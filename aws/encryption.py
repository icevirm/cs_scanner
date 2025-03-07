from base64 import b64encode
from botocore import exceptions
from boto3 import client as boto_client
from hashlib import md5
from json import loads

s3 = boto_client('s3')


def get_bucket_encryption(bucket: str) -> dict:
    '''
    Gets encryption configuration from the S3 bucket

    Args: (str) bucket - the name of the bucket to scan
    Returns: (dict) Encryption configuration from response
    '''
    try:
        response = s3.get_bucket_encryption(Bucket=bucket)

        return response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
    
    except exceptions.ClientError as err:
        print(f'Encryption is not configured.')


def check_sse_c_allowed(bucket: str) -> bool:
    '''
    Checks if it is possible to upload and then get an object onto S3 bucket with a customer key (SSE-C)
    
    Args: (str) bucket - the name of the bucket to scan
    Returns: (bool) sse_c_status - if True, then SSE-C is allowed, posing a security risk
    '''
    object_key = 'example.txt'
    encryption_key = b'0123456789abcdef0123456789abcdef'
    sse_c_status = None

    sse_headers = {
        'SSECustomerAlgorithm': 'AES256',
        'SSECustomerKey': b64encode(encryption_key).decode('utf-8'),
        'SSECustomerKeyMD5': b64encode(md5(encryption_key).digest()).decode('utf-8')
    }

    with open('aws/files/example.txt', 'rb') as data:
        try:
            s3.put_object(
                Bucket=bucket,
                Key=object_key,
                Body=data,
                SSECustomerAlgorithm=sse_headers['SSECustomerAlgorithm'],
                SSECustomerKey=sse_headers['SSECustomerKey'],
                SSECustomerKeyMD5=sse_headers['SSECustomerKeyMD5']
            )
        except s3.exceptions.ClientError as e:
            if 'explicit deny in a resource-based policy' in str(e):
                sse_c_status = False
                return

    try:
        s3.get_object(Bucket=bucket, Key=object_key)
        sse_c_status = False
    except s3.exceptions.ClientError as e:
        if 'SSECustomerKey' in str(e) or 'InvalidRequest' in str(e):
            sse_c_status = True
        else:
            print(f'Other error: {e}')

    try:
        s3.get_object(
        Bucket=bucket,
        Key=object_key,
        SSECustomerAlgorithm='AES256',
        SSECustomerKey=b64encode(encryption_key).decode('utf-8'),
        SSECustomerKeyMD5=b64encode(md5(encryption_key).digest()).decode('utf-8')
    )
    except:
        print('Something went wrong with getting object')

    return sse_c_status


def check_tls_enforced(bucket: str) -> bool:
    '''
    Checks if TLS is enforced in the bucket policy

    Args: (str) bucket - the name of the bucket to scan
    Returns: (bool) - if True, the TLS is enforced in the bucket policy
    '''
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
        policy = loads(response['Policy'])

        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                condition = statement.get('Condition', {})
                if 'Bool' in condition and condition['Bool'].get('aws:SecureTransport') == 'false':
                    return True

    except s3.exceptions.from_code('NoSuchBucketPolicy'):
        print('No bucket policy found')

    return False


def encryption_configuration(buckets: list) -> None:
    '''
    Scans encryption configuration settings on S3 buckets in the current account.
    Gets the encryption algorythm applied to the bucket.
    Checks if SSE-C is allowed.
    Checks if TLS is enforced in the bucket policy.

    Args: (list) buckets - list of S3 buckets in the current account
    Returns: None
    '''
    for bucket in buckets:
        encryption = get_bucket_encryption(bucket)
        encryption_algorythm = encryption['SSEAlgorithm']
        if encryption_algorythm == 'AES256':
            key = 'S3 managed'
        else:
            key = 'KMS managed'
        encryption_key = encryption.get('KMSMasterKeyID', key)
        sse_c_status = check_sse_c_allowed(bucket)
        tls_status = check_tls_enforced(bucket)


        print(f'\nConfiguration of the bucket {bucket}:')
        print('-' * 50)
        print(f'Encryption Algorythm: {encryption_algorythm}')
        print(f'KMS key: {encryption_key}')
        
        if sse_c_status:
            print('SSE-C is allowed')
        else:
            print('SSE-C is not allowed')

        if tls_status:
            print('TLS is enforced')
        else:
            print('TLS is not enforced')
