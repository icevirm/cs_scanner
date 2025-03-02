from base64 import b64encode
from botocore import exceptions, UNSIGNED
from botocore.config import Config
from boto3 import client as boto_client
from hashlib import md5
from json import loads

s3 = boto_client('s3')


def list_buckets():
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets'] if not bucket['Name'].startswith('cdk-')]

    return buckets


def list_objects(bucket):
    response = s3.list_objects(Bucket=bucket)
    objects = [obj['Key'] for obj in response.get('Contents', [])]

    return objects


def get_bucket_acl(bucket):
    response = s3.get_bucket_acl(Bucket=bucket)
    
    return response['Grants']


def get_bucket_encryption(bucket):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket)

        return response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']
    
    except exceptions.ClientError as err:
        print(f'Encryption is not configured.')


def check_sse_c_allowed(bucket):
    object_key = 'example.txt'
    encryption_key = b'0123456789abcdef0123456789abcdef'
    sse_c_status = None

    sse_headers = {
        'SSECustomerAlgorithm': 'AES256',
        'SSECustomerKey': b64encode(encryption_key).decode('utf-8'),
        'SSECustomerKeyMD5': b64encode(md5(encryption_key).digest()).decode('utf-8')
    }

    with open('example.txt', 'rb') as data:
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


def check_tls_enforced(bucket):
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
        policy = loads(response['Policy'])

        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Deny":
                condition = statement.get("Condition", {})
                if "Bool" in condition and condition["Bool"].get("aws:SecureTransport") == "false":
                    return True

    except s3.exceptions.from_code('NoSuchBucketPolicy'):
        print("No bucket policy found.")

    return False


def get_bucket_logging(bucket):
    response = s3.get_bucket_logging(Bucket=bucket)
    
    return response.get('LoggingEnabled', 'Logging is not configured.')


def get_bucket_versioning(bucket):
    response = s3.get_bucket_versioning(Bucket=bucket)

    return response.get('Status', 'Versioning is not enabled.')
    

def get_bucket_policy(bucket):
    try:
        response = s3.get_bucket_policy(Bucket=bucket)

        return response

    except exceptions.ClientError as err:
        print(f'Policy does not exist.')


def main():
    buckets = list_buckets()
    print(f'Existing S3 buckets: {buckets}')

    for bucket in buckets:
        # objects = list_objects(bucket)
        # acl = get_bucket_acl(bucket)
        
        encryption = get_bucket_encryption(bucket)
        encryption_algorythm = encryption["SSEAlgorithm"]
        if encryption_algorythm == 'AES256':
            key = 'S3 managed'
        else:
            key = 'KMS managed'
        encryption_key = encryption.get("KMSMasterKeyID", key)
        sse_c_status = check_sse_c_allowed(bucket)
        tls_status = check_tls_enforced(bucket)

        #logging = get_bucket_logging(bucket)
        #versioning = get_bucket_versioning(bucket)
        # policy = get_bucket_policy(bucket)

        print(f'\nConfiguration of the bucket {bucket}:')
        print('-' * 50)
        # print(f'Objects: {objects}\n')
        # print(f'ACL: {acl}\n')
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
        #print(f'Logging: {logging}\n')
        #print(f'Versioning: {versioning}\n')
        # print(f'Bucket policy: {policy}\n')


if __name__ == '__main__':
    main()
