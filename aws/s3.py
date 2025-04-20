'''
    This modules scans configuration settings of AWS S3 buckets
    in the current account.

    Depending on the flags chosen in the main module, it scans
    encryption or public access settings.
'''
from base64 import b64encode
from boto3 import client as boto_client
from botocore import exceptions
from hashlib import md5
from json import dumps, loads
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

from .helpers import parse_arn

s3 = boto_client('s3')
kms = boto_client('kms')

console = Console()


# Encryption settings
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
                return sse_c_status

    try:
        s3.get_object(Bucket=bucket, Key=object_key)
        sse_c_status = False
    except s3.exceptions.ClientError as e:
        if 'SSECustomerKey' in str(e) or 'InvalidRequest' in str(e):
            sse_c_status = True
            return sse_c_status
        else:
            print(f'Other error: {e}')

    try:
        s3.get_object(
            Bucket=bucket,
            Key=object_key,
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=b64encode(encryption_key).decode('utf-8'),
            SSECustomerKeyMD5=b64encode(
                md5(encryption_key).digest()).decode('utf-8')
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


def get_bucket_location(bucket: str) -> str:
    '''
        Gets region where the bucket is located.

        Args: (str) bucket - the name of the bucket to scan
        Returns: (str) location - The bucket's region
    '''
    location = s3.get_bucket_location(Bucket=bucket)

    return location['LocationConstraint']


def get_key_location(encryption_key: str) -> str:
    '''
        Parses key location from key ARN

        Args: (str) encryption_key - ARN of the encryption key
        Returns: (str) - region part of the ARN
    '''
    return parse_arn(encryption_key)[3]


# Public access settings
def get_bucket_public_configuration(bucket: str) -> bool:
    '''
        Checks the public access configuration of the bucket

        Args: (str) bucket - the name of the bucket to scan
        Returns: (bool) - if True, public access is blocked completely
    '''
    public_access_block = s3.get_public_access_block(
        Bucket=bucket
    )

    for block in public_access_block['PublicAccessBlockConfiguration'].values():
        if not block:
            return False

    return True


# Dispatcher
def list_buckets() -> list:
    '''
        Returns all S3 buckets in the current account, except CDK bootstrap one

        Args: None
        Returns: (list) buckets - list of S3 buckets in the current account
    '''
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets']
               if not bucket['Name'].startswith('cdk-')]

    return buckets


def evaluate_s3_encryption(bucket: str) -> dict:
    '''
        Outputs information about S3 bucket encryption settings

        Args: (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - encryption settings for the bucket
    '''
    encryption = get_bucket_encryption(bucket)
    encryption_algorithm = encryption['SSEAlgorithm']

    if encryption_algorithm == 'AES256':
        key = 'S3 managed'
    else:
        key = 'KMS managed'

    sse_c_status = check_sse_c_allowed(bucket)
    tls_status = check_tls_enforced(bucket)
    bucket_location = get_bucket_location(bucket)

    if 'KMSMasterKeyID' in encryption:
        encryption_key = encryption['KMSMasterKeyID']
        key_location = get_key_location(encryption_key)
    else:
        encryption_key = key
        key_location = bucket_location

    return {
        'BucketLocation': bucket_location,
        'Algorithm': encryption_algorithm,
        'Key': encryption_key,
        'KeyLocation': key_location,
        'TLS': tls_status,
        'SSE-C': sse_c_status
    }


def evaluate_s3_public_access(bucket: str) -> dict:
    '''
        Output information about S3 Public Access Block settings

        Args: (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - status of public access block settings
    '''
    return {
        'PublicAccess': get_bucket_public_configuration(bucket)
    }


# Output
def output_json(buckets: list, enc: bool, pub: bool) -> None:
    '''
        Outputs the result in JSON, useful for automation

        Args: (bool) enc - encryption module
            (bool) pub - public access module

        Returns: None
    '''
    bucket_encryption = {}
    public_access = {}
    for bucket in buckets:
        if enc:
            bucket_encryption[bucket] = evaluate_s3_encryption(bucket)
        if pub:
            public_access[bucket] = evaluate_s3_public_access(bucket)

    evaluation = []
    for bucket in buckets:
        evaluation.append({
            'BucketName': bucket,
            'Encryption': {
                'KeyLocation': bucket_encryption.get(bucket, {}).get('KeyLocation', ''),
                'TLS': bucket_encryption.get(bucket, {}).get('TLS', ''),
                'SSE-C': bucket_encryption.get(bucket, {}).get('SSE-C', ''),
                'BucketLocation': bucket_encryption.get(bucket, {}).get('BucketLocation'),
                'Algorithm': bucket_encryption.get(bucket, {}).get('Algorithm'),
                'Key': bucket_encryption.get(bucket, {}).get('Key')
            },
            'PublicAccess': {
                'PublicAccess': public_access.get(bucket, {}).get('PublicAccess', '')
            }
        })

    print(dumps(evaluation))


def output_table(buckets: list, enc: bool, pub: bool) -> None:
    '''
        Outputs the result in table, useful for CLI and human

        Args: (bool) enc - encryption module
            (bool) pub - public access module

        Returns: None
    '''
    table = Table(title='S3 Bucket Security Scan Results')
    table.add_column('Bucket Name', style='cyan', justify='left')
    table.add_column('Bucket Location', style='magenta', justify='center')
    table.add_column('Encryption Algorythm', style='magenta', justify='center')
    table.add_column('Encryption Key', style='magenta', justify='center')
    table.add_column('Key Location', style='magenta', justify='center')
    table.add_column('TLS Enforced', style='green', justify='center')
    table.add_column('SSE-C Blocked', style='green', justify='center')
    table.add_column('Public Access', style='green', justify='center')

    bucket_encryption = {}
    public_access = {}
    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        if enc:
            bucket_encryption[bucket] = evaluate_s3_encryption(bucket)
        if pub:
            public_access[bucket] = evaluate_s3_public_access(bucket)

    for bucket in buckets:
        key_location = bucket_encryption.get(bucket, {}).get('KeyLocation', '')
        if key_location.startswith('eu-'):
            key_location = f'{key_location}: ✅'
        elif enc and not key_location.startswith('eu-'):
            key_location = '❌'

        tls_status = bucket_encryption.get(bucket, {}).get('TLS', '')
        if tls_status:
            tls_status = '✅'
        elif enc and not tls_status:
            tls_status = ''

        sse_c_status = bucket_encryption.get(bucket, {}).get('SSE-C', '')
        if sse_c_status:
            sse_c_status = '❌'
        elif enc and not sse_c_status:
            sse_c_status = '✅'

        public_access_status = public_access.get(
            bucket, {}).get('PublicAccess', '')
        if public_access_status:
            public_access_status = f'✅'
        elif pub and public_access_status:
            public_access_status = '❌'

        table.add_row(
            bucket,
            bucket_encryption.get(bucket, {}).get('BucketLocation'),
            bucket_encryption.get(bucket, {}).get('Algorithm'),
            bucket_encryption.get(bucket, {}).get('Key'),
            key_location,
            tls_status,
            sse_c_status,
            public_access_status
        )

    console.print(table)


def evaluate_s3_security(enc: bool, pub: bool, json: bool) -> None:
    '''
        Runs different security checks on S3 buckets in the account and reports the results

        Args:
            (bool) enc - scan encryption settings
            (bool) pub - scan public access settings
            (bool) json - output in JSON format
        Returns: None
    '''
    buckets = list_buckets()

    if json:
        output_json(buckets, enc, pub)
    else:
        output_table(buckets, enc, pub)
