from boto3 import client as boto_client
from json import dumps
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

from . import encryption as s3_encryption
from . import public_access as s3_public

s3 = boto_client('s3')

console = Console()

def list_buckets() -> list:
    '''
    Returns all S3 buckets in the current account, except CDK bootstrap one
    
    Args: None
    Returns: (list) buckets - list of S3 buckets in the current account
    '''
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets'] if not bucket['Name'].startswith('cdk-')]

    return buckets


def evaluate_s3_encryption(bucket: str) -> dict:
    '''
    Outputs information about S3 bucket encryption settings

    Args: (str) bucket - name of S3 bucket to be scanned
    Returns: (dict) - encryption settings for the bucket
    '''
    encryption = s3_encryption.get_bucket_encryption(bucket)
    encryption_algorithm = encryption['SSEAlgorithm']

    if encryption_algorithm == 'AES256':
        key = 'S3 managed'
    else:
        key = 'KMS managed'

    sse_c_status = s3_encryption.check_sse_c_allowed(bucket)
    tls_status = s3_encryption.check_tls_enforced(bucket)
    bucket_location = s3_encryption.get_bucket_location(bucket)

    if 'KMSMasterKeyID' in encryption:
        encryption_key = encryption['KMSMasterKeyID']
        key_location = s3_encryption.get_key_location(encryption_key)
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
        'PublicAccess': s3_public.get_bucket_public_configuration(bucket)
    }


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

        public_access_status = public_access.get(bucket, {}).get('PublicAccess', '')
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
