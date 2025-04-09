from boto3 import client as boto_client
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


def evaluate_s3_encryption(buckets: list, table: Table):
    '''
    Outputs information about S3 buckets encryption settings

    Args: (list) buckets - list of S3 buckets in the current account
          (rich.Table) - rich table to be filled in with data
    Returns: (rich.Table) - updated table
    '''
    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
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

        table.add_row(
            bucket,
            f'{bucket_location}: ✅' if bucket_location.startswith('eu-') else '❌',
            encryption_algorithm,
            encryption_key,
            f'{key_location}: ✅' if key_location.startswith('eu-') else '❌',
            '✅' if tls_status else '❌',
            '❌' if sse_c_status else '✅',
        )

    return table


def evaluate_s3_public_access(buckets, table):
    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        public = s3_public.get_bucket_public_configuration(bucket)

        print(public)
        
        table.add_row(
            '✅' if public else '❌',
        )

    return table 

def evaluate_s3_security(enc: bool, pub: bool) -> None:
    '''
    Runs different security checks on S3 buckets in the account and reports the results

    Args:
        (bool) enc - scan encryption settings
        (bool) pub - scan public access settings
    Returns: None
    '''
    buckets = list_buckets()
    print(f'Existing S3 buckets: {buckets}')

    table = Table(title='S3 Bucket Security Scan Results')
    table.add_column('Bucket Name', style='cyan', justify='left')
    table.add_column('Bucket Location', style='magenta', justify='center')
    table.add_column('Encryption Algorythm', style='magenta', justify='center')
    table.add_column('Encryption Key', style='magenta', justify='center')
    table.add_column('Key Location', style='magenta', justify='center')
    table.add_column('TLS Enforced', style='green', justify='center')
    table.add_column('SSE-C Blocked', style='green', justify='center')
    table.add_column('Public Access', style='green', justify='center')

    if enc:
        table = evaluate_s3_encryption(buckets, table)
    
    if pub:
        table = evaluate_s3_public_access(buckets, table)

    console.print(table)
