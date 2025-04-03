from boto3 import client as boto_client
from . import encryption

s3 = boto_client('s3')

def list_buckets() -> list:
    '''
    Returns all S3 buckets in the current account, except CDK bootstrap one
    
    Args: None
    Returns: (list) buckets - list of S3 buckets in the current account
    '''
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets'] if not bucket['Name'].startswith('cdk-')]

    return buckets

def evaluate_s3_security(enc: bool) -> None:
    '''
    Runs different security checks on S3 buckets in the account and reports the results

    Args:
        (bool) enc - scan encryption settings
    Returns: None
    '''
    buckets = list_buckets()
    print(f'Existing S3 buckets: {buckets}')

    if enc:
        encryption.encryption_configuration(buckets)
    else:
        pass
