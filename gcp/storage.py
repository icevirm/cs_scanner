from google.cloud import storage
from . import encryption

client = storage.Client()

def list_buckets() -> list:
    '''
    Returns all buckets in the current account
    
    Args: None
    Returns: (list) buckets - list of buckets in the current account
    '''
    response = client.list_buckets()
    buckets = [bucket.name for bucket in response]

    return buckets

def evaluate_storage_security(enc: bool) -> None:
    '''
    Runs different security checks on GCS buckets in the account and reports the results

    Args:
        (bool) enc - scan encryption settings
    Returns: None
    '''
    buckets = list_buckets()
    print(f'Existing buckets: {buckets}')

    if enc:
        encryption.encryption_configuration(buckets)
    else:
        pass
