from google.cloud import storage
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

console = Console()

client = storage.Client()


def get_bucket(bucket: str) -> dict:
    '''
    Gets bucket configuration
    
    Args: (str) bucket - the name of the bucket to scan
    Returns: (dict) Bucket object
    '''
    try:
        response = client.get_bucket(bucket)

        return response
    except Exception as e:
        print(e)


def parse_key(key: str) -> str:
    '''
    Returns the location of the encryption key
    
    Args: (str) key - encryption key used to encrypt the bucket
    Returns: (str) - key location parsed from the name, e.g.
        projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu -> europe-west1
    '''
    return key.split('/')[3]


def encryption_configuration(buckets: list) -> None:
    '''
    Scans encryption configuration settings on GCS buckets in the current account.
    Gets the encryption algorithm applied to the bucket.

    Args: (list) buckets - list of buckets in the current account
    Returns: None
    '''
    table = Table(title='GCS Buckets Security Scan Results')
    table.add_column('Bucket Name', style='cyan', justify='left')
    table.add_column('Encryption Type', style='magenta', justify='center')
    table.add_column('Encryption Key', style='magenta', justify='center')
    table.add_column('Key Location', style='magenta', justify='center')
    table.add_column('Bucket Location', style='magenta', justify='center')

    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        bucket_object = get_bucket(bucket)
        default_kms_key_name = bucket_object.default_kms_key_name
        location = bucket_object.location.lower()
        encryption_algorithm = 'AES-256'
        
        if default_kms_key_name: 
            encryption_key = 'Customer Managed'
            key_location = parse_key(default_kms_key_name)
        else:
            encryption_key = 'Google Managed'
            key_location = location

        table.add_row(
            bucket,
            encryption_algorithm,
            encryption_key,
            f'{key_location}: ✅' if key_location.startswith('europe-') else '❌',
            f'{location}: ✅' if location.startswith('europe-') else '❌'
        )
        
    console.print(table)