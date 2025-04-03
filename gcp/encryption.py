from google.cloud import storage
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

console = Console()

client = storage.Client()


def get_bucket_encryption(bucket: str) -> dict:
    '''
    Gets encryption configuration from the bucket

    Args: (str) bucket - the name of the bucket to scan
    Returns: (dict) Encryption configuration from response
    '''
    try:
        response = client.get_bucket(bucket)

        return response.default_kms_key_name
    except Exception as e:
        print(e)


def encryption_configuration(buckets: list) -> None:
    '''
    Scans encryption configuration settings on GCS buckets in the current account.
    Gets the encryption algorithm applied to the bucket.

    Args: (list) buckets - list of buckets in the current account
    Returns: None
    '''
    table = Table(title="GCS Buckets Security Scan Results")
    table.add_column("Bucket Name", style="cyan", justify="left")
    table.add_column("Encryption Type", style="magenta", justify="center")
    table.add_column("Encryption Key", style="magenta", justify="center")

    for bucket in tqdm(buckets, desc="Scanning Buckets", unit="bucket"):
        default_kms_key_name = get_bucket_encryption(bucket)
        encryption_algorithm = "AES-256"
        
        if default_kms_key_name:    
            encryption_key = "Customer Managed"
        else:
            encryption_key = "Google Managed"

        table.add_row(
            bucket,
            encryption_algorithm,
            encryption_key
        )
        
    console.print(table)