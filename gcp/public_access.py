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


def get_public_prevention(bucket: str) -> dict:
    bucket_iam = bucket.iam_configuration

    if bucket_iam.public_access_prevention == "enforced":
        print("Public access prevention is ENABLED")
    else:
        print("Public access prevention is NOT enabled")


def public_access_configuration(buckets: list) -> None:
    '''
    '''
    for bucket in buckets:
        bucket_object = get_bucket(bucket)
        print(get_public_prevention(bucket_object))
