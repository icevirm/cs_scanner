from google.cloud import storage
from json import dumps
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

console = Console()


def get_client():
    return storage.Client()


# Encryption settings
def get_bucket(bucket: str) -> dict:
    '''
        Gets bucket configuration

        Args: (str) bucket - the name of the bucket to scan
        Returns: (dict) Bucket object
    '''
    try:
        response = get_client().get_bucket(bucket)
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


def evaluate_storage_encryption(bucket: str) -> dict:
    '''
        Gets the encryption algorithm applied to the bucket.

        Args: (str) bucket - the name of the bucket to be scanned
        Returns: (dict) - encryption settings for the bucket
    '''
    bucket_object = get_bucket(bucket)
    default_kms_key_name = bucket_object.default_kms_key_name
    bucket_location = bucket_object.location.lower()
    encryption_algorithm = 'AES-256'

    if default_kms_key_name:
        encryption_key = 'Customer Managed'
        key_location = parse_key(default_kms_key_name)
    else:
        encryption_key = 'Google Managed'
        key_location = bucket_location

    return {
        'BucketLocation': bucket_location,
        'Algorithm': encryption_algorithm,
        'Key': encryption_key,
        'KeyLocation': key_location
    }


# Public access settings
def get_public_prevention(bucket: str) -> dict:
    '''
        Gets the status of public access prevention of the bucket

        Args: (str) bucket - the name of the bucket to be scanned
        Returns: (bool) - True if enforced
    '''
    bucket_iam = bucket.iam_configuration

    if bucket_iam.public_access_prevention == "enforced":
        return True

    return False


def evaluate_storage_public_access(bucket: str) -> dict:
    '''
        Output information about GCS Public Access settings

        Args: (str) bucket - name of the bucket to be scanned
        Returns: (dict) - status of public access settings
    '''
    bucket_object = get_bucket(bucket)
    return {
        'PublicAccess': get_public_prevention(bucket_object)
    }


# Dispatcher
def list_buckets() -> list:
    '''
        Returns all buckets in the current account

        Args: None
        Returns: (list) buckets - list of buckets in the current account
    '''
    response = get_client().list_buckets()
    buckets = [bucket.name for bucket in response]

    return buckets


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
            bucket_encryption[bucket] = evaluate_storage_encryption(bucket)
        if pub:
            public_access[bucket] = evaluate_storage_public_access(bucket)

    evaluation = []
    for bucket in buckets:
        evaluation.append({
            'BucketName': bucket,
            'Encryption': {
                'KeyLocation': bucket_encryption.get(bucket, {}).get('KeyLocation', ''),
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
        Outputs the result in table, useful for CLI and humans

        Args: (bool) enc - encryption module
              (bool) pub - public access module

        Returns: None
    '''
    table = Table(title='GCS Buckets Security Scan Results')
    table.add_column('Bucket Name', style='cyan', justify='left')
    table.add_column('Bucket Location', style='magenta', justify='center')
    table.add_column('Encryption Type', style='magenta', justify='center')
    table.add_column('Encryption Key', style='magenta', justify='center')
    table.add_column('Key Location', style='magenta', justify='center')
    table.add_column('Public Access', style='green', justify='center')

    bucket_encryption = {}
    public_access = {}
    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        if enc:
            bucket_encryption[bucket] = evaluate_storage_encryption(bucket)
        if pub:
            public_access[bucket] = evaluate_storage_public_access(bucket)

    for bucket in buckets:
        key_location = bucket_encryption.get(bucket, {}).get('KeyLocation', '')
        if key_location.startswith('europe-'):
            key_location = f'{key_location}: ✅'
        elif enc and not key_location.startswith('eu-'):
            key_location = '❌'

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
            public_access_status
        )

    console.print(table)


def evaluate_storage_security(enc: bool, pub: bool, json: bool) -> None:
    '''
        Runs different security checks on GCS buckets in the account and reports the results

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
