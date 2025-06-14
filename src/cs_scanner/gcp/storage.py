from google.cloud import storage
from json import dumps
from tqdm import tqdm

from cs_scanner.shared import output, llm


def get_client() -> storage.Client:
    '''
        Returns GCP storage API client

        Args: None

        Returns: (storage.Client) - GCP client
    '''
    return storage.Client()


# Encryption settings
def parse_key(key: str) -> str:
    '''
        Returns the location of the encryption key

        Args: (str) key - encryption key used to encrypt the bucket
        Returns: (str) - key location parsed from the name, e.g.
            projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu -> europe-west1
    '''
    return key.split('/')[3]


def evaluate_storage_encryption(bucket: dict) -> dict:
    '''
        Gets the encryption algorithm applied to the bucket

        Args: (dict) bucket - GCS bucket structure
        Returns: (dict) - encryption settings for the bucket
    '''
    default_kms_key_name = bucket.default_kms_key_name
    bucket_location = bucket.location.lower()
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
def evaluate_bucket_policy(bucket: dict) -> dict:
    '''
        Evaluates GCS bucket policy with LLM.
        Returns general status of the policy and reasoning.

        Args: (dict) bucket - GCS bucket structure

        Returns: (dict) - dictionary with status and reason
    '''
    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy_json = dumps(policy.to_api_repr(), indent=2)

    prompt = \
    f'''
        Evaluate the following GCP storage bucket policy. 
        Respond strictly in JSON with this format: 
        {{"Policy": "Good" or "Bad", "Reason": "short explanation"}}.

        Policy:
        {dumps(policy_json, indent=2)}
    '''
    model_response = llm.ask_model(prompt)

    return {
        'PolicyStatus': model_response['Policy'],
        'PolicyReason': model_response['Reason']
    }


def evaluate_storage_public_access(bucket: dict) -> dict:
    '''
        Output information about GCS Public Access settings.
        Checks if public access prevention is set.

        Args: (dict) bucket - GCS bucket structure
        Returns: (dict) - status of public access prevention
    '''
    bucket_iam = bucket.iam_configuration
    prevention = False

    if bucket_iam.public_access_prevention == 'enforced':
        prevention = True

    return {
        'Prevention': prevention
    }


# Dispatcher
def list_buckets() -> list:
    '''
        Returns all buckets in the current account

        Args: None
        Returns: (list) - list of buckets in the current account
    '''
    return get_client().list_buckets()


def evaluate_storage_security(enc: bool, pub: bool, noai: bool, json: bool) -> None:
    '''
        Runs different security checks on GCS buckets in the account and reports the results

        Args:
            (bool) enc - scan encryption settings
            (bool) pub - scan public access settings
            (bool) noai - disable evaluation with LLM
            (bool) json - output in JSON format
        Returns: None
    '''
    buckets = list_buckets()

    bucket_security = {}

    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        bucket_security[bucket.name] = {'BucketName': bucket.name}

        if enc:
            bucket_security[bucket.name]['Encryption'] = evaluate_storage_encryption(bucket)
        if pub:
            bucket_security[bucket.name]['PublicAccess'] = evaluate_storage_public_access(bucket)
            if not noai:
                bucket_security[bucket.name]['PolicyEval'] = evaluate_bucket_policy(bucket)

    if json:
        output.output_json(bucket_security)
    else:
        title = 'GCS Buckets Security Scan Results'
        output.output_table(bucket_security, title)
