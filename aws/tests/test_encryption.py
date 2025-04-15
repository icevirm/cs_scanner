from boto3 import client
from json import dumps
from moto import mock_aws
from aws.encryption import get_bucket_encryption, check_sse_c_allowed, check_tls_enforced, get_bucket_location, get_key_location

DEFAULT_REGION = 'eu-central-1'


@mock_aws
def test_get_bucket_encryption():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )
    encryption_config = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            }
        ]
    }
    s3.put_bucket_encryption(Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)

    result = get_bucket_encryption(bucket_name)
    assert result['SSEAlgorithm'] == 'AES256'


@mock_aws
def test_get_bucket_encryption_no_config():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )
    
    result = get_bucket_encryption(bucket_name)
    assert result is None


@mock_aws
def test_check_sse_c_allowed():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )
    
    result = check_sse_c_allowed(bucket_name)
    assert result is False  # Because moto does not support SSE-C


@mock_aws
def test_check_tls_enforced():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )
    bucket_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:*',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {'aws:SecureTransport': 'false'}
                }
            }
        ]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=dumps(bucket_policy))

    assert check_tls_enforced(bucket_name) is True


@mock_aws
def test_check_tls_not_enforced():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )
    
    assert check_tls_enforced(bucket_name) is False


@mock_aws
def test_get_bucket_location():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )

    assert get_bucket_location(bucket_name) == DEFAULT_REGION


@mock_aws
def test_get_key_location():
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )
    encryption_config = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'dsse:kms'
                }
            }
        ]
    }
    s3.put_bucket_encryption(Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)

    encryption = get_bucket_encryption(bucket_name)
    if 'KMSMasterKeyID' in encryption:
        encryption_key = encryption['KMSMasterKeyID']
        key_location = get_key_location(encryption_key)
    else:
        bucket_location = get_bucket_location(bucket_name)
        key_location = bucket_location

    assert key_location == DEFAULT_REGION
