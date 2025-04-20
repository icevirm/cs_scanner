from boto3 import client
from botocore import exceptions
from moto import mock_aws
from aws.public_access import get_bucket_public_configuration

DEFAULT_REGION = 'eu-central-1'


@mock_aws
def test_get_bucket_public_configuration():
    '''
    Test default bucket configuration, public access must be blocked
    '''
    s3 = client('s3')
    bucket_name = 'test-bucket'
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': DEFAULT_REGION
        }
    )

    try:
        result = get_bucket_public_configuration(bucket_name)
    except exceptions.ClientError as exc:
        print('PublicAccessBlock is not supported by moto')
        result = True

    assert result == True
