import boto3
import pytest
from json import dumps
from moto import mock_aws
from botocore.exceptions import ClientError
from aws.encryption import get_bucket_encryption, check_sse_c_allowed, check_tls_enforced


@mock_aws
def test_get_bucket_encryption():
    s3 = boto3.client("s3")
    bucket_name = "test-bucket"
    s3.create_bucket(Bucket=bucket_name)
    encryption_config = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }
    s3.put_bucket_encryption(Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)

    result = get_bucket_encryption(bucket_name)
    assert result["SSEAlgorithm"] == "AES256"


@mock_aws
def test_get_bucket_encryption_no_config():
    s3 = boto3.client("s3")
    bucket_name = "test-bucket"
    s3.create_bucket(Bucket=bucket_name)
    
    result = get_bucket_encryption(bucket_name)
    assert result is None


@mock_aws
def test_check_sse_c_allowed():
    s3 = boto3.client("s3")
    bucket_name = "test-bucket"
    s3.create_bucket(Bucket=bucket_name)
    
    result = check_sse_c_allowed(bucket_name)
    assert result is False  # Because moto does not support SSE-C


@mock_aws
def test_check_tls_enforced():
    s3 = boto3.client("s3")
    bucket_name = "test-bucket"
    s3.create_bucket(Bucket=bucket_name)
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "Bool": {"aws:SecureTransport": "false"}
                }
            }
        ]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=dumps(bucket_policy))

    assert check_tls_enforced(bucket_name) is True


@mock_aws
def test_check_tls_not_enforced():
    s3 = boto3.client("s3")
    bucket_name = "test-bucket"
    s3.create_bucket(Bucket=bucket_name)
    
    assert check_tls_enforced(bucket_name) is False
