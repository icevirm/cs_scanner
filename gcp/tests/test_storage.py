import pytest
from unittest.mock import patch, MagicMock

from gcp.storage import get_bucket, parse_key, evaluate_storage_encryption, get_public_prevention, evaluate_storage_public_access, list_buckets


@pytest.fixture
def mock_bucket():
    mock = MagicMock()
    mock.default_kms_key_name = (
        "projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu"
    )
    mock.location = "EUROPE-WEST1"
    mock.iam_configuration.public_access_prevention = "enforced"
    return mock


@pytest.fixture
def mock_bucket_google_managed():
    mock = MagicMock()
    mock.default_kms_key_name = None
    mock.location = "US-CENTRAL1"
    mock.iam_configuration.public_access_prevention = "inherited"
    return mock


@patch("gcp.storage.client.get_bucket")
def test_get_bucket(mock_get_bucket, mock_bucket):
    mock_get_bucket.return_value = mock_bucket
    result = get_bucket("test-bucket")
    assert result.default_kms_key_name == mock_bucket.default_kms_key_name


def test_parse_key():
    key = "projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu"
    assert parse_key(key) == "europe-west1"


@patch("gcp.storage.get_bucket")
def test_evaluate_storage_encryption_customer_key(mock_get_bucket, mock_bucket):
    mock_get_bucket.return_value = mock_bucket
    result = evaluate_storage_encryption("test-bucket")
    assert result["Key"] == "Customer Managed"
    assert result["KeyLocation"] == "europe-west1"
    assert result["BucketLocation"] == "europe-west1"
    assert result["Algorithm"] == "AES-256"


@patch("gcp.storage.get_bucket")
def test_evaluate_storage_encryption_google_key(mock_get_bucket, mock_bucket_google_managed):
    mock_get_bucket.return_value = mock_bucket_google_managed
    result = evaluate_storage_encryption("test-bucket")
    assert result["Key"] == "Google Managed"
    assert result["KeyLocation"] == "us-central1"
    assert result["BucketLocation"] == "us-central1"
    assert result["Algorithm"] == "AES-256"


def test_get_public_prevention_true(mock_bucket):
    assert get_public_prevention(mock_bucket) is True


def test_get_public_prevention_false(mock_bucket_google_managed):
    assert get_public_prevention(mock_bucket_google_managed) is False


@patch("gcp.storage.get_bucket")
def test_evaluate_storage_public_access(mock_get_bucket, mock_bucket):
    mock_get_bucket.return_value = mock_bucket
    result = evaluate_storage_public_access("test-bucket")
    assert result["PublicAccess"] is True


@patch("gcp.storage.client.list_buckets")
def test_list_buckets(mock_list_buckets):
    bucket1 = MagicMock()
    bucket1.name = "bucket-1"
    bucket2 = MagicMock()
    bucket2.name = "bucket-2"
    mock_list_buckets.return_value = [bucket1, bucket2]
    result = list_buckets()
    assert result == ["bucket-1", "bucket-2"]
