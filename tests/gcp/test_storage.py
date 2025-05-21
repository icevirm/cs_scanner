import unittest
from unittest.mock import patch, MagicMock

from cs_scanner.gcp.storage import get_bucket, parse_key, evaluate_storage_encryption, get_public_prevention, evaluate_storage_public_access, list_buckets


class TestGCSModule(unittest.TestCase):

    @patch("cs_scanner.gcp.storage.get_client")
    def test_get_bucket(self, mock_get_client):
        mock_client = MagicMock()
        mock_bucket = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = get_bucket("test-bucket")
        mock_client.get_bucket.assert_called_once_with("test-bucket")
        self.assertEqual(result, mock_bucket)

    def test_parse_key(self):
        key = "projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu"
        result = parse_key(key)
        self.assertEqual(result, "europe-west1")

    @patch("cs_scanner.gcp.storage.get_client")
    def test_evaluate_storage_encryption_cmek(self, mock_get_client):
        mock_bucket = MagicMock()
        mock_bucket.default_kms_key_name = "projects/project/locations/us/keyRings/kr/cryptoKeys/key"
        mock_bucket.location = "US"

        mock_client = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = evaluate_storage_encryption("bucket-1")
        expected = {
            'BucketLocation': 'us',
            'Algorithm': 'AES-256',
            'Key': 'Customer Managed',
            'KeyLocation': 'us'
        }
        self.assertEqual(result, expected)

    @patch("cs_scanner.gcp.storage.get_client")
    def test_evaluate_storage_encryption_gmek(self, mock_get_client):
        mock_bucket = MagicMock()
        mock_bucket.default_kms_key_name = None
        mock_bucket.location = "europe-west1"

        mock_client = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = evaluate_storage_encryption("bucket-1")
        expected = {
            'BucketLocation': 'europe-west1',
            'Algorithm': 'AES-256',
            'Key': 'Google Managed',
            'KeyLocation': 'europe-west1'
        }
        self.assertEqual(result, expected)

    def test_get_public_prevention_enforced(self):
        mock_bucket = MagicMock()
        mock_bucket.iam_configuration.public_access_prevention = "enforced"
        self.assertTrue(get_public_prevention(mock_bucket))

    def test_get_public_prevention_not_enforced(self):
        mock_bucket = MagicMock()
        mock_bucket.iam_configuration.public_access_prevention = "unspecified"
        self.assertFalse(get_public_prevention(mock_bucket))

    @patch("cs_scanner.gcp.storage.get_client")
    def test_evaluate_storage_public_access(self, mock_get_client):
        mock_bucket = MagicMock()
        mock_bucket.iam_configuration.public_access_prevention = "enforced"

        mock_client = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = evaluate_storage_public_access("test-bucket")
        self.assertEqual(result, {"PublicAccess": True})

    @patch("cs_scanner.gcp.storage.get_client")
    def test_list_buckets(self, mock_get_client):
        mock_bucket_1 = MagicMock(name="bucket-a")
        mock_bucket_1.name = "bucket-a"
        mock_bucket_2 = MagicMock(name="bucket-b")
        mock_bucket_2.name = "bucket-b"

        mock_client = MagicMock()
        mock_client.list_buckets.return_value = [mock_bucket_1, mock_bucket_2]
        mock_get_client.return_value = mock_client

        result = list_buckets()
        self.assertEqual(result, ["bucket-a", "bucket-b"])
