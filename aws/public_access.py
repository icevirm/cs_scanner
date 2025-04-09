from boto3 import client as boto_client

s3 = boto_client('s3')

def get_bucket_public_configuration(bucket):
    public_access_block = s3.get_public_access_block(
        Bucket=bucket
    )

    return public_access_block['PublicAccessBlockConfiguration']
