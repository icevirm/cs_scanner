from boto3 import client as boto_client

s3 = boto_client('s3')

def get_bucket_public_configuration(bucket):
    public_access_block = s3.get_public_access_block(
        Bucket=bucket
    )

    for block in public_access_block['PublicAccessBlockConfiguration'].values():
        if not block:
            return False
          
    return True
