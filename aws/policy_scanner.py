import requests
import json
import boto3

s3 = boto3.client('s3')

def list_buckets() -> list:
    '''
        Returns all S3 buckets in the current account, except CDK bootstrap one

        Args: None
        Returns: (list) buckets - list of S3 buckets in the current account
    '''
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets']
               if not bucket['Name'].startswith('cdk-')]

    return buckets

buckets = list_buckets()

for bucket in buckets:
    policy = s3.get_bucket_policy(Bucket=bucket)
    prompt = f"""Evaluate the following AWS IAM policy. 
    Respond strictly in JSON with this format: 
    {{"Policy": "Good" or "Bad", "Reason": "short explanation"}}.

    Policy:
    {json.dumps(policy, indent=2)}
    """

    response = requests.post(
        'http://192.168.2.19:11434/api/generate',
        json={
            'model': 'mistral',
            'prompt': prompt,
            'stream': False
        }
    )

    output = response.json()['response']

    try:
        result = json.loads(output)
        print("Policy:", result['Policy'])
        print("Reason:", result['Reason'])
    except json.JSONDecodeError:
        print("Failed to decode response:")
        print(output)
