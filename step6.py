import boto3
import json
import os
import uuid
from dotenv import load_dotenv

load_dotenv()
aws_access_key = os.getenv("AWS_ACCESS_KEY")
aws_secret_key = os.getenv("AWS_SECRET_KEY")

iam = boto3.client(
    'iam',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name='us-east-1'
)

sts = boto3.client(
    'sts',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name='us-east-1'
)

s3_resource = boto3.resource(
    's3',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name='us-east-1'
)

# Step 6: Delete objects and the bucket

# Use the IAM client to find the ARN of the 'Dev' role
roles = iam.list_roles()
role_arn = None
for role in roles['Roles']:
    if role['RoleName'] == 'Dev':
        role_arn = role['Arn']
        break

# If the 'Dev' role is not found, manually paste the role ARN
if not role_arn:
    print("Role 'Dev' not found. Please paste the role ARN manually.")

# Replace these with the actual access keys of the new IAM user
access_key = os.getenv("AWS_ACCESS_KEY_NEW")
secret_key = os.getenv("AWS_SECRET_KEY_NEW")

# Create a specific STS client using the new IAM user's credentials
sts_client = boto3.client(
    'sts',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
)

# Assume the role using the new user's credentials
assumed_role = sts_client.assume_role(
    RoleArn=role_arn,
    RoleSessionName="DevSession"
)
credentials = assumed_role['Credentials']

# Create a new S3 resource object using the assumed role credentials
s3_assumed_resource = boto3.resource(
    's3',
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken'],
    region_name='us-east-2'
)

bucket = s3_assumed_resource.Bucket(f"2xycs6620")

# Delete all objects
for obj in bucket.objects.all():
    obj.delete()

# Delete the bucket
bucket.delete()
print(f"Bucket and all objects deleted successfully.")
