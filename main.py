# %% 
# Import necessary libraries
import boto3
import json
import os
from dotenv import load_dotenv

load_dotenv()
aws_access_key = os.getenv("AWS_ACCESS_KEY")
aws_secret_key = os.getenv("AWS_SECRET_KEY")

# Initialize clients
iam = boto3.client('iam')
sts = boto3.client('sts')
s3_resource = boto3.resource('s3')

# %% 
# Step 1: Create IAM roles 'Dev' and 'User'
dev_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

user_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

# Create roles
dev_role = iam.create_role(
    RoleName='Dev',
    AssumeRolePolicyDocument=json.dumps(dev_role_policy)
)

user_role = iam.create_role(
    RoleName='User',
    AssumeRolePolicyDocument=json.dumps(user_role_policy)
)

print("Roles 'Dev' and 'User' created successfully.")



# %%
# Step 2: Attach policies to roles

# Attach S3 Full Access policy to Dev role
iam.attach_role_policy(
    RoleName='Dev',
    PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess'
)

# Create a custom policy for User role with limited S3 access
user_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::*",
                "arn:aws:s3:::*/*"
            ]
        }
    ]
}

user_policy_response = iam.create_policy(
    PolicyName='UserLimitedS3Access',
    PolicyDocument=json.dumps(user_policy)
)

# Attach the created policy to User role
iam.attach_role_policy(
    RoleName='User',
    PolicyArn=user_policy_response['Policy']['Arn']
)

print("Policies attached successfully.")

# %% 
# Step2.1 Update trust relationship for Dev role to allow AssumeRole
# Define the trust policy to allow user_assignment1 to assume the Dev role
trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

# Update the trust policy for the Dev role
iam.update_assume_role_policy(
    RoleName='Dev',
    PolicyDocument=json.dumps(trust_policy)
)
iam.update_assume_role_policy(
    RoleName='User',
    PolicyDocument=json.dumps(trust_policy)
)

print("Dev role trust policy updated to allow users to assume the role.")

# %% 
# Step 3: Create IAM user and attach policies
user_name = 'user_assignment1'
iam.create_user(UserName=user_name)
print(f"User {user_name} created successfully.")

# Attach S3 Full Access policy to the new user
iam.attach_user_policy(
    UserName='user_assignment1',
    PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess'
)

# Attach IAM policies to allow AssumeRole
assume_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*"
        }
    ]
}

response = iam.put_user_policy(
    UserName='user_assignment1',
    PolicyName='AssumeRolePolicy',
    PolicyDocument=json.dumps(assume_role_policy)
)

print("S3FullAccess and AssumeRole permissions added to user_assignment1")


# %% 
# Step 4: Assume role and create buckets and objects

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
access_key = aws_access_key
secret_key = aws_secret_key

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

# Create S3 bucket and upload files

# Generate a unique bucket name
import uuid
bucket_name = f"lecture1-{uuid.uuid4()}"  # Use a random UUID to ensure the bucket name is unique

# Create S3 bucket
bucket = s3_assumed_resource.Bucket(bucket_name)
bucket.create(
    CreateBucketConfiguration={
        'LocationConstraint': 'us-east-2'  # Replace with your desired region
    }
)
print(f"Bucket '{bucket_name}' created successfully.")

# Upload assignment files
bucket.put_object(Key='assignment1.txt', Body='Empty Assignment 1')
bucket.put_object(Key='assignment2.txt', Body='Empty Assignment 2')

# Upload image file (replace with your local image path)
with open('little yellow.jpg', 'rb') as img_file:
    bucket.put_object(Key='recording1.jpg', Body=img_file)

print("Objects uploaded successfully.")


# %%
# Step 5: Assume User role and compute total size of objects

# Use the IAM client to find the ARN of the 'User' role
roles = iam.list_roles()
role_arn = None
for role in roles['Roles']:
    if role['RoleName'] == 'User':
        role_arn = role['Arn']
        break

# If the 'User' role is not found, manually paste the role ARN
if not role_arn:
    print("Role 'User' not found. Please paste the role ARN manually.")

# Replace these with the actual access keys of the new IAM user
access_key = aws_access_key
secret_key = aws_secret_key

# Create a specific STS client using the new IAM user's credentials
sts_client = boto3.client(
    'sts',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
)

# Assume the role using the new user's credentials
assumed_role = sts_client.assume_role(
    RoleArn=role_arn,
    RoleSessionName="UserSession"
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


bucket = s3_assumed_resource.Bucket(bucket_name)

total_size = 0
for obj in bucket.objects.filter(Prefix='assignment'):
    total_size += obj.size

print(f"Total size of objects with prefix 'assignment': {total_size} bytes.")

# %% 
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
access_key = aws_access_key
secret_key = aws_secret_key

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

bucket = s3_assumed_resource.Bucket(bucket_name)

# Delete all objects
for obj in bucket.objects.all():
    obj.delete()

# Delete the bucket
bucket.delete()
print(f"Bucket '{bucket_name}' and all objects deleted successfully.")


# %%
