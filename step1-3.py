import boto3
import json
import os
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


# Define role names
roles_to_create = {
    "Dev": {
        "TrustPolicy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    },
    "User": {
        "TrustPolicy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    }
}

# Step 1: Check if roles exist before creating them
for role_name, role_data in roles_to_create.items():
    try:
        iam.get_role(RoleName=role_name)
        print(f"Role '{role_name}' already exists, skipping creation.")
    except iam.exceptions.NoSuchEntityException:
        # Role does not exist, create it
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(role_data["TrustPolicy"])
        )
        print(f"Role '{role_name}' created successfully.")

# Step 2: Attach policies to roles
iam.attach_role_policy(
    RoleName="Dev",
    PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
)

# Create a custom policy for User role with limited S3 access
user_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]
        }
    ]
}

# Check if the policy already exists before creating it
policy_name = "UserLimitedS3Access"
existing_policies = iam.list_policies(Scope='Local')
policy_arn = None

for policy in existing_policies['Policies']:
    if policy['PolicyName'] == policy_name:
        policy_arn = policy['Arn']
        print(f"Policy '{policy_name}' already exists. Using existing policy.")
        break

# If policy does not exist, create it
if not policy_arn:
    policy_response = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(user_policy)
    )
    policy_arn = policy_response['Policy']['Arn']
    print(f"Policy '{policy_name}' created successfully.")

# Attach the policy to User role
iam.attach_role_policy(
    RoleName="User",
    PolicyArn=policy_arn
)

print("Policies attached successfully.")



# Step 3: Create IAM user and attach policies
user_name = "user_assignment1"

try:
    iam.get_user(UserName=user_name)
    print(f"User '{user_name}' already exists, skipping creation.")
except iam.exceptions.NoSuchEntityException:
    iam.create_user(UserName=user_name)
    print(f"User '{user_name}' created successfully.")

# Attach S3 Full Access policy to the new user
iam.attach_user_policy(
    UserName=user_name,
    PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
)

# Attach IAM policies to allow AssumeRole
assume_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": [
                "arn:aws:iam::783764596465:role/Dev",
                "arn:aws:iam::783764596465:role/User"
            ]
        }
    ]
}


iam.put_user_policy(
    UserName=user_name,
    PolicyName="AssumeRolePolicy",
    PolicyDocument=json.dumps(assume_role_policy)
)

print("S3FullAccess and AssumeRole permissions added to user_assignment1")

# Step 3.1: Update trust relationship for Dev role to allow AssumeRole
trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::783764596465:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": "arn:aws:iam::783764596465:user/user_assignment1"
                }
            }
        }
    ]
}


# Update trust policy only if the role exists
for role_name in ["Dev", "User"]:
    try:
        iam.get_role(RoleName=role_name)
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )
        print(f"Updated trust policy for role '{role_name}'.")
    except iam.exceptions.NoSuchEntityException:
        print(f"Role '{role_name}' does not exist, skipping trust policy update.")
