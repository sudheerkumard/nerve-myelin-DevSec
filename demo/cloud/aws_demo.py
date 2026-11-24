# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""A fictional AWS account served through boto3-shaped responses. Used to build the demo inventory
(demo/cloud/aws-inventory.json) and by the collector tests; it exercises the same code path as a live account."""
import json
from datetime import datetime, timedelta, timezone

ACCT = "411122223333"
NOW = datetime.now(timezone.utc)


def ago(d):
    return NOW - timedelta(days=d)


class _Err(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
OCR_POLICY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}]}
NOTIFY_POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["sns:Publish", "logs:CreateLogStream"], "Resource": "*"}]}
CREDENTIAL_REPORT = "\n".join([
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated",
    f"<root_account>,arn:aws:iam::{ACCT}:root,{ago(900).isoformat()},not_supported,{ago(3).isoformat()},not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
    f"ci-deploy,arn:aws:iam::{ACCT}:user/ci-deploy,{ago(400).isoformat()},false,N/A,N/A,N/A,false,true,{ago(212).isoformat()},{ago(1).isoformat()},ap-south-1,s3,true,{ago(380).isoformat()},{ago(140).isoformat()},ap-south-1,ecr,false,N/A,false,N/A",
    f"rahul.admin,arn:aws:iam::{ACCT}:user/rahul.admin,{ago(300).isoformat()},true,{ago(2).isoformat()},{ago(90).isoformat()},N/A,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
    f"auditor,arn:aws:iam::{ACCT}:user/auditor,{ago(200).isoformat()},true,{ago(5).isoformat()},{ago(30).isoformat()},N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
]).encode()


class _Client:
    def __init__(self, svc, region):
        self.svc, self.region = svc, region

    def __getattr__(self, name):
        fn = getattr(self, f"_{self.svc}_{name}", None)
        if fn is None:
            raise _Err("AccessDenied")
        return fn

    # STS / S3
    def _sts_get_caller_identity(self):
        return {"Account": ACCT}

    def _s3control_get_public_access_block(self, AccountId):
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}}

    def _s3_list_buckets(self):
        return {"Buckets": [{"Name": "acme-kyc-documents"}, {"Name": "acme-cloudtrail-logs"}]}

    def _s3_get_public_access_block(self, Bucket):
        if Bucket == "acme-cloudtrail-logs":
            return {"PublicAccessBlockConfiguration": {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}}
        raise _Err("NoSuchPublicAccessBlockConfiguration")

    def _s3_get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": Bucket == "acme-kyc-documents"}}

    def _s3_get_bucket_acl(self, Bucket):
        return {"Grants": []}

    def _s3_get_bucket_tagging(self, Bucket):
        if Bucket == "acme-kyc-documents":
            return {"TagSet": [{"Key": "git_repo", "Value": "platform-terraform"}, {"Key": "git_file", "Value": "aws/s3-kyc.tf"}]}
        raise _Err("NoSuchTagSet")

    def _s3_get_bucket_versioning(self, Bucket):
        return {"Status": "Enabled"} if Bucket == "acme-cloudtrail-logs" else {}

    def _s3_get_bucket_logging(self, Bucket):
        return {}

    # EC2
    def _ec2_describe_security_groups(self):
        return {"SecurityGroups": [
            {"GroupId": "sg-0a1b2c3d4e5f60718", "GroupName": "legacy-admin", "VpcId": "vpc-01", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"GroupId": "sg-0f9e8d7c6b5a40312", "GroupName": "loan-db", "VpcId": "vpc-01", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"GroupId": "sg-0123456789abcdef0", "GroupName": "internal-only", "VpcId": "vpc-01", "IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}

    def _ec2_describe_instances(self):
        return {"Reservations": [{"Instances": [
            {"InstanceId": "i-0c1d2e3f4a5b6c7d8", "State": {"Name": "running"}, "PublicIpAddress": "13.233.40.17",
             "MetadataOptions": {"HttpTokens": "optional"}, "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/kyc-ocr-profile"},
             "SecurityGroups": [{"GroupId": "sg-0a1b2c3d4e5f60718"}], "ImageId": "ami-0abc",
             "Tags": [{"Key": "Name", "Value": "kyc-ocr-worker"}, {"Key": "git_repo", "Value": "kyc-onboarding"}, {"Key": "git_file", "Value": "deploy/ec2.tf"}]},
            {"InstanceId": "i-0aa11bb22cc33dd44", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "required"},
             "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0"}], "Tags": [{"Key": "Name", "Value": "batch-runner"}]}]}]}

    def _ec2_get_ebs_encryption_by_default(self):
        return {"EbsEncryptionByDefault": False}

    def _guardduty_list_detectors(self):
        return {"DetectorIds": []}

    def _rds_describe_db_instances(self):
        return {"DBInstances": [{"DBInstanceIdentifier": "loan-db", "DBInstanceArn": f"arn:aws:rds:{self.region}:{ACCT}:db:loan-db",
                                 "PubliclyAccessible": True, "StorageEncrypted": False, "BackupRetentionPeriod": 1, "DeletionProtection": False,
                                 "Engine": "postgres", "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0f9e8d7c6b5a40312"}],
                                 "TagList": [{"Key": "git_repo", "Value": "loan-origination"}]}]}

    def _eks_list_clusters(self):
        return {"clusters": ["eks-trading"]}

    def _eks_describe_cluster(self, name):
        return {"cluster": {"arn": f"arn:aws:eks:{self.region}:{ACCT}:cluster/{name}", "version": "1.30",
                            "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]},
                            "logging": {"clusterLogging": [{"types": ["api"], "enabled": True}, {"types": ["audit", "authenticator"], "enabled": False}]},
                            "tags": {"git_repo": "trade-capture"}}}

    def _lambda_list_functions(self):
        return {"Functions": [{"FunctionName": "notify-webhook", "FunctionArn": f"arn:aws:lambda:{self.region}:{ACCT}:function:notify-webhook",
                               "Runtime": "python3.8", "Role": f"arn:aws:iam::{ACCT}:role/notify-role"}]}

    def _lambda_list_function_url_configs(self, FunctionName):
        return {"FunctionUrlConfigs": [{"AuthType": "NONE", "FunctionUrl": "https://abc123.lambda-url.ap-south-1.on.aws/"}]}

    def _kms_list_keys(self):
        return {"Keys": [{"KeyId": "6f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f"}]}

    def _kms_describe_key(self, KeyId):
        return {"KeyMetadata": {"Arn": f"arn:aws:kms:{self.region}:{ACCT}:key/{KeyId}", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT"}}

    def _kms_get_key_rotation_status(self, KeyId):
        return {"KeyRotationEnabled": False}

    def _cloudtrail_describe_trails(self, includeShadowTrails=False):
        return {"trailList": [{"Name": "mgmt-events", "TrailARN": f"arn:aws:cloudtrail:{self.region}:{ACCT}:trail/mgmt-events",
                               "IsMultiRegionTrail": False, "LogFileValidationEnabled": False}]}

    def _cloudtrail_get_trail_status(self, Name):
        return {"IsLogging": True}

    # IAM
    def _iam_get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}

    def _iam_get_account_password_policy(self):
        return {"PasswordPolicy": {"MinimumPasswordLength": 8, "PasswordReusePrevention": 0}}

    def _iam_generate_credential_report(self):
        return {"State": "COMPLETE"}

    def _iam_get_credential_report(self):
        return {"Content": CREDENTIAL_REPORT}

    def _iam_get_account_authorization_details(self, **kw):
        return {"IsTruncated": False,
                "UserDetailList": [
                    {"UserName": "ci-deploy", "Arn": f"arn:aws:iam::{ACCT}:user/ci-deploy", "CreateDate": ago(400),
                     "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]},
                    {"UserName": "rahul.admin", "Arn": f"arn:aws:iam::{ACCT}:user/rahul.admin", "CreateDate": ago(300), "GroupList": ["platform-admins"]},
                    {"UserName": "auditor", "Arn": f"arn:aws:iam::{ACCT}:user/auditor", "CreateDate": ago(200),
                     "AttachedManagedPolicies": [{"PolicyName": "SecurityAudit", "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"}]}],
                "GroupDetailList": [{"GroupName": "platform-admins", "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}],
                "RoleDetailList": [
                    {"RoleName": "kyc-ocr-role", "Arn": f"arn:aws:iam::{ACCT}:role/kyc-ocr-role", "Path": "/", "CreateDate": ago(500),
                     "AssumeRolePolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
                     "RolePolicyList": [{"PolicyName": "ocr-access", "PolicyDocument": json.dumps(OCR_POLICY)}],
                     "InstanceProfileList": [{"Arn": f"arn:aws:iam::{ACCT}:instance-profile/kyc-ocr-profile"}], "RoleLastUsed": {"LastUsedDate": ago(0)}},
                    {"RoleName": "notify-role", "Arn": f"arn:aws:iam::{ACCT}:role/notify-role", "Path": "/", "CreateDate": ago(100),
                     "AssumeRolePolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
                     "RolePolicyList": [{"PolicyName": "notify", "PolicyDocument": json.dumps(NOTIFY_POLICY)}], "RoleLastUsed": {"LastUsedDate": ago(0)}},
                    {"RoleName": "vendor-readonly", "Arn": f"arn:aws:iam::{ACCT}:role/vendor-readonly", "Path": "/", "CreateDate": ago(700),
                     "AssumeRolePolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}),
                     "AttachedManagedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}], "RoleLastUsed": {}},
                    {"RoleName": "break-glass-admin", "Arn": f"arn:aws:iam::{ACCT}:role/break-glass-admin", "Path": "/", "CreateDate": ago(800),
                     "AssumeRolePolicyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "sts:AssumeRole",
                                                                            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}),
                     "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                     "RoleLastUsed": {"LastUsedDate": ago(160)}},
                    {"RoleName": "AWSServiceRoleForSupport", "Arn": f"arn:aws:iam::{ACCT}:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
                     "Path": "/aws-service-role/support.amazonaws.com/"}],
                "Policies": [
                    {"PolicyName": "AdministratorAccess", "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                     "PolicyVersionList": [{"IsDefaultVersion": True, "Document": json.dumps(ADMIN)}]},
                    {"PolicyName": "SecurityAudit", "Arn": "arn:aws:iam::aws:policy/SecurityAudit",
                     "PolicyVersionList": [{"IsDefaultVersion": True, "Document": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["iam:Get*", "iam:List*", "s3:GetBucketPolicy", "ec2:Describe*"], "Resource": "*"}]})}]},
                    {"PolicyName": "ReadOnlyAccess", "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                     "PolicyVersionList": [{"IsDefaultVersion": True, "Document": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "ec2:Describe*"], "Resource": "*"}]})}]}]}


def client(svc, region):
    return _Client(svc, region)
