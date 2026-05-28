import boto3
import json
from botocore.exceptions import ClientError
from datetime import datetime

s3 = boto3.client('s3')


PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _is_public_grant(grant, allowed_permissions):
    grantee = grant.get('Grantee', {})
    permission = grant.get('Permission')
    uri = grantee.get('URI')

    return uri in PUBLIC_ACL_URIS and permission in allowed_permissions

def check_public_acl(bucket_name):
    try:
        bucket_acl = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in bucket_acl.get('Grants', []):
            if _is_public_grant(grant, {"READ", "WRITE", "FULL_CONTROL"}):
                return True

        objects = s3.list_objects_v2(Bucket=bucket_name)
        for obj in objects.get('Contents', []):
            object_acl = s3.get_object_acl(Bucket=bucket_name, Key=obj['Key'])

            for grant in object_acl.get('Grants', []):
                if _is_public_grant(grant, {"READ", "FULL_CONTROL"}):
                    return True
    except ClientError as e:
        print(f"[ERROR] ACL check failed for {bucket_name}: {e}")
    return False

def check_bucket_policy(bucket_name):
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        policy_json = json.loads(policy['Policy'])

        for statement in policy_json.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal')

                if principal == "*" or principal == {"AWS": "*"}:
                    return True
    except ClientError as e:
        error_code = e.response['Error']['Code']

        # EXPECTED case: no policy exists
        if error_code == "NoSuchBucketPolicy":
            return False

        # Real error (permission issue, etc.)
        print(f"[ERROR] Bucket policy check failed for {bucket_name}: {e}")
    return False


# Block Public Access check
def check_block_public_access(bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']

        # If ALL are true → public access is blocked
        return all(config.values())

    except ClientError as e:
        print(f"[ERROR] Block Public Access check failed for {bucket_name}: {e}")
        return False


# Object-level ACL check
def check_object_public_acl(bucket_name, max_objects=50):
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects)

        for obj in response.get('Contents', []):
            acl = s3.get_object_acl(Bucket=bucket_name, Key=obj['Key'])

            for grant in acl.get('Grants', []):
                if _is_public_grant(grant, {"READ", "FULL_CONTROL"}):
                    return True

    except ClientError as e:
        print(f"[ERROR] Object ACL check failed for {bucket_name}: {e}")

    return False

def check_bucket_versioning(bucket_name):
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get("Status") != "Enabled":
            return True
    except ClientError as e:
        print(f"[ERROR] Versioning check failed for {bucket_name}: {e}")
    return False

def check_bucket_encryption(bucket_name):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        # If no encryption
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return True
    return False

def scan_s3_buckets():
    results = []
    try:
        buckets = s3.list_buckets()
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return results

    for bucket in buckets.get('Buckets', []):
        name = bucket['Name']

        # check block public access once
        block_enabled = check_block_public_access(name)

        # Public ACL
        if check_public_acl(name):
            results.append({
                "Resource": name,
                "Type": "S3 Bucket",
                "Issue": "Public Access via ACL",
                "Severity": "HIGH",
                "Impact": "Anyone on the internet can read bucket contents"
            })

        # Object-level public access
        if check_object_public_acl(name) and not block_enabled:
            results.append({
                "Resource": name,
                "Type": "S3 Bucket",
                "Issue": "Public Objects via ACL",
                "Severity": "HIGH",
                "Impact": "Specific objects are publicly accessible"
            })

        # Public Policy
        if check_bucket_policy(name):
            results.append({
                "Resource": name,
                "Type": "S3 Bucket",
                "Issue": "Public Access via Bucket Policy",
                "Severity": "HIGH",
                "Impact": "Bucket data is publicly accessible due to open policy"
            })

        # Versioning Disabled
        if check_bucket_versioning(name):
            results.append({
                "Resource": name,
                "Type": "S3 Bucket",
                "Issue": "Versioning Disabled",
                "Severity": "MEDIUM",
                "Impact": "Deleted/modified objects cannot be recovered"
            })

        # Encryption Disabled
        if check_bucket_encryption(name):
            results.append({
                "Resource": name,
                "Type": "S3 Bucket",
                "Issue": "Server-side Encryption Disabled",
                "Severity": "MEDIUM",
                "Impact": "Data is stored in plaintext, vulnerable if leaked"
            })

    return results


def print_friendly(results):
    print("\nRunning S3 security scan...\n")
    print(f"{'Resource':30} | {'Issue':35} | {'Severity':8} | Impact")
    print("-" * 100)

    for item in results:
        resource = item.get('Resource', 'Unknown')
        issue = item.get('Issue', 'Unknown')
        severity = item.get('Severity', 'Unknown')
        impact = item.get('Impact', 'Unknown')

        print(f"{resource:30} | {issue:35} | {severity:8} | {impact}")