import boto3
from datetime import datetime, timedelta

iam = boto3.client('iam')

def scan_managed_policies():
    results = []
    policies = iam.list_policies(Scope='Local').get('Policies', [])

    for policy in policies:
        arn = policy['Arn']
        try:
            version = iam.get_policy_version(
                PolicyArn=arn,
                VersionId=policy['DefaultVersionId']
            )
            document = version['PolicyVersion']['Document']
            for statement in document.get('Statement', []):
                actions = statement.get('Action')
                resources = statement.get('Resource')

                # Normalize
                if isinstance(actions, str): actions = [actions]
                if isinstance(resources, str): resources = [resources]

                if "*" in actions or "*" in resources:
                    results.append({
                        "Resource": policy['PolicyName'],
                        "Type": "IAM Policy",
                        "Issue": "Overly Permissive Managed Policy",
                        "Severity": "HIGH",
                        "Impact": "Grants full access to all actions/resources"
                    })
        except Exception as e:
            print(f"Error checking policy {policy['PolicyName']}: {e}")
    return results

def scan_inline_policies():
    results = []
    users = iam.list_users().get('Users', [])
    for user in users:
        username = user['UserName']
        inline_policies = iam.list_user_policies(UserName=username).get('PolicyNames', [])
        for policy_name in inline_policies:
            try:
                policy = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                document = policy['PolicyDocument']
                statements = document.get('Statement', [])
                if not isinstance(statements, list): statements = [statements]
                for st in statements:
                    actions = st.get('Action')
                    resources = st.get('Resource')
                    if isinstance(actions, str): actions = [actions]
                    if isinstance(resources, str): resources = [resources]
                    if "*" in actions or "*" in resources:
                        results.append({
                            "Resource": f"{username} ({policy_name})",
                            "Type": "IAM Inline Policy",
                            "Issue": "Overly Permissive Inline Policy",
                            "Severity": "HIGH",
                            "Impact": "Grants full access to all actions/resources"
                        })
            except Exception as e:
                print(f"Error checking inline policy {policy_name} for {username}: {e}")
    return results

def scan_access_keys():
    results = []
    users = iam.list_users().get('Users', [])
    ninety_days_ago = datetime.utcnow() - timedelta(days=90)
    for user in users:
        keys = iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata', [])
        for key in keys:
            if key['CreateDate'].replace(tzinfo=None) < ninety_days_ago:
                results.append({
                    "Resource": f"{user['UserName']} ({key['AccessKeyId']})",
                    "Type": "IAM User",
                    "Issue": "Old Access Key (>90 days)",
                    "Severity": "LOW",
                    "Impact": "Access key may be at risk of compromise"
                })
    return results

def scan_iam():
    results = []
    results.extend(scan_managed_policies())
    results.extend(scan_inline_policies())
    results.extend(scan_access_keys())
    return results