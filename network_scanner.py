import boto3
from tabulate import tabulate
from botocore.exceptions import ClientError
import json
import csv

DANGEROUS_PORTS = [22, 3389, 3306, 5432]

IMPACT_MAP = {
    "CRITICAL": "High risk - immediate remediation required",
    "HIGH": "Potential exposure to unauthorized access",
    "MEDIUM": "Security improvement recommended"
}


def scan_network():
    """Scan security groups across all AWS regions."""
    findings = []
    
    # Get all regions
    try:
        ec2_global = boto3.client('ec2', region_name='us-west-2')
        regions_response = ec2_global.describe_regions()
        regions = [r['RegionName'] for r in regions_response['Regions']]
    except ClientError as e:
        print(f"Error fetching regions: {e}")
        regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']  # Fallback
    
    print(f"Scanning security groups across {len(regions)} regions...")
    
    # Scan each region
    for region in regions:
        try:
            ec2 = boto3.client('ec2', region_name=region)
            response = ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                group_name = sg.get('GroupName', 'Unknown')
                group_id = sg.get('GroupId', 'Unknown')
                
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')

                    # handle protocol '-1' (all) or None ports → treat as all ports
                    ip_protocol = rule.get('IpProtocol')
                    if ip_protocol == '-1' or (from_port is None and to_port is None):
                        is_all_ports = True
                        from_port_val = 0
                        to_port_val = 65535
                    else:
                        is_all_ports = (from_port == 0 and to_port == 65535)
                        from_port_val = from_port
                        to_port_val = to_port

                    # collect both IPv4 and IPv6 ranges
                    ip_ranges = []
                    for ip in rule.get('IpRanges', []):
                        cidr = ip.get('CidrIp')
                        if cidr:
                            ip_ranges.append(cidr)
                    for ip6 in rule.get('Ipv6Ranges', []):
                        cidr6 = ip6.get('CidrIpv6')
                        if cidr6:
                            ip_ranges.append(cidr6)

                    # Resource identifier with region and group ID
                    resource_id = f"{group_name} ({group_id}) [{region}]"

                    for cidr in ip_ranges:
                        if not cidr:
                            continue

                        # GLOBAL open to world (IPv4 or IPv6)
                        if cidr == '0.0.0.0/0' or cidr == '::/0':
                            # All ports open (protocol -1 or missing ports)
                            if is_all_ports:
                                findings.append({
                                    'resource': resource_id,
                                    'type': 'Weak Security Rule',
                                    'issue': 'All ports open',
                                    'severity': 'CRITICAL',
                                    'impact': IMPACT_MAP['CRITICAL']
                                })
                                findings.append({
                                    'resource': resource_id,
                                    'type': 'Open Network Port',
                                    'issue': f'Port {from_port_val}-{to_port_val} open to world',
                                    'severity': 'HIGH',
                                    'impact': IMPACT_MAP['HIGH']
                                })
                                findings.append({
                                    'resource': resource_id,
                                    'type': 'Weak Security Rule',
                                    'issue': f'Weak IP range {cidr}',
                                    'severity': 'MEDIUM',
                                    'impact': IMPACT_MAP['MEDIUM']
                                })
                                continue

                            # Dangerous specific ports (e.g., 22) open to world
                            if from_port_val in DANGEROUS_PORTS:
                                findings.append({
                                    'resource': resource_id,
                                    'type': 'Open Network Port',
                                    'issue': f'Critical port {from_port_val} open to world',
                                    'severity': 'CRITICAL',
                                    'impact': IMPACT_MAP['CRITICAL']
                                })
                                findings.append({
                                    'resource': resource_id,
                                    'type': 'Open Network Port',
                                    'issue': f'Port {from_port_val}-{from_port_val} open to world',
                                    'severity': 'HIGH',
                                    'impact': IMPACT_MAP['HIGH']
                                })
                                findings.append({
                                    'resource': resource_id,
                                    'type': 'Weak Security Rule',
                                    'issue': f'Weak IP range {cidr}',
                                    'severity': 'MEDIUM',
                                    'impact': IMPACT_MAP['MEDIUM']
                                })
                                continue

                            # Generic open port range to world
                            findings.append({
                                'resource': resource_id,
                                'type': 'Open Network Port',
                                'issue': f'Port {from_port_val}-{to_port_val} open to world',
                                'severity': 'HIGH',
                                'impact': IMPACT_MAP['HIGH']
                            })
                            findings.append({
                                'resource': resource_id,
                                'type': 'Weak Security Rule',
                                'issue': f'Weak IP range {cidr}',
                                'severity': 'MEDIUM',
                                'impact': IMPACT_MAP['MEDIUM']
                            })

                        # non-global weak CIDR ranges (e.g., 10.0.0.0/8)
                        elif cidr.endswith('/0'):
                            findings.append({
                                'resource': resource_id,
                                'type': 'Weak Security Rule',
                                'issue': f'Weak IP range {cidr}',
                                'severity': 'MEDIUM',
                                'impact': IMPACT_MAP['MEDIUM']
                            })
        
        except ClientError as e:
            print(f"Error scanning region {region}: {e}")
            continue
    
    return findings


def print_report(results):
    table = []

    for r in results:
        table.append([
            r["resource"],
            r["type"],
            r["issue"],
            r["severity"],
            r["impact"]
        ])

    print("\nRunning Cloud Security Scan...\n")

    print(tabulate(
        table,
        headers=["Resource", "Type", "Issue", "Severity", "Impact"],
        tablefmt="grid"
    ))


# 💾 EXPORT TO JSON
def export_json(results, filename="scan_results.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n JSON report saved to {filename}")


# 💾 EXPORT TO CSV
def export_csv(results, filename="scan_results.csv"):
    if not results:
        return

    # convert keys to match headers
    formatted_results = [
        {
            "Resource": r["resource"],
            "Type": r["type"],
            "Issue": r["issue"],
            "Severity": r["severity"],
            "Impact": r["impact"]
        }
        for r in results
    ]

    fieldnames = ["Resource", "Type", "Issue", "Severity", "Impact"]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(formatted_results)

    print(f"CSV report saved to {filename}")


# 🚀 MAIN
if __name__ == "__main__":
    results = scan_network()

    if not results:
        print("No issues found.")
    else:
        print_report(results)
        export_json(results)
        export_csv(results)