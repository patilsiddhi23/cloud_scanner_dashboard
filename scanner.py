import json
import os
from datetime import datetime, timezone

print("🔎 scanner.py loading — integrating sub-scanners...")


def _normalize(item):
    """Normalize scanner outputs to lowercase keys.

    Accepts dictionaries with either TitleCase keys (from older scanners)
    or lowercase keys and returns standardized keys:
    resource, type, issue, severity, impact
    """
    if not isinstance(item, dict):
        return None

    resource = item.get('resource') or item.get('Resource') or item.get('ResourceName')
    type_ = item.get('type') or item.get('Type')
    issue = item.get('issue') or item.get('Issue')
    severity = item.get('severity') or item.get('Severity')
    impact = item.get('impact') or item.get('Impact')

    return {
        'resource': resource,
        'type': type_,
        'issue': issue,
        'severity': severity,
        'impact': impact
    }


def run_scan():
    """Run all available scanners (S3, IAM, Network) and save a unified report."""
    findings = []

    # Dynamically import the modules where possible so missing pieces
    # won't crash the whole run.
    try:
        from Buckets_Policies import s3_scanner, iam_scanner
    except Exception as e:
        print("Could not import Buckets_Policies scanners:", e)
        s3_scanner = None
        iam_scanner = None

    try:
        import network_scanner
    except Exception as e:
        print("Could not import network_scanner:", e)
        network_scanner = None

    # S3
    if s3_scanner:
        try:
            s3_results = s3_scanner.scan_s3_buckets()
            for it in s3_results:
                n = _normalize(it)
                if n:
                    findings.append(n)
        except Exception as e:
            print("S3 scanner error:", e)

    # IAM
    if iam_scanner:
        try:
            iam_results = iam_scanner.scan_iam()
            for it in iam_results:
                n = _normalize(it)
                if n:
                    findings.append(n)
        except Exception as e:
            print("IAM scanner error:", e)

    # Network (security groups)
    if network_scanner:
        try:
            net_results = network_scanner.scan_network()
            for it in net_results:
                n = _normalize(it)
                if n:
                    findings.append(n)
        except Exception as e:
            print("Network scanner error:", e)

    # Fallback: if no findings and no scanners available, keep empty list

    # Ensure reports folder exists
    if not os.path.exists('reports'):
        os.makedirs('reports')

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
    filename = f'reports/report_{timestamp}.json'

    with open(filename, 'w') as fh:
        json.dump(findings, fh, indent=4)

    print(f"✅ Report saved: {filename}")
    print(f"🔍 Findings count: {len(findings)}")

    return findings