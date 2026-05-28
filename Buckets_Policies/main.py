from s3_scanner import scan_s3_buckets
from iam_scanner import scan_iam
from tabulate import tabulate
import json
import csv
from datetime import datetime, UTC

def generate_reports(all_results, account_id="897421226559", region="us-east-1"):
    scan_date = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    # -------------------------
    # JSON report (to send scan results in json format)
    # -------------------------
    report = {
        "scan_date": scan_date,
        "account": account_id,
        "region": region,
        "results": all_results,
        "summary": {
            "total_findings": len(all_results),
            "high": sum(1 for r in all_results if r["Severity"] == "HIGH"),
            "medium": sum(1 for r in all_results if r["Severity"] == "MEDIUM"),
            "low": sum(1 for r in all_results if r["Severity"] == "LOW")
        }
    }

    json_filename = "cloud_security_report.json"
    with open(json_filename, "w") as json_file:
        json.dump(report, json_file, indent=4)
    print(f"✅ JSON report saved as {json_filename}")

    # -------------------------
    # CSV report (to send scan results in csv format)
    # -------------------------
    csv_filename = "cloud_security_report.csv"
    fieldnames = ["Resource", "Type", "Issue", "Severity", "Impact"]
    with open(csv_filename, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_results:
            writer.writerow(r)
    print(f"✅ CSV report saved as {csv_filename}")

def main():
    print("\n🔍 Running Cloud Security Scan...\n")

    all_results = []

    # Scan S3 buckets
    s3_results = scan_s3_buckets()
    all_results.extend(s3_results)

    # Scan IAM users/policies
    iam_results = scan_iam()
    all_results.extend(iam_results)

    # Display results
    if all_results:
        print(tabulate(all_results, headers="keys", tablefmt="grid"))
        # Generate JSON + CSV reports automatically
        generate_reports(all_results)
    else:
        print("✅ No misconfigurations found!")

if __name__ == "__main__":
    main()