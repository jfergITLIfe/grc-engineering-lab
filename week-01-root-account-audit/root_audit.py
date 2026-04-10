import boto3
import json
import datetime
import time


def get_account_id(iam_client):
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def check_root_access_keys(credential_report):
    for line in credential_report.splitlines():
        if line.startswith("<root_account>"):
            fields = line.split(",")
            access_key_1_active = fields[8].strip().lower()
            access_key_2_active = fields[13].strip().lower()
            keys_exist = (access_key_1_active == "true" or access_key_2_active == "true")
            return {
                "control": "CIS 1.3",
                "title": "No root user access key exists",
                "status": "FAIL" if keys_exist else "PASS",
                "detail": "Root access key(s) are active. Remove immediately." if keys_exist else "No root access keys found.",
                "frameworks": {"CIS AWS v5.0": "1.3", "SOC 2": "CC6.3", "NIST 800-53 Rev 5": "AC-2"}
            }


def check_root_mfa(credential_report):
    for line in credential_report.splitlines():
        if line.startswith("<root_account>"):
            fields = line.split(",")
            mfa_active = fields[7].strip().lower()
            return {
                "control": "CIS 1.4",
                "title": "MFA enabled for root user",
                "status": "PASS" if mfa_active == "true" else "FAIL",
                "detail": "MFA is enabled on the root account." if mfa_active == "true" else "MFA is NOT enabled on root. Enable immediately.",
                "frameworks": {"CIS AWS v5.0": "1.4", "SOC 2": "CC6.1", "NIST 800-53 Rev 5": "IA-2"}
            }


def build_report(results, account_id):
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    errored = sum(1 for r in results if r["status"] == "ERROR")
    return {
        "report": "Root Account Exposure Check",
        "lab": "GRC Engineering Lab - Week 01",
        "account_id": account_id,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "summary": {"total_checks": len(results), "passed": passed, "failed": failed, "errors": errored, "posture": "PASS" if failed == 0 and errored == 0 else "FAIL"},
        "findings": results
    }


def print_report(report):
    summary = report["summary"]
    print("\n" + "=" * 60)
    print(f"  {report['report']}")
    print(f"  {report['lab']}")
    print("=" * 60)
    print(f"  Account : {report['account_id']}")
    print(f"  Run At  : {report['generated_at']}")
    print("-" * 60)
    print(f"  Checks  : {summary['total_checks']}")
    print(f"  Passed  : {summary['passed']}")
    print(f"  Failed  : {summary['failed']}")
    print(f"  Errors  : {summary['errors']}")
    print(f"  Posture : {summary['posture']}")
    print("=" * 60)
    for finding in report["findings"]:
        status_icon = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "ERROR"}.get(finding["status"], "?")
        print(f"\n  [{status_icon}] {finding['control']} - {finding['title']}")
        print(f"      {finding['detail']}")
        fw = finding["frameworks"]
        print(f"      Frameworks: " + " | ".join([f"{k}: {v}" for k, v in fw.items()]))
    print("\n" + "=" * 60 + "\n")


def main():
    iam = boto3.client("iam")
    print("\n[*] Generating IAM credential report...")
    iam.generate_credential_report()
    for _ in range(20):
        try:
            response = iam.get_credential_report()
            break
        except iam.exceptions.CredentialReportNotReadyException:
            time.sleep(3)
    credential_report = response["Content"].decode("utf-8")
    account_id = get_account_id(iam)
    results = [check_root_access_keys(credential_report), check_root_mfa(credential_report)]
    report = build_report(results, account_id)
    print_report(report)
    with open("root_audit_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("[*] Full report saved to root_audit_report.json\n")


if __name__ == "__main__":
    main()
