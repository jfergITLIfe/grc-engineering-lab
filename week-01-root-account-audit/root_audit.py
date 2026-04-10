"""
root_audit.py
-------------
GRC Engineering Lab | Week 01
Root Account Exposure Check

Checks:
  CIS AWS Foundations Benchmark v5.0 — 1.3, 1.4
  SOC 2 — CC6.1, CC6.3
  NIST 800-53 Rev 5 — IA-2, IA-5, AC-2

Author: Jacob Ferguson | github.com/jfergITLife
"""

import boto3
import json
import datetime


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_account_id(iam_client):
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def check_root_access_keys(credential_report):
    """
    CIS 1.3 — Ensure no root user access key exists.
    Parses the IAM credential report for the root account row.
    """
    for line in credential_report.splitlines():
        if line.startswith("<root_account>"):
            fields = line.split(",")
            # credential report columns: user, arn, user_creation_time,
            # password_enabled, password_last_used, password_last_changed,
            # password_next_rotation, mfa_active,
            # access_key_1_active, access_key_2_active, ...
            access_key_1_active = fields[8].strip().lower()
            access_key_2_active = fields[13].strip().lower()

            keys_exist = (access_key_1_active == "true" or
                          access_key_2_active == "true")

            return {
                "control": "CIS 1.3",
                "title": "No root user access key exists",
                "status": "FAIL" if keys_exist else "PASS",
                "detail": (
                    "Root access key(s) are active. Remove immediately."
                    if keys_exist
                    else "No root access keys found."
                ),
                "frameworks": {
                    "CIS AWS v5.0": "1.3",
                    "SOC 2": "CC6.3",
                    "NIST 800-53 Rev 5": "AC-2"
                }
            }

    return {
        "control": "CIS 1.3",
        "title": "No root user access key exists",
        "status": "ERROR",
        "detail": "Root account row not found in credential report.",
        "frameworks": {
            "CIS AWS v5.0": "1.3",
            "SOC 2": "CC6.3",
            "NIST 800-53 Rev 5": "AC-2"
        }
    }


def check_root_mfa(credential_report):
    """
    CIS 1.4 — Ensure MFA is enabled for the root user account.
    """
    for line in credential_report.splitlines():
        if line.startswith("<root_account>"):
            fields = line.split(",")
            mfa_active = fields[7].strip().lower()

            return {
                "control": "CIS 1.4",
                "title": "MFA enabled for root user",
                "status": "PASS" if mfa_active == "true" else "FAIL",
                "detail": (
                    "MFA is enabled on the root account."
                    if mfa_active == "true"
                    else "MFA is NOT enabled on root. Enable immediately."
                ),
                "frameworks": {
                    "CIS AWS v5.0": "1.4",
                    "SOC 2": "CC6.1",
                    "NIST 800-53 Rev 5": "IA-2"
                }
            }

    return {
        "control": "CIS 1.4",
        "title": "MFA enabled for root user",
        "status": "ERROR",
        "detail": "Root account row not found in credential report.",
        "frameworks": {
            "CIS AWS v5.0": "1.4",
            "SOC 2": "CC6.1",
            "NIST 800-53 Rev 5": "IA-2"
        }
    }


# ── Report ────────────────────────────────────────────────────────────────────

def build_report(results, account_id):
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    errored = sum(1 for r in results if r["status"] == "ERROR")

    return {
        "report": "Root Account Exposure Check",
        "lab": "GRC Engineering Lab — Week 01",
        "account_id": account_id,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_checks": len(results),
            "passed": passed,
            "failed": failed,
            "errors": errored,
            "posture": "PASS" if failed == 0 and errored == 0 else "FAIL"
        },
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
        status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️ "}.get(
            finding["status"], "?"
        )
        print(f"\n  {status_icon}  [{finding['status']}] {finding['control']} — {finding['title']}")
        print(f"      {finding['detail']}")
        print(f"      Frameworks: ", end="")
        fw = finding["frameworks"]
        print(" | ".join([f"{k}: {v}" for k, v in fw.items()]))

    print("\n" + "=" * 60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    iam = boto3.client("iam")

    print("\n[*] Generating IAM credential report...")
    iam.generate_credential_report()

    import time
    for _ in range(10):
        response = iam.get_credential_report()
        if response["GeneratedTime"]:
            break
        time.sleep(2)

    credential_report = response["Content"].decode("utf-8")
    account_id = get_account_id(iam)

    results = [
        check_root_access_keys(credential_report),
        check_root_mfa(credential_report),
    ]

    report = build_report(results, account_id)
    print_report(report)

    with open("root_audit_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("[*] Full report saved to root_audit_report.json\n")


if __name__ == "__main__":
    main()
jacob@jferg:~/grc-engineering-lab/week-01-root-account-audit$ ^C
jacob@jferg:~/grc-engineering-lab/week-01-root-account-audit$ cat ~/Downloads/root_audit.py
"""
root_audit.py
-------------
GRC Engineering Lab | Week 01
Root Account Exposure Check

Checks:
  CIS AWS Foundations Benchmark v5.0 — 1.3, 1.4
  SOC 2 — CC6.1, CC6.3
  NIST 800-53 Rev 5 — IA-2, IA-5, AC-2

Author: Jacob Ferguson | github.com/jfergITLife
"""

import boto3
import json
import datetime


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_account_id(iam_client):
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def check_root_access_keys(credential_report):
    """
    CIS 1.3 — Ensure no root user access key exists.
    Parses the IAM credential report for the root account row.
    """
    for line in credential_report.splitlines():
        if line.startswith("<root_account>"):
            fields = line.split(",")
            # credential report columns: user, arn, user_creation_time,
            # password_enabled, password_last_used, password_last_changed,
            # password_next_rotation, mfa_active,
            # access_key_1_active, access_key_2_active, ...
            access_key_1_active = fields[8].strip().lower()
            access_key_2_active = fields[13].strip().lower()

            keys_exist = (access_key_1_active == "true" or
                          access_key_2_active == "true")

            return {
                "control": "CIS 1.3",
                "title": "No root user access key exists",
                "status": "FAIL" if keys_exist else "PASS",
                "detail": (
                    "Root access key(s) are active. Remove immediately."
                    if keys_exist
                    else "No root access keys found."
                ),
                "frameworks": {
                    "CIS AWS v5.0": "1.3",
                    "SOC 2": "CC6.3",
                    "NIST 800-53 Rev 5": "AC-2"
                }
            }

    return {
        "control": "CIS 1.3",
        "title": "No root user access key exists",
        "status": "ERROR",
        "detail": "Root account row not found in credential report.",
        "frameworks": {
            "CIS AWS v5.0": "1.3",
            "SOC 2": "CC6.3",
            "NIST 800-53 Rev 5": "AC-2"
        }
    }


def check_root_mfa(credential_report):
    """
    CIS 1.4 — Ensure MFA is enabled for the root user account.
    """
    for line in credential_report.splitlines():
        if line.startswith("<root_account>"):
            fields = line.split(",")
            mfa_active = fields[7].strip().lower()

            return {
                "control": "CIS 1.4",
                "title": "MFA enabled for root user",
                "status": "PASS" if mfa_active == "true" else "FAIL",
                "detail": (
                    "MFA is enabled on the root account."
                    if mfa_active == "true"
                    else "MFA is NOT enabled on root. Enable immediately."
                ),
                "frameworks": {
                    "CIS AWS v5.0": "1.4",
                    "SOC 2": "CC6.1",
                    "NIST 800-53 Rev 5": "IA-2"
                }
            }

    return {
        "control": "CIS 1.4",
        "title": "MFA enabled for root user",
        "status": "ERROR",
        "detail": "Root account row not found in credential report.",
        "frameworks": {
            "CIS AWS v5.0": "1.4",
            "SOC 2": "CC6.1",
            "NIST 800-53 Rev 5": "IA-2"
        }
    }


# ── Report ────────────────────────────────────────────────────────────────────

def build_report(results, account_id):
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    errored = sum(1 for r in results if r["status"] == "ERROR")

    return {
        "report": "Root Account Exposure Check",
        "lab": "GRC Engineering Lab — Week 01",
        "account_id": account_id,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_checks": len(results),
            "passed": passed,
            "failed": failed,
            "errors": errored,
            "posture": "PASS" if failed == 0 and errored == 0 else "FAIL"
        },
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
        status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️ "}.get(
            finding["status"], "?"
        )
        print(f"\n  {status_icon}  [{finding['status']}] {finding['control']} — {finding['title']}")
        print(f"      {finding['detail']}")
        print(f"      Frameworks: ", end="")
        fw = finding["frameworks"]
        print(" | ".join([f"{k}: {v}" for k, v in fw.items()]))

    print("\n" + "=" * 60 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    iam = boto3.client("iam")

    print("\n[*] Generating IAM credential report...")
    iam.generate_credential_report()

    import time
    for _ in range(10):
        response = iam.get_credential_report()
        if response["GeneratedTime"]:
            break
        time.sleep(2)

    credential_report = response["Content"].decode("utf-8")
    account_id = get_account_id(iam)

    results = [
        check_root_access_keys(credential_report),
        check_root_mfa(credential_report),
    ]

    report = build_report(results, account_id)
    print_report(report)

    with open("root_audit_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("[*] Full report saved to root_audit_report.json\n")


if __name__ == "__main__":
    main()