# Week 01 — Root Account Exposure Check

**GRC Engineering Lab Series**
`Python` `boto3` `IAM` `CIS AWS v5.0` `SOC 2` `NIST 800-53`

---

## What This Does

Audits your AWS root account for two of the highest-severity misconfigurations in the CIS AWS Foundations Benchmark:

- **CIS 1.3** — No root user access key exists
- **CIS 1.4** — MFA is enabled for the root user

Outputs a pass/fail compliance report to the terminal and saves a structured JSON artifact you can use as audit evidence.

---

## Why This Matters

The root account is the most privileged identity in AWS. It bypasses IAM policies entirely. A root access key exposed in a breach, a leaked `.env` file, or a misconfigured CI/CD pipeline gives an attacker unrestricted access to every resource in your account with no IAM boundary to stop them.

This is the first thing an auditor checks. It should be the first thing you automate.

---

## Framework Mapping

| Control | CIS AWS v5.0 | SOC 2 | NIST 800-53 Rev 5 |
|---------|-------------|-------|-------------------|
| No root access key exists | 1.3 | CC6.3 | AC-2 |
| MFA enabled for root user | 1.4 | CC6.1 | IA-2 |

**SOC 2 context:**
- CC6.1 — Logical access security controls, including MFA enforcement
- CC6.3 — Access is removed or modified when no longer appropriate

**NIST 800-53 context:**
- AC-2 — Account Management: restricting use of privileged accounts
- IA-2 — Identification and Authentication: MFA for privileged users

---

## Prerequisites

- Python 3.8+
- boto3 installed (`pip install boto3`)
- AWS credentials configured (`aws configure` or environment variables)
- IAM permissions: `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `sts:GetCallerIdentity`

---

## Usage

```bash
# Clone the repo
git clone https://github.com/jfergITLife/grc-engineering-lab.git
cd grc-engineering-lab/week-01-root-account-audit

# Install dependency
pip install boto3

# Run the audit
python root_audit.py
```

---

## Sample Output

```
============================================================
  Root Account Exposure Check
  GRC Engineering Lab — Week 01
============================================================
  Account : 123456789012
  Run At  : 2026-04-09T18:00:00Z
------------------------------------------------------------
  Checks  : 2
  Passed  : 2
  Failed  : 0
  Errors  : 0
  Posture : PASS
============================================================

  ✅  [PASS] CIS 1.3 — No root user access key exists
      No root access keys found.
      Frameworks: CIS AWS v5.0: 1.3 | SOC 2: CC6.3 | NIST 800-53 Rev 5: AC-2

  ✅  [PASS] CIS 1.4 — MFA enabled for root user
      MFA is enabled on the root account.
      Frameworks: CIS AWS v5.0: 1.4 | SOC 2: CC6.1 | NIST 800-53 Rev 5: IA-2

============================================================
```

---

## Output Artifact

Running the script saves `root_audit_report.json` — a structured compliance report you can attach as audit evidence or feed into a larger reporting pipeline.

```json
{
  "report": "Root Account Exposure Check",
  "lab": "GRC Engineering Lab — Week 01",
  "account_id": "123456789012",
  "generated_at": "2026-04-09T18:00:00Z",
  "summary": {
    "total_checks": 2,
    "passed": 2,
    "failed": 0,
    "errors": 0,
    "posture": "PASS"
  },
  "findings": [...]
}
```

---

## Remediation

**If CIS 1.3 FAILS — root access key exists:**
1. AWS Console → IAM → Security credentials (signed in as root)
2. Under "Access keys" — deactivate and delete all keys
3. Re-run this script to confirm

**If CIS 1.4 FAILS — root MFA not enabled:**
1. AWS Console → IAM → Security credentials (signed in as root)
2. Under "Multi-factor authentication (MFA)" — assign an MFA device
3. Re-run this script to confirm

---

## IAM Policy for Least-Privilege Execution

If you want to run this with a dedicated audit role instead of your default credentials:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Part of a Series

This lab is Week 01 of a monthly IAM Hardening Audit Suite.

| Week | Lab | Focus |
|------|-----|-------|
| 01 | Root Account Exposure Check | CIS 1.3, 1.4 |
| 02 | IAM Credential Age Auditor | CIS 1.11, 1.13 |
| 03 | MFA Enforcement Checker | CIS 1.9 |
| 04 | IAM Hardening Audit Suite | CIS 1.3, 1.4, 1.9, 1.11, 1.13, 1.14, 1.16, 1.19 |

---

## About

Built by [Jacob Ferguson](https://linkedin.com/in/itlife) — Cybersecurity analyst at an MSSP, Rice MBA candidate, Navy veteran. Building at the intersection of technical security and compliance engineering.

Follow the series on [LinkedIn](https://linkedin.com/in/itlife) | [GitHub](https://github.com/jfergITLife)
