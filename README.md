# GRC Engineering Lab

One GRC Engineering project per week. Real problems. Real frameworks. Real code.

This repo is the index for a growing library of open-source tools that automate governance, risk, and compliance work in AWS. Every project includes the business case it solves, the compliance frameworks it maps to, and what I learned building it.

The goal: replace spreadsheets with scripts, manual evidence collection with automated checks, and compliance theater with engineering rigor.

Built against **CIS AWS Foundations Benchmark v7.0.0** (2026) and mapped to **CIS Controls v8.1**.

## How the CIS Pieces Fit Together

CIS publishes two separate but related products:

- **CIS Controls v8.1** — 18 high-level, organization-wide security safeguards. Vendor-neutral. The "what to do" layer.
- **CIS AWS Foundations Benchmark v7.0** — prescriptive, AWS-specific configuration checks. The "how to do it on AWS" layer.

Each AWS Benchmark recommendation maps back to a CIS Controls v8.1 safeguard. This project automates the Benchmark checks and traces each one up through all five frameworks.

## Project Index

| Week | Project | Benchmark Section | Frameworks | Status |
|------|---------|-------------------|------------|--------|
| 01 | *Coming soon* | | | |

## CIS AWS Foundations Benchmark v7.0.0 — Control Coverage

*Control tables will be finalized once the v7.0 benchmark PDF is reviewed. The sections below reflect the standard benchmark structure. Controls from v5.0 are listed as a baseline and will be updated to match v7.0 numbering.*

### Section 1 — Identity and Access Management

| Benchmark | Control | Automated | Project |
|-----------|---------|-----------|---------|
| 1.2 | Security contact information registered | — | |
| 1.3 | No root user access key exists | — | |
| 1.4 | MFA enabled for root user | — | |
| 1.5 | Hardware MFA enabled for root user | — | |
| 1.7 | Password policy minimum length 14+ | — | |
| 1.8 | Password policy prevents reuse | — | |
| 1.9 | MFA enabled for all IAM console users | — | |
| 1.11 | Credentials unused 45+ days removed | — | |
| 1.13 | Access keys rotated every 90 days | — | |
| 1.14 | IAM users get permissions through groups only | — | |
| 1.16 | Support role exists for AWS Support | — | |
| 1.18 | Expired SSL/TLS certs in IAM removed | — | |
| 1.19 | IAM Access Analyzer enabled | — | |
| 1.21 | AWSCloudShellFullAccess not attached | — | |

### Section 2 — Storage

| Benchmark | Control | Automated | Project |
|-----------|---------|-----------|---------|
| 2.1.1 | S3 bucket policy denies HTTP (SSL required) | — | |
| 2.1.2 | MFA Delete enabled on S3 buckets | — | |
| 2.1.4 | S3 Block Public Access enabled | — | |
| 2.2.1 | RDS encryption at rest enabled | — | |
| 2.2.2 | RDS automatic minor version upgrades enabled | — | |
| 2.2.3 | RDS instances prohibit public access | — | |
| 2.2.4 | RDS multi-AZ configured | — | |
| 2.3.1 | EFS encrypted at rest with KMS | — | |

### Section 3 — Logging

| Benchmark | Control | Automated | Project |
|-----------|---------|-----------|---------|
| 3.1 | CloudTrail enabled in all regions | — | |
| 3.2 | CloudTrail log file validation enabled | — | |
| 3.3 | AWS Config enabled in all regions | — | |
| 3.4 | S3 access logging on CloudTrail bucket | — | |
| 3.5 | CloudTrail logs encrypted with KMS | — | |
| 3.6 | KMS key rotation enabled | — | |
| 3.7 | VPC flow logging enabled in all VPCs | — | |

### Section 4 — Monitoring

Most CloudWatch metric filter and alarm controls are classified as manual checks. These are not part of the automated benchmark but can be checked via CloudWatch APIs. Future projects may cover these.

### Section 5 — Networking

| Benchmark | Control | Automated | Project |
|-----------|---------|-----------|---------|
| 5.1.1 | EBS default encryption enabled | — | |
| 5.2 | NACLs block 0.0.0.0/0 to port 22 and 3389 | — | |
| 5.3 | Security groups block 0.0.0.0/0 to admin ports | — | |
| 5.4 | Security groups block ::/0 to admin ports | — | |
| 5.5 | Default security group restricts all traffic | — | |
| 5.7 | EC2 instances use IMDSv2 | — | |

## Cross-Framework Mappings

Each project maps AWS Benchmark checks through five frameworks:

1. **CIS AWS Foundations Benchmark v7.0** — the specific technical check (what the code does)
2. **CIS Controls v8.1** — the parent organizational safeguard
3. **SOC 2 Trust Services Criteria** — [coverage tracker](framework-coverage/soc2.md)
4. **ISO 27001:2022** — [coverage tracker](framework-coverage/iso-27001.md)
5. **NIST 800-53 Rev 5** — [coverage tracker](framework-coverage/nist-800-53.md)

## Learning Roadmap

[How weekly projects map to AWS skill development and cert prep →](LEARNING_ROADMAP.md)

## Project Structure

Every weekly project repo follows a consistent format:

1. **The Problem** — what business or compliance gap this addresses
2. **The Business Case** — why it matters, tied to real risk
3. **Frameworks** — CIS Benchmark, CIS Controls v8.1, SOC 2, ISO 27001, NIST 800-53 mappings
4. **What I Learned** — AWS services, APIs, and concepts from building it
5. **How It Works** — technical approach
6. **Usage** — run it yourself
7. **Sample Output** — what the results look like
8. **Remediation** — what to do when a check fails

[Project README template →](templates/PROJECT_README.md)

## Who This Is For

- GRC engineers and analysts looking for automation examples
- Security engineers studying for AWS certifications
- Anyone tired of doing compliance in spreadsheets

## About

Built by [Jacob Ferguson](https://linkedin.com/in/itlife). Cybersecurity analyst at an MSSP, Rice MBA candidate, Navy veteran. Building at the intersection of technical security and business risk strategy.

Weekly project posts on [LinkedIn](https://linkedin.com/in/itlife).
