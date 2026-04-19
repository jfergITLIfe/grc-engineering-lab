# S3 Public Access Audit Report

**AWS Account:** 000000000000
**Generated:** 2026-04-19T21:14:46.642927Z
**Collector:** s3-public-access v0.1.0
**Schema Version:** 0.1.0

## Executive Summary

This report presents the results of an automated audit of S3 public access configurations for AWS account 000000000000. The audit evaluates account-level and bucket-level controls against CIS AWS Foundations Benchmark v5.0.0 and maps findings to SOC 2 Trust Services Criteria, NIST SP 800-53 Rev. 5, CIS Controls v8.1, and ISO/IEC 27001:2022.

**Findings summary:**

| Status | Count |
|--------|-------|
| PASS | 4 |
| FAIL | 1 |
| ERROR | 0 |
| **Total** | **5** |

## Collection Metadata

| Field | Value |
|-------|-------|
| Collected at | 2026-04-19T19:40:29.065954Z |
| Caller ARN | `arn:aws:iam::000000000000:user/Example` |
| Collector | s3-public-access v0.1.0 |
| Schema version | 0.1.0 |

## SOC 2 Trust Services Criteria Coverage

This audit provides evidence for the following SOC 2 criteria. Criterion language is from the 2017 Trust Services Criteria, revised 2022.

### CC6.1: Logical and Physical Access Controls

**Criterion language:**

> The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.

**Relevance to this audit:**

S3 bucket access controls (Block Public Access, bucket policies, and ACLs) are the logical access security mechanisms for object storage. Misconfiguration permitting public access represents a failure of logical access security.

### CC6.6: Protection Against Threats from External Sources

**Criterion language:**

> The entity implements logical access security measures to protect against threats from sources outside its system boundaries.

**Relevance to this audit:**

A publicly accessible S3 bucket is, by definition, accessible from outside the system boundary without authentication. This is the canonical CC6.6 failure mode.


## Control Results

### EXT-ACCT-BPA-01: Ensure account-level S3 Block Public Access is fully enabled

**Severity:** high
**Scope:** account

**Rationale:**

Account-level Block Public Access applies to all buckets regardless of individual configuration, providing defense in depth. This is a collector-defined extension beyond CIS Benchmark v5.0.0, which does not enumerate account-level BPA as a separate control.

**Framework Mappings:**

| Framework | References |
|-----------|------------|
| SOC 2 Trust Services Criteria (2017, rev. 2022) | CC6.1, CC6.6 |
| NIST SP 800-53 Rev. 5 | AC-3, SC-7 |
| CIS Controls v8.1 | 3.3, 14.6 |
| ISO/IEC 27001:2022 Annex A | A.5.10, A.8.3 |

**Findings:**

| Resource | Status | Detail |
|----------|--------|--------|
| `000000000000` | **FAIL** | Account-level Block Public Access has never been configured |

### CIS-AWS-2.1.4: Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'

**Severity:** high
**Scope:** bucket

**Rationale:**

Bucket-level Block Public Access settings prevent bucket policies and ACLs from granting public access. All four settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) should be enabled for defense in depth.

**Framework Mappings:**

| Framework | References |
|-----------|------------|
| SOC 2 Trust Services Criteria (2017, rev. 2022) | CC6.1, CC6.6 |
| NIST SP 800-53 Rev. 5 | AC-3, AC-4, SC-7 |
| CIS Controls v8.1 | 3.3, 14.6 |
| ISO/IEC 27001:2022 Annex A | A.5.10, A.8.3 |

**Findings:**

| Resource | Status | Detail |
|----------|--------|--------|
| `example-reports-bucket` | PASS | Bucket Block Public Access is properly configured with all settings enabled |
| `aws-cloudtrail-logs-000000000000-example` | PASS | Bucket Block Public Access is properly configured with all settings enabled |

### CIS-AWS-2.1.5: Ensure that S3 Buckets are not publicly accessible via bucket policy or ACL

**Severity:** critical
**Scope:** bucket

**Rationale:**

Even with Block Public Access enabled, bucket policies and ACLs may grant access to AllUsers or AuthenticatedUsers, or use Principal:* without restricting conditions. These grants expose objects to anonymous access.

**Framework Mappings:**

| Framework | References |
|-----------|------------|
| SOC 2 Trust Services Criteria (2017, rev. 2022) | CC6.1, CC6.6 |
| NIST SP 800-53 Rev. 5 | AC-3, AC-4, SC-7 |
| CIS Controls v8.1 | 3.3, 14.6 |
| ISO/IEC 27001:2022 Annex A | A.5.10, A.8.3 |

**Findings:**

| Resource | Status | Detail |
|----------|--------|--------|
| `example-reports-bucket` | PASS | No public access detected in bucket policy or ACL |
| `aws-cloudtrail-logs-000000000000-example` | PASS | No public access detected in bucket policy or ACL |


## Scope Declarations

The following items are explicitly out of scope for this audit:

- Object-level ACLs (per-object public access)
- S3 Access Points and their public access settings
- Cross-account bucket policies with specific external account grants
- Buckets where the collector receives AccessDenied on policy or ACL reads
- VPC endpoint policies and bucket access via private networking

## Required IAM Permissions

This collector operates with read-only permissions. The complete IAM policy document is included in this evidence pack as `collector_iam_policy.json`. The actions used are:

- `s3:GetAccountPublicAccessBlock` 
- `s3:GetBucketAcl` 
- `s3:GetBucketLocation` 
- `s3:GetBucketPolicy` 
- `s3:GetBucketPolicyStatus` 
- `s3:GetBucketPublicAccessBlock` 
- `s3:ListAllMyBuckets` 

---

*This report was generated by an automated evidence collector. Raw API responses are preserved in `raw/` directory for independent verification. Finding-level evidence references in `findings.json` point to specific files under `raw/`.*
