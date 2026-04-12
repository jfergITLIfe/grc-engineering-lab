<div align="center">

# 🔒 GRC Engineering Lab

**Automated Compliance. Real Findings. Production-Ready.**

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20Bedrock%20%7C%20S3-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Claude](https://img.shields.io/badge/Claude-Sonnet%204.6-CC785C?style=for-the-badge&logo=anthropic&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![IaC](https://img.shields.io/badge/IaC-CloudFormation-232F3E?style=for-the-badge&logo=amazonwebservices&logoColor=white)

---

*Hands-on GRC engineering projects demonstrating automated compliance, security assessment, and risk management in AWS.*

</div>

---

## 📋 AWS Automated Access Review

An automated IAM security access review system that collects findings across multiple AWS security services, generates AI-powered executive narratives, and delivers audit-ready compliance reports directly to stakeholders.

---

## 🛠️ What I Built

| Extension | Description |
|-----------|-------------|
| **AI Model Upgrade** | Replaced legacy Claude v2 with **Claude Sonnet 4.6** via Bedrock Messages API. Full refactor of request/response handling for the new API format. |
| **GRC Dashboard** | **Streamlit** visualization layer pulling live data from S3. Interactive charts for severity distribution, category breakdown, compliance coverage, and detailed finding cards. |
| **Live AWS Environment** | Deployed and configured a full security stack (Security Hub, IAM Access Analyzer, SES, Bedrock) generating **real findings against a real AWS account**. |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      AWS Account (us-east-1)                     │
│                                                                  │
│   ┌─────────────┐   ┌──────────────────┐   ┌──────────────┐     │
│   │  Security    │   │   IAM Access     │   │  CloudTrail  │     │
│   │    Hub       │   │   Analyzer       │   │              │     │
│   └──────┬──────┘   └────────┬─────────┘   └──────┬───────┘     │
│          │                   │                     │             │
│          └───────────────────┼─────────────────────┘             │
│                              │                                   │
│                    ┌─────────▼──────────┐                        │
│                    │   Lambda Function  │                        │
│                    │    (Collector)     │                        │
│                    └─────────┬──────────┘                        │
│                              │                                   │
│              ┌───────────────┼───────────────┐                   │
│              │               │               │                   │
│       ┌──────▼─────┐  ┌─────▼──────┐  ┌─────▼──────┐           │
│       │     S3     │  │  Bedrock   │  │    SES     │           │
│       │  (Reports) │  │(Sonnet 4.6)│  │  (Email)   │           │
│       └──────┬─────┘  └────────────┘  └────────────┘           │
│              │                                                   │
└──────────────┼───────────────────────────────────────────────────┘
               │
        ┌──────▼──────┐
        │  Streamlit  │
        │  Dashboard  │
        └─────────────┘
```

---

## 📊 Dashboard Preview

The Streamlit dashboard provides real-time visibility into access review findings:

- **Severity Metrics** — at-a-glance cards for Critical, High, Medium, Low, and Informational counts
- **Findings by Severity** — interactive donut chart with total count
- **Findings by Category** — horizontal bar chart (IAM, CloudTrail, Security Hub, SCP, Access Analyzer)
- **Compliance Coverage** — framework mapping visualization (CIS, NIST, SOC 2, PCI DSS)
- **Detailed Finding Cards** — severity-coded cards with descriptions, recommendations, and resource IDs
- **Report Selector** — switch between historical reports stored in S3

---

## 🔗 Compliance Framework Coverage

Findings are automatically mapped to controls across:

| Framework | Examples |
|-----------|----------|
| **CIS AWS Foundations Benchmark** | 1.2 (MFA), 1.5-1.11 (Password Policy), 3.1 (CloudTrail) |
| **AWS Well-Architected** | Security Pillar best practices |
| **NIST 800-53 Rev 5** | AC (Access Control), AU (Audit), IA (Identification) |
| **SOC 2 TSC** | CC6.1 (Logical Access), CC7.2 (Anomaly Detection) |
| **PCI DSS v4.0** | Req 8.4 (MFA), Req 10.2 (Audit Logs) |

---

## ⚡ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Compute** | AWS Lambda (Python 3.11) |
| **AI/ML** | Amazon Bedrock (Claude Sonnet 4.6) |
| **Security** | Security Hub, IAM Access Analyzer, CloudTrail |
| **Infrastructure** | CloudFormation |
| **Storage** | Amazon S3 |
| **Notifications** | Amazon SES |
| **Dashboard** | Streamlit, Plotly, Pandas, Boto3 |

---

## 🚀 Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.11+
- AWS services enabled: Security Hub, IAM Access Analyzer, SES, Bedrock (Claude model access)

### 1. Deploy the Access Review Tool

```bash
cd aws_automated_access_review
./scripts/check_aws_creds.sh
./scripts/deploy.sh --email your.email@example.com
```

### 2. Run an Access Review

```bash
aws lambda invoke \
  --function-name aws-access-review-access-review \
  --payload '{}' /tmp/response.json
```

### 3. Launch the Dashboard

```bash
cd aws_automated_access_review/dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

---

## 📁 Project Structure

```
grc-engineering-lab/
├── aws_automated_access_review/
│   ├── src/lambda/
│   │   ├── index.py                        # Main Lambda handler
│   │   ├── bedrock_integration.py          # AI narrative engine (Sonnet 4.6)
│   │   └── modules/
│   │       ├── iam_findings.py             # IAM security checks
│   │       ├── securityhub_findings.py     # Security Hub integration
│   │       ├── access_analyzer_findings.py # External access detection
│   │       ├── cloudtrail_findings.py      # Audit logging checks
│   │       ├── scp_findings.py             # Org policy checks
│   │       ├── reporting.py                # CSV report generation
│   │       └── email_utils.py              # SES email delivery
│   ├── dashboard/
│   │   ├── app.py                          # Streamlit dashboard
│   │   └── requirements.txt
│   ├── templates/
│   │   └── access-review.yaml              # CloudFormation template
│   ├── scripts/
│   │   ├── deploy.sh                       # One-command deployment
│   │   ├── run_report.sh                   # Manual report trigger
│   │   └── check_aws_creds.sh              # Pre-flight checks
│   └── tests/
├── .gitignore
└── README.md
```

---

## 📝 Sample AI Output

The Bedrock-powered narrative generates audit-ready executive reports including:

> **Executive Summary** — Overall security posture assessment with severity breakdown
>
> **Critical Findings Analysis** — Risk description and business impact for each finding
>
> **Prioritized Recommendations** — Immediate (24-72hr), Short-term (1-2 weeks), Scheduled (30 days)
>
> **Compliance Implications** — Mapping to CIS, NIST CSF, SOC 2, and PCI DSS controls

---

## 🙏 Connect with me

Extensions and customizations by **Jacob Ferguson** — [LinkedIn](https://linkedin.com/in/itlife) | [GitHub](https://github.com/jfergITLife)

---

<div align="center">

*This lab is part of an ongoing GRC engineering portfolio. Built with real tools, real findings, real frameworks.*

</div>
