<div align="center">

# 🔒 GRC Engineering Lab

**Automated Compliance. Real Findings. Production-Ready.**

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Security%20Stack-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Claude](https://img.shields.io/badge/AI-Bedrock%20%7C%20Sonnet%204.6-CC785C?style=for-the-badge&logo=anthropic&logoColor=white)
![IaC](https://img.shields.io/badge/IaC-CloudFormation-232F3E?style=for-the-badge&logo=amazonwebservices&logoColor=white)

---

A portfolio of hands-on GRC engineering projects built in real AWS environments with real findings, real frameworks, and production-grade automation. Each project demonstrates a different aspect of modern GRC engineering: compliance automation, security assessment, risk reporting, and AI-powered analysis.

</div>

---

## 📂 Projects

### 1. [AWS Automated Access Review](./aws_automated_access_review)

**Status:** ✅ Complete

An end-to-end automated IAM security access review system. Collects findings across multiple AWS security services, generates AI-powered executive narratives via Amazon Bedrock, and delivers audit-ready compliance reports to stakeholders.

**What I Built:**

| Extension | Description |
|-----------|-------------|
| **AI Model Upgrade** | Replaced legacy Claude v2 with **Claude Sonnet 4.6** via Bedrock Messages API. Full refactor of request/response handling. |
| **GRC Dashboard** | **Streamlit** visualization layer pulling live data from S3. Severity distribution, category breakdown, compliance coverage, and detailed finding cards. |
| **Live AWS Environment** | Deployed a full security stack (Security Hub, IAM Access Analyzer, SES, Bedrock) generating **real findings against a real account**. |

**Architecture:**

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

**Tech Stack:** Lambda, Bedrock (Sonnet 4.6), Security Hub, IAM Access Analyzer, CloudTrail, CloudFormation, S3, SES, Streamlit, Plotly

**Compliance Mapping:** CIS AWS Foundations, NIST 800-53 Rev 5, SOC 2 TSC, PCI DSS v4.0, AWS Well-Architected

---

### 2. Coming Soon

More projects in development. Future labs will cover areas like:

- Infrastructure hardening and configuration compliance
- Continuous monitoring and alerting pipelines
- Policy-as-code and preventive controls
- Risk quantification and reporting automation

---

## 🔗 Compliance Frameworks Covered

| Framework | Projects |
|-----------|----------|
| **CIS AWS Foundations Benchmark** | Access Review |
| **NIST 800-53 Rev 5** | Access Review |
| **SOC 2 TSC** | Access Review |
| **PCI DSS v4.0** | Access Review |
| **AWS Well-Architected** | Access Review |

---

## ⚡ Core Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Compute** | AWS Lambda (Python 3.11) |
| **AI/ML** | Amazon Bedrock (Claude Sonnet 4.6) |
| **Security Services** | Security Hub, IAM Access Analyzer, CloudTrail |
| **Infrastructure** | CloudFormation |
| **Storage** | Amazon S3 |
| **Visualization** | Streamlit, Plotly, Pandas |
| **Notifications** | Amazon SES |

---

## 📁 Repo Structure

```
grc-engineering-lab/
├── aws_automated_access_review/    # Project 1: Automated Access Review
│   ├── src/lambda/                 #   Lambda function + modules
│   ├── dashboard/                  #   Streamlit dashboard
│   ├── templates/                  #   CloudFormation IaC
│   ├── scripts/                    #   Deploy + run scripts
│   └── tests/                      #   Unit + integration tests
├── .gitignore
└── README.md
```

---

## 👤 About

Built by **Jacob Ferguson** — Navy veteran, cybersecurity analyst, Rice MBA candidate, and GRC engineer.

- [LinkedIn](https://linkedin.com/in/itlife)
- [GitHub](https://github.com/jfergITLife)


---

<div align="center">

*Built with real tools. Real findings. Real frameworks.*

</div>
