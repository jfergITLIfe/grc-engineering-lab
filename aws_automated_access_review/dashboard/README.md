# GRC Access Review Dashboard

Streamlit-based visualization layer for the AWS Automated Access Review tool. Pulls live report data from S3 and presents interactive security posture visualizations.

## Features

- **Live S3 Integration**: Pulls CSV reports directly from your access review S3 bucket
- **Severity Overview**: At-a-glance metric cards for Critical, High, Medium, Low, and Informational findings
- **Interactive Charts**: Donut chart for severity distribution, bar charts for category and compliance breakdown
- **Compliance Mapping**: Visual breakdown of findings by compliance framework (CIS, NIST, SOC 2, etc.)
- **Detailed Findings View**: Expandable finding cards with severity badges, recommendations, and resource details
- **Report Selector**: Switch between historical reports from the sidebar
- **Filtering**: Filter findings by severity level
- **CSV Export**: Download filtered findings as CSV

## Setup

```bash
cd dashboard
pip install -r requirements.txt
```

## Usage

```bash
streamlit run app.py
```

The dashboard will open in your browser at `http://localhost:8501`.

### Configuration

In the sidebar:
- **S3 Bucket Name**: Your access review report bucket (default: pre-configured)
- **AWS Profile**: Optional AWS CLI profile name (leave blank for default credentials)

## Requirements

- Python 3.11+
- AWS credentials configured with read access to the report S3 bucket
- At least one access review report generated in S3

## Architecture

```
dashboard/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

The dashboard reads from the same S3 bucket that the Lambda function writes to, creating a complete pipeline:

```
Lambda (findings collection) → S3 (CSV storage) → Dashboard (visualization)
```
