# Standard Operating Procedure: S3 Public Access Auditor

> **Purpose:** This document outlines the standard operating procedure for executing the S3 Public Access Auditor. This tool collects read-only configuration data from AWS S3, evaluates it against CIS Foundations Benchmark v5.0.0, and generates a cryptographically verifiable evidence pack mapped to SOC 2, NIST, CIS, and ISO frameworks.

---

## 📋 Prerequisites

Before running the tool, ensure your environment meets the following requirements:

* **Python:** Version 3.10 or higher installed.
* **AWS Credentials:** AWS CLI configured with active, **read-only** credentials.
* **Repository:** The project repository must be cloned to your local machine.

---

## 🚀 Phase 1: Environment Setup

Initialize your environment and install the required dependencies to ensure the tool runs smoothly.

1. **Navigate to the tool directory:**
   ```bash
   cd s3_public_access
   ```

2. **Install the required Python packages:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔍 Phase 2: Evidence Collection

The collection phase communicates with the AWS API to gather raw configuration states. It operates strictly as an observer and makes **no modifications** to the environment.

1. **Execute the collector**, specifying your desired output directory for the raw evidence:
   ```bash
   python collector.py --output-dir /tmp/evidence
   ```

2. **Verify the execution:** Watch the terminal output and ensure you see `INFO` logs indicating successful enumeration and check completion.

---

## 📦 Phase 3: Evidence Packaging

The packaging phase processes the raw JSON, applies framework mappings, renders the formal PDF report, and generates the final `.zip` artifact.

1. **Execute the packager**, pointing it to the collection directory and specifying a final destination for the evidence pack:
   ```bash
   python pack.py --input-dir /tmp/evidence --output-dir /tmp/packs
   ```

2. **Confirm generation:** The tool will automatically generate a ZIP file containing the report, raw evidence, and manifest, along with a `.sha256` sidecar file.

---

## 🔐 Phase 4: Integrity Verification

To prove the chain of custody and ensure the evidence has not been tampered with, you must verify the cryptographic hash of the generated pack.

1. **Navigate to the final output directory:**
   ```bash
   cd /tmp/packs
   ```

2. **Run the standard Linux checksum verification:**
   ```bash
   sha256sum -c *.sha256
   ```

3. **Verify the output:** Ensure the terminal outputs `OK` next to the archive filename. 

> **Success:** Once the `OK` status is confirmed, the cryptographic evidence pack is finalized and ready for formal auditor delivery.
