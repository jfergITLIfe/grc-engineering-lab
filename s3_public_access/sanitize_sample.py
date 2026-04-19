"""Sanitize an evidence pack for use as a public sample.

Takes real collector output and pack output, replaces real account IDs,
ARNs, and bucket names with example placeholders, then regenerates
findings, report, manifest, zip, and sidecar using the existing pack.py
functions. Produces a sanitized pack suitable for committing to a public
repository.

Usage:
    python sanitize_sample.py \\
        --collector-input /tmp/evidence-test \\
        --output-dir /path/to/repo/s3_public_access/sample_evidence_pack
"""
import argparse
import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

# Import pack.py functions to reuse the pipeline
sys.path.insert(0, str(Path(__file__).parent))
from pack import (
    setup_logging,
    load_mappings,
    write_organized_findings,
    write_iam_policy,
    render_report,
    render_pdf,
    copy_input_artifacts,
    write_manifest,
    create_zip,
    write_sha256_sidecar,
)

# Real values will be replaced with these sanitized values
REAL_ACCOUNT_ID = "632783683648"
SANITIZED_ACCOUNT_ID = "000000000000"

REAL_CALLER_ARN = "arn:aws:iam::632783683648:user/Jacob"
SANITIZED_CALLER_ARN = "arn:aws:iam::000000000000:user/Example"

BUCKET_NAME_MAP = {
    "aws-access-review-reportbucket-fjmz5dmn8dgi": "example-reports-bucket",
    "aws-cloudtrail-logs-632783683648-a8f52672": "aws-cloudtrail-logs-000000000000-example"
}


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Sanitize evidence pack for public sample use"
    )
    parser.add_argument(
        "--collector-input",
        type=Path,
        required=True,
        help="Directory with real collector output"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Where to write sanitized pack"
    )
    return parser.parse_args()


def sanitize_string(text: str, real_user_id: str) -> str:
    """Replace real values with sanitized placeholders.
    
    Order matters: replace longer, more specific strings (bucket names,
    full ARN) BEFORE the account ID alone, otherwise the account ID
    replacement breaks later string matches.
    """
    sanitized = text
    
    # 1. Replace bucket names first (contain account ID)
    for real_bucket, sanitized_bucket in BUCKET_NAME_MAP.items():
        sanitized = sanitized.replace(real_bucket, sanitized_bucket)
    
    # 2. Replace full caller ARN (contains account ID and username)
    sanitized = sanitized.replace(REAL_CALLER_ARN, SANITIZED_CALLER_ARN)
    
    # 3. Replace any remaining occurrences of account ID
    sanitized = sanitized.replace(REAL_ACCOUNT_ID, SANITIZED_ACCOUNT_ID)
    
    # 4. Replace user_id (independent of other replacements)
    sanitized = sanitized.replace(real_user_id, "AIDAEXAMPLEEXAMPLEEX")
    
    return sanitized


def sanitize_json_file(src: Path, dst: Path, real_user_id: str) -> None:
    """Read, sanitize, and write JSON file."""
    with open(src, 'r', encoding='utf-8') as f:
        content = f.read()
    
    sanitized_content = sanitize_string(content, real_user_id)
    
    # Verify it's still valid JSON
    try:
        json.loads(sanitized_content)
    except json.JSONDecodeError as e:
        logging.error(f"Sanitization broke JSON in {src}: {e}")
        sys.exit(1)
    
    with open(dst, 'w', encoding='utf-8') as f:
        json.dump(json.loads(sanitized_content), f, indent=2)


def sanitize_collector_output(collector_input: Path, sanitized_input: Path) -> str:
    """Sanitize entire collector output directory."""
    # Read real collection metadata to extract user_id
    with open(collector_input / "collection_metadata.json", 'r', encoding='utf-8') as f:
        collection_metadata = json.load(f)
    
    real_user_id = collection_metadata.get('user_id', '')
    logging.info(f"Sanitizing collector output for user_id: {real_user_id}")
    
    # Create sanitized input directory structure
    sanitized_input.mkdir(parents=True, exist_ok=True)
    
    # Sanitize all JSON files in root
    for json_file in collector_input.glob("*.json"):
        if json_file.is_file():
            dst_file = sanitized_input / json_file.name
            sanitize_json_file(json_file, dst_file, real_user_id)
    
    # Handle raw/ directory tree manually
    raw_src = collector_input / "raw"
    if raw_src.exists():
        raw_dst = sanitized_input / "raw"
        raw_dst.mkdir(exist_ok=True)
        
        # Create buckets subdirectory first
        buckets_dst = raw_dst / "buckets"
        buckets_dst.mkdir(exist_ok=True)
        
        # Sanitize raw/account_public_access_block.json
        account_bpa_src = raw_src / "account_public_access_block.json"
        if account_bpa_src.exists():
            sanitize_json_file(account_bpa_src, raw_dst / "account_public_access_block.json", real_user_id)
        
        # Sanitize raw/buckets/inventory.json (now safe because buckets_dst exists)
        inventory_src = raw_src / "buckets" / "inventory.json"
        if inventory_src.exists():
            sanitize_json_file(inventory_src, buckets_dst / "inventory.json", real_user_id)
        
        # Sanitize bucket subdirectories
        buckets_src = raw_src / "buckets"
        if buckets_src.exists():
            buckets_dst = raw_dst / "buckets"
            buckets_dst.mkdir(exist_ok=True)
            
            for bucket_dir in buckets_src.iterdir():
                if bucket_dir.is_dir():
                    bucket_name = bucket_dir.name
                    sanitized_bucket_name = BUCKET_NAME_MAP.get(
                        bucket_name, f"sanitized-{bucket_name}"
                    )
                    sanitized_bucket_dir = buckets_dst / sanitized_bucket_name
                    sanitized_bucket_dir.mkdir(exist_ok=True)
                    
                    # Sanitize files in each bucket directory
                    for file_path in bucket_dir.rglob("*"):
                        if file_path.is_file():
                            dst_file = sanitized_bucket_dir / file_path.name
                            sanitize_json_file(file_path, dst_file, real_user_id)
    
    return real_user_id


def main() -> None:
    """Main entry point for sanitization utility."""
    setup_logging()
    args = parse_args()
    
    # Create temp dir for sanitized collector output
    temp_collector_dir = Path(tempfile.mkdtemp(prefix="sanitize-collector-"))
    temp_staging_dir = None
    
    try:
        # Sanitize collector output
        real_user_id = sanitize_collector_output(args.collector_input, temp_collector_dir)
        
        # Create output dir if needed
        args.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Clear output dir if it exists and is non-empty
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            logging.warning(f"Output directory {args.output_dir} exists and is not empty")
            shutil.rmtree(args.output_dir)
            args.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create temp dir for sanitized staging
        temp_staging_dir = Path(tempfile.mkdtemp(prefix="sanitize-staging-"))
        
        # Load mappings from pack.py directory
        mappings_path = Path(__file__).parent / "mappings.yaml"
        mappings = load_mappings(mappings_path)
        
        # Load sanitized findings
        with open(temp_collector_dir / "findings_raw.json", 'r', encoding='utf-8') as f:
            findings_data = json.load(f)
        
        # Run full pack.py pipeline on sanitized data
        findings_organized = write_organized_findings(findings_data, mappings, temp_staging_dir)
        write_iam_policy(mappings, temp_staging_dir)
        render_report(findings_data, findings_organized, mappings, temp_collector_dir, temp_staging_dir)
        render_pdf(temp_staging_dir)
        copy_input_artifacts(temp_collector_dir, temp_staging_dir)
        write_manifest(findings_data, temp_staging_dir)
        
        # Create zip and sidecar in output directory
        zip_path = create_zip(findings_data, temp_staging_dir, args.output_dir)
        sidecar_path = write_sha256_sidecar(zip_path)
        
        # Copy individual artifacts to output_dir for easy viewing
        for artifact_name in ["findings.json", "report.md", "report.pdf", "manifest.json", "collector_iam_policy.json", "collection_metadata.json"]:
            src_file = temp_staging_dir / artifact_name
            if src_file.exists():
                dst_file = args.output_dir / artifact_name
                shutil.copy2(src_file, dst_file)
        
        # Copy raw directory
        raw_dst = args.output_dir / "raw"
        if temp_staging_dir.exists():
            shutil.copytree(temp_staging_dir / "raw", raw_dst)
        
        logging.info(f"Sanitized sample evidence pack written to: {args.output_dir}")
        
    finally:
        # Clean up both temp dirs
        shutil.rmtree(temp_collector_dir, ignore_errors=True)
        if temp_staging_dir is not None:
            shutil.rmtree(temp_staging_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
