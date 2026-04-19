"""
S3 Public Access Evidence Pack Assembler

Reads collector output from --input-dir and produces a zipped evidence pack
containing findings.json (SOC 2-organized), report.md, report.pdf,
collector_iam_policy.json, manifest.json (with SHA-256 hashes), and raw/
directory. The zip is written to --output-dir along with a .sha256 sidecar.
"""

import argparse
import json
import logging
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
import hashlib
import markdown
import zipfile
from weasyprint import HTML, CSS

import yaml


def setup_logging() -> None:
    """Configure logging with clean format at INFO level."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_mappings(path: Path) -> dict:
    """
    Load YAML mappings file and return parsed dictionary.
    
    Args:
        path: Path to the YAML mappings file
        
    Returns:
        Parsed YAML content as dictionary
        
    Exits:
        If file is missing or malformed
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            mappings = yaml.safe_load(f)
            if not mappings:
                return {}
            
            # Validate required top-level keys
            required_keys = {
                'schema_version',
                'collector', 
                'collector_version',
                'technical_checks',
                'soc2_controls',
                'required_iam_permissions'
            }
            missing_keys = required_keys - set(mappings.keys())
            if missing_keys:
                logging.error(f"mappings.yaml missing required keys: {', '.join(sorted(missing_keys))}")
                sys.exit(1)
            
            return mappings
    except FileNotFoundError:
        logging.error(f"Mappings file not found: {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Invalid YAML in mappings file {path}: {e}")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Assemble S3 public access evidence pack from collector output"
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing collector output"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write the evidence pack zip"
    )
    return parser.parse_args()


def validate_input_dir(input_dir: Path) -> dict[str, Any]:
    """
    Validate input directory contains required collector files.
    
    Args:
        input_dir: Directory containing collector output
        
    Returns:
        Parsed findings_raw.json data
        
    Exits:
        If required files are missing or invalid
    """
    findings_file = input_dir / "findings_raw.json"
    metadata_file = input_dir / "collection_metadata.json"
    raw_dir = input_dir / "raw"
    
    if not findings_file.exists():
        logging.error(f"findings_raw.json not found in {input_dir}")
        sys.exit(1)
    
    if not metadata_file.exists():
        logging.error(f"collection_metadata.json not found in {input_dir}")
        sys.exit(1)
    
    if not raw_dir.exists():
        logging.error(f"raw directory not found in {input_dir}")
        sys.exit(1)
    
    try:
        with open(findings_file, 'r', encoding='utf-8') as f:
            findings_data = json.load(f)
            return findings_data
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in findings_raw.json: {e}")
        sys.exit(1)


def write_organized_findings(findings_data: dict[str, Any], mappings: dict, staging_dir: Path) -> dict[str, Any]:
    """
    Write findings organized by control to staging directory.
    
    Args:
        findings_data: Parsed findings_raw.json dict
        mappings: Parsed mappings.yaml dict
        staging_dir: Directory to write findings.json
    """
    # Extract flat findings list
    flat_findings = findings_data['findings']
    
    # Group findings by control_id
    control_groups = {}
    for finding in flat_findings:
        control_id = finding['control_id']
        if control_id not in control_groups:
            control_groups[control_id] = []
        control_groups[control_id].append(finding)
    
    # Build organized output
    organized_output = {
        'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'collector': findings_data['collector'],
        'collector_version': findings_data['collector_version'],
        'schema_version': findings_data['schema_version'],
        'aws_account_id': findings_data['aws_account_id'],
        'summary': findings_data['summary'],
        'controls': {}
    }
    
    # Process controls in mappings order
    for control_id in mappings['technical_checks'].keys():
        if control_id not in control_groups:
            continue  # Skip controls with no findings
            
        control_metadata = mappings['technical_checks'].get(control_id, {})
        
        organized_output['controls'][control_id] = {
            'control_metadata': {
                'title': control_metadata.get('title', ''),
                'rationale': control_metadata.get('rationale', '').strip(),
                'severity': control_metadata.get('measurement', {}).get('severity', ''),
                'scope': control_metadata.get('measurement', {}).get('scope', ''),
                'maps_to': control_metadata.get('maps_to', {
                    'soc2': [],
                    'cis_controls_v8': [],
                    'iso_27001_2022': [],
                    'nist_800_53_r5': []
                })
            },
            'findings': control_groups[control_id]
        }
    
    # Write organized findings
    findings_file = staging_dir / "findings.json"
    with open(findings_file, 'w', encoding='utf-8') as f:
        json.dump(organized_output, f, indent=2)
    
    return organized_output


def write_iam_policy(mappings: dict, staging_dir: Path) -> None:
    """
    Write IAM policy document for collector permissions.
    
    Args:
        mappings: Parsed mappings.yaml dict
        staging_dir: Directory to write the IAM policy file
    """
    actions = sorted(mappings['required_iam_permissions'])
    
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3PublicAccessAuditorReadOnly",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            }
        ]
    }
    
    policy_file = staging_dir / "collector_iam_policy.json"
    with open(policy_file, 'w', encoding='utf-8') as f:
        json.dump(policy, f, indent=2)


def render_report(findings_data: dict[str, Any], findings_organized: dict[str, Any], mappings: dict, input_dir: Path, staging_dir: Path) -> None:
    """
    Render markdown report from Jinja2 template.
    
    Args:
        findings_data: Raw findings dict (from findings_raw.json, already loaded)
        findings_organized: The organized findings dict from write_organized_findings
        mappings: Parsed mappings.yaml dict
        input_dir: Collector's output directory (to read collection_metadata.json)
        staging_dir: Directory to write report.md
    """
    # Read collection metadata
    with open(input_dir / "collection_metadata.json", 'r', encoding='utf-8') as f:
        collection_metadata = json.load(f)
    
    # Build template context
    context = {
        'account_id': findings_data['aws_account_id'],
        'generated_at': findings_organized['generated_at'],
        'collector_name': findings_data['collector'],
        'collector_version': findings_data['collector_version'],
        'schema_version': findings_data['schema_version'],
        'collected_at': collection_metadata['collected_at'],
        'caller_arn': collection_metadata['caller_arn'],
        'summary': findings_data['summary'],
        'soc2_controls': mappings['soc2_controls'],
        'controls': findings_organized['controls'],
        'out_of_scope': mappings['out_of_scope_v0_1'],
        'required_permissions': sorted(mappings['required_iam_permissions']),
        'framework_labels': mappings['framework_labels']
    }
    
    # Set up Jinja2 environment
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(disabled_extensions=('j2',), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True
    )
    template = env.get_template("report.md.j2")
    
    # Render and write
    rendered = template.render(**context)
    report_file = staging_dir / "report.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(rendered)


def render_pdf(staging_dir: Path) -> None:
    """
    Render PDF report from markdown using WeasyPrint.
    
    Args:
        staging_dir: Directory containing report.md (and where report.pdf will be written)
    """
    # Read markdown file
    with open(staging_dir / "report.md", 'r', encoding='utf-8') as f:
        md_text = f.read()
    
    # Convert markdown to HTML
    html_body = markdown.markdown(md_text, extensions=['tables'])
    
    # Wrap in HTML document
    html_doc = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>S3 Public Access Audit Report</title>
</head>
<body>
{html_body}
</body>
</html>"""
    
    # Load CSS and render to PDF
    css_path = Path(__file__).parent / "templates" / "report.css"
    HTML(string=html_doc).write_pdf(
        staging_dir / "report.pdf",
        stylesheets=[CSS(filename=str(css_path))]
    )


def copy_input_artifacts(input_dir: Path, staging_dir: Path) -> None:
    """
    Copy input artifacts to staging directory.
    
    Args:
        input_dir: Collector's output directory
        staging_dir: Evidence pack staging directory
    """
    # Copy collection metadata
    shutil.copy2(input_dir / "collection_metadata.json", staging_dir / "collection_metadata.json")
    
    # Copy raw directory tree
    shutil.copytree(input_dir / "raw", staging_dir / "raw", dirs_exist_ok=False)


def _sha256_of_file(path: Path) -> str:
    """
    Compute SHA-256 hex digest of a file using chunked reads.
    
    Args:
        path: File path to hash
        
    Returns:
        SHA-256 hex digest
    """
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_manifest(findings_data: dict[str, Any], staging_dir: Path) -> None:
    """
    Write manifest with SHA-256 hashes for all files.
    
    Args:
        findings_data: Parsed findings_raw.json dict
        staging_dir: Evidence pack staging directory containing all files to be manifested
    """
    files = []
    
    for file_path in staging_dir.rglob("*"):
        if not file_path.is_file():
            continue
        
        # Skip manifest.json itself if it exists
        if file_path.name == "manifest.json":
            continue
        
        relative_path = file_path.relative_to(staging_dir).as_posix()
        file_size = file_path.stat().st_size
        sha256_hash = _sha256_of_file(file_path)
        
        files.append({
            "path": relative_path,
            "size_bytes": file_size,
            "sha256": sha256_hash
        })
    
    # Sort files alphabetically by path
    files.sort(key=lambda x: x["path"])
    
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "collector": findings_data["collector"],
        "collector_version": findings_data["collector_version"],
        "aws_account_id": findings_data["aws_account_id"],
        "file_count": len(files),
        "files": files
    }
    
    manifest_file = staging_dir / "manifest.json"
    with open(manifest_file, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)


def create_zip(findings_data: dict[str, Any], staging_dir: Path, output_dir: Path) -> Path:
    """
    Create evidence pack zip file.
    
    Args:
        findings_data: Parsed findings_raw.json dict
        staging_dir: Evidence pack staging directory containing all files to include
        output_dir: Directory where the zip file will be written
        
    Returns:
        Path to the created zip file
    """
    # Build zip filename
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H-%M-%SZ")
    filename = f"evidence-s3-public-access-{findings_data['aws_account_id']}-{timestamp}.zip"
    zip_path = output_dir / filename
    
    # Create zip with compression
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in staging_dir.rglob("*"):
            if not file_path.is_file():
                continue
            
            arcname = file_path.relative_to(staging_dir).as_posix()
            zf.write(file_path, arcname=arcname)
    
    return zip_path


def write_sha256_sidecar(zip_path: Path) -> Path:
    """
    Write SHA-256 sidecar file for zip.
    
    Args:
        zip_path: Path to the zip file to hash
        
    Returns:
        Path to the created sidecar file
    """
    sha256_hash = _sha256_of_file(zip_path)
    sidecar_path = zip_path.with_suffix(f"{zip_path.suffix}.sha256")
    
    with open(sidecar_path, 'w', encoding='utf-8') as f:
        f.write(f"{sha256_hash}  {zip_path.name}\n")
    
    return sidecar_path


def main() -> None:
    """Main entry point for the evidence pack assembler."""
    setup_logging()
    args = parse_args()
    
    # Load mappings from script directory
    mappings_path = Path(__file__).parent / "mappings.yaml"
    mappings = load_mappings(mappings_path)
    
    # Validate input directory and load findings
    findings_data = validate_input_dir(args.input_dir)
    logging.info(f"Loaded findings_raw.json ({findings_data['summary']['total']} findings)")
    
    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create staging directory
    temp_path = tempfile.mkdtemp(prefix="s3-evidence-pack-")
    staging_dir = Path(temp_path)
    logging.info(f"Created staging directory: {staging_dir}")
    
    # Write organized findings
    findings_organized = write_organized_findings(findings_data, mappings, staging_dir)
    logging.info("Wrote findings.json (organized by control)")
    
    # Write IAM policy
    write_iam_policy(mappings, staging_dir)
    logging.info("Wrote collector_iam_policy.json")
    
    # Render report.md
    render_report(findings_data, findings_organized, mappings, args.input_dir, staging_dir)
    logging.info("Wrote report.md")
    
    # Render report.pdf
    render_pdf(staging_dir)
    logging.info("Wrote report.pdf")
    
    # Copy input artifacts
    copy_input_artifacts(args.input_dir, staging_dir)
    logging.info("Copied raw evidence and collection metadata to staging")
    
    # Write manifest with SHA-256 hashes
    write_manifest(findings_data, staging_dir)
    logging.info("Wrote manifest.json")
    
    # Create zip and sidecar
    zip_path = create_zip(findings_data, staging_dir, args.output_dir)
    logging.info(f"Created zip: {zip_path.name}")

    sidecar_path = write_sha256_sidecar(zip_path)
    logging.info(f"Created SHA-256 sidecar: {sidecar_path.name}")
    
    logging.info(f"Evidence pack complete: {zip_path}")
    
    # Clean up staging directory
    # shutil.rmtree(staging_dir)


if __name__ == "__main__":
    main()