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


def write_organized_findings(findings_data: dict[str, Any], mappings: dict, staging_dir: Path) -> None:
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
    write_organized_findings(findings_data, mappings, staging_dir)
    logging.info("Wrote findings.json (organized by control)")
    
    # Clean up staging directory
    shutil.rmtree(staging_dir)


if __name__ == "__main__":
    main()