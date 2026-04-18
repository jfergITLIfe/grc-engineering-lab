"""
S3 Public Access Auditor

This CLI tool audits S3 buckets for public access configurations and generates
evidence pack findings. It reads framework mappings from mappings.yaml to
determine compliance checks and produces structured output for security
auditing purposes.
"""

import argparse
import logging
import sys
from pathlib import Path

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
            return mappings or {}
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
        description="Audit S3 buckets for public access configurations"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to store audit results"
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS profile name for authentication"
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point for the S3 public access auditor."""
    setup_logging()
    args = parse_args()
    
    # Load mappings from script directory
    mappings_path = Path(__file__).parent / "mappings.yaml"
    mappings = load_mappings(mappings_path)
    
    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    # Log status
    technical_checks = mappings.get("technical_checks", {})
    if not technical_checks:
        logging.error("mappings.yaml has no technical_checks defined")
        sys.exit(1)
    logging.info(f"Loaded {len(technical_checks)} technical checks from mappings.yaml")
    logging.info(f"Output directory ready: {args.output_dir}")


if __name__ == "__main__":
    main()