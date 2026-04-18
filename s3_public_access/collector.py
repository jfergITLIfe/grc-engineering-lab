"""
S3 Public Access Auditor

This CLI tool audits S3 buckets for public access configurations and generates
evidence pack findings. It reads framework mappings from mappings.yaml to
determine compliance checks and produces structured output for security
auditing purposes.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
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
    
    # AWS authentication
    session = create_session(args.profile)
    identity = get_caller_identity(session)
    logging.info(f"Authenticated to AWS account {identity['account_id']} as {identity['caller_arn']}")
    
    # Write collection metadata
    write_collection_metadata(args.output_dir, identity, mappings)
    logging.info("Wrote collection_metadata.json")


def create_session(profile: str | None) -> boto3.Session:
    """
    Create a boto3 Session with optional profile.
    
    Args:
        profile: AWS profile name or None for default chain
        
    Returns:
        Authenticated boto3 Session
        
    Exits:
        If profile is not found
    """
    try:
        if profile:
            session = boto3.Session(profile_name=profile)
        else:
            session = boto3.Session()
        return session
    except ProfileNotFound:
        logging.error(f"AWS profile '{profile}' not found")
        sys.exit(1)


def get_caller_identity(session: boto3.Session) -> dict[str, Any]:
    """
    Get AWS caller identity information.
    
    Args:
        session: Authenticated boto3 Session
        
    Returns:
        Dict with account_id, caller_arn, user_id
        
    Exits:
        If credentials are missing or API call fails
    """
    try:
        sts = session.client('sts')
        response = sts.get_caller_identity()
        return {
            'account_id': response['Account'],
            'caller_arn': response['Arn'],
            'user_id': response['UserId']
        }
    except NoCredentialsError:
        logging.error("AWS credentials not found")
        sys.exit(1)
    except ClientError as e:
        logging.error(f"Failed to get caller identity: {e}")
        sys.exit(1)


def write_collection_metadata(output_dir: Path, identity: dict[str, Any], mappings: dict) -> None:
    """
    Write collection metadata JSON file.
    
    Args:
        output_dir: Directory to write metadata file
        identity: AWS identity information
        mappings: Mappings configuration dict
    """
    metadata = {
        'collector': mappings['collector'],
        'collector_version': mappings['collector_version'],
        'schema_version': mappings['schema_version'],
        'collected_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'aws_account_id': identity['account_id'],
        'caller_arn': identity['caller_arn'],
        'user_id': identity['user_id']
    }
    
    metadata_file = output_dir / 'collection_metadata.json'
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)


if __name__ == "__main__":
    main()