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
    
    # Create raw output subdirectory
    raw_dir = args.output_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    
    # Perform technical checks
    findings = []
    
    # Check account-level Block Public Access (EXT-ACCT-BPA-01)
    bpa_finding = check_account_bpa(session, identity['account_id'], raw_dir)
    findings.append(bpa_finding)
    logging.info(f"Account-level BPA check: {bpa_finding['status']}")

    # Enumerate S3 buckets for per-bucket checks
    buckets = enumerate_buckets(session, raw_dir)
    logging.info(f"Enumerated {len(buckets)} bucket(s)")


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


def check_account_bpa(session: boto3.Session, account_id: str, output_dir: Path) -> dict[str, Any]:
    """
    Check account-level Block Public Access settings (EXT-ACCT-BPA-01).
    
    Args:
        session: Authenticated boto3 Session
        account_id: AWS account ID
        output_dir: Directory to write raw evidence
        
    Returns:
        Finding dict with check results
        
    Exits:
        If API call fails (except NoSuchPublicAccessBlockConfiguration)
    """
    try:
        s3control = session.client('s3control')
        response = s3control.get_public_access_block(AccountId=account_id)
        
        # Write raw response
        raw_response = {k: v for k, v in response.items() if k != 'ResponseMetadata'}
        raw_file = output_dir / "account_public_access_block.json"
        with open(raw_file, 'w', encoding='utf-8') as f:
            json.dump(raw_response, f, indent=2)
        
        # Evaluate settings
        settings = raw_response.get('PublicAccessBlockConfiguration', {})
        required_settings = [
            'BlockPublicAcls',
            'IgnorePublicAcls', 
            'BlockPublicPolicy',
            'RestrictPublicBuckets'
        ]
        
        disabled_settings = []
        for setting in required_settings:
            if not settings.get(setting, False):
                disabled_settings.append(setting)
        
        if disabled_settings:
            return {
                'finding_id': 'EXT-ACCT-BPA-01-account',
                'control_id': 'EXT-ACCT-BPA-01',
                'scope': 'account',
                'resource_id': account_id,
                'status': 'FAIL',
                'severity': 'high',
                'detail': f"Account-level Block Public Access has disabled settings: {', '.join(disabled_settings)}",
                'evidence_ref': 'raw/account_public_access_block.json'
            }
        else:
            return {
                'finding_id': 'EXT-ACCT-BPA-01-account',
                'control_id': 'EXT-ACCT-BPA-01',
                'scope': 'account',
                'resource_id': account_id,
                'status': 'PASS',
                'severity': 'high',
                'detail': "Account-level Block Public Access is properly configured with all settings enabled",
                'evidence_ref': 'raw/account_public_access_block.json'
            }
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            # Account-level BPA has never been configured
            raw_response = {'configured': False}
            raw_file = output_dir / "account_public_access_block.json"
            with open(raw_file, 'w', encoding='utf-8') as f:
                json.dump(raw_response, f, indent=2)
            
            return {
                'finding_id': 'EXT-ACCT-BPA-01-account',
                'control_id': 'EXT-ACCT-BPA-01',
                'scope': 'account',
                'resource_id': account_id,
                'status': 'FAIL',
                'severity': 'high',
                'detail': "Account-level Block Public Access has never been configured",
                'evidence_ref': 'raw/account_public_access_block.json'
            }
        else:
            logging.error(f"Failed to get account public access block: {e}")
            sys.exit(1)


def enumerate_buckets(session: boto3.Session, raw_dir: Path) -> list[dict[str, Any]]:
    """
    Enumerate all S3 buckets in the account.
    
    Args:
        session: Authenticated boto3 Session
        raw_dir: Directory to write raw evidence files
        
    Returns:
        List of bucket dicts with name, creation_date, and region
        
    Exits:
        If unable to list buckets
    """
    try:
        s3 = session.client('s3')
        response = s3.list_buckets()
        
        # Create buckets subdirectory
        buckets_dir = raw_dir / "buckets"
        buckets_dir.mkdir(exist_ok=True)
        
        buckets = []
        for bucket_data in response.get('Buckets', []):
            bucket_name = bucket_data['Name']
            creation_date = bucket_data['CreationDate'].isoformat().replace('+00:00', 'Z')
            
            # Get bucket region
            try:
                location_response = s3.get_bucket_location(Bucket=bucket_name)
                location_constraint = location_response.get('LocationConstraint')
                
                # Normalize region names
                if location_constraint is None or location_constraint == '':
                    region = 'us-east-1'
                elif location_constraint == 'EU':
                    region = 'eu-west-1'
                else:
                    region = location_constraint
                    
            except ClientError as e:
                logging.warning(f"Failed to get location for bucket {bucket_name}: {e.response['Error']['Code']}")
                region = None
                bucket_dict = {
                    'name': bucket_name,
                    'creation_date': creation_date,
                    'region': region,
                    'enumeration_error': e.response['Error']['Code']
                }
            else:
                bucket_dict = {
                    'name': bucket_name,
                    'creation_date': creation_date,
                    'region': region
                }
            
            buckets.append(bucket_dict)
        
        # Write inventory file
        inventory = {
            'enumerated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'bucket_count': len(buckets),
            'buckets': buckets
        }
        
        inventory_file = buckets_dir / "inventory.json"
        with open(inventory_file, 'w', encoding='utf-8') as f:
            json.dump(inventory, f, indent=2)
        
        return buckets
        
    except (ClientError, NoCredentialsError) as e:
        logging.error(f"Failed to enumerate buckets: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()