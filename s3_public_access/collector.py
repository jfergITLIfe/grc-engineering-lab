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

    # Per-bucket public access checks (CIS-AWS-2.1.4 and CIS-AWS-2.1.5)
    for bucket in buckets: 
        bucket_findings = check_bucket_public_access(session, bucket, raw_dir)
        findings.extend(bucket_findings)
        for finding in bucket_findings:
            logging.info(f"{finding['control_id']} on {finding['resource_id']}: {finding['status']}")


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


def check_bucket_public_access(session: boto3.Session, bucket: dict[str, Any], raw_dir: Path) -> list[dict[str, Any]]:
    """
    Check bucket-level public access settings.
    
    Args:
        session: Authenticated boto3 Session
        bucket: Bucket dict with name, creation_date, region, and optional enumeration_error
        raw_dir: Base raw evidence directory
        
    Returns:
        List of two findings: CIS-AWS-2.1.4 (BPA) and CIS-AWS-2.1.5 (policy/ACL)
    """
    findings = []
    
    # Step 0: Handle enumeration errors
    if 'enumeration_error' in bucket:
        error_detail = f"Bucket could not be evaluated due to enumeration error: {bucket['enumeration_error']}"
        evidence_ref = 'raw/buckets/inventory.json'
        
        bpa_finding = {
            'finding_id': f'CIS-AWS-2.1.4-{bucket["name"]}',
            'control_id': 'CIS-AWS-2.1.4',
            'scope': 'bucket',
            'resource_id': bucket["name"],
            'status': 'ERROR',
            'severity': 'high',
            'detail': error_detail,
            'evidence_ref': evidence_ref
        }
        
        policy_finding = {
            'finding_id': f'CIS-AWS-2.1.5-{bucket["name"]}',
            'control_id': 'CIS-AWS-2.1.5',
            'scope': 'bucket',
            'resource_id': bucket["name"],
            'status': 'ERROR',
            'severity': 'critical',
            'detail': error_detail,
            'evidence_ref': evidence_ref
        }
        
        return [bpa_finding, policy_finding]
    
    # Step 1: Create per-bucket evidence subdirectory
    bucket_dir = raw_dir / "buckets" / bucket["name"]
    bucket_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 2: Create regional S3 client
    s3 = session.client('s3', region_name=bucket["region"])
    
    # Step 3: CIS-AWS-2.1.4 - Bucket-level Block Public Access
    try:
        bpa_response = s3.get_public_access_block(Bucket=bucket["name"])
        bpa_data = {k: v for k, v in bpa_response.items() if k != 'ResponseMetadata'}
        
        # Write BPA evidence
        bpa_file = bucket_dir / "public_access_block.json"
        with open(bpa_file, 'w', encoding='utf-8') as f:
            json.dump(bpa_data, f, indent=2)
        
        # Evaluate BPA settings
        settings = bpa_data.get('PublicAccessBlockConfiguration', {})
        required_settings = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']
        
        disabled_settings = []
        for setting in required_settings:
            if not settings.get(setting, False):
                disabled_settings.append(setting)
        
        if disabled_settings:
            bpa_status = 'FAIL'
            bpa_detail = f"Bucket Block Public Access has disabled settings: {', '.join(disabled_settings)}"
        else:
            bpa_status = 'PASS'
            bpa_detail = "Bucket Block Public Access is properly configured with all settings enabled"
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            # No BPA configuration
            bpa_data = {'configured': False}
            bpa_file = bucket_dir / "public_access_block.json"
            with open(bpa_file, 'w', encoding='utf-8') as f:
                json.dump(bpa_data, f, indent=2)
            
            bpa_status = 'FAIL'
            bpa_detail = "Bucket has no Block Public Access configuration"
        else:
            logging.warning(f"Failed to get BPA for bucket {bucket['name']}: {e.response['Error']['Code']}")
            bpa_status = 'ERROR'
            bpa_detail = f"API error retrieving Block Public Access: {e.response['Error']['Code']}"
    
    bpa_finding = {
        'finding_id': f'CIS-AWS-2.1.4-{bucket["name"]}',
        'control_id': 'CIS-AWS-2.1.4',
        'scope': 'bucket',
        'resource_id': bucket["name"],
        'status': bpa_status,
        'severity': 'high',
        'detail': bpa_detail,
        'evidence_ref': f'raw/buckets/{bucket["name"]}/public_access_block.json'
    }
    findings.append(bpa_finding)
    
    # Step 4: CIS-AWS-2.1.5 - Policy and ACL public access
    try:
        # 4a: Policy status
        try:
            policy_status_response = s3.get_bucket_policy_status(Bucket=bucket["name"])
            policy_status_data = {k: v for k, v in policy_status_response.items() if k != 'ResponseMetadata'}
            is_public = policy_status_data.get('PolicyStatus', {}).get('IsPublic', False)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                policy_status_data = {'has_policy_status': False}
                is_public = False
            else:
                raise e
        
        # Write policy status evidence
        policy_status_file = bucket_dir / "policy_status.json"
        with open(policy_status_file, 'w', encoding='utf-8') as f:
            json.dump(policy_status_data, f, indent=2)
        
        # 4b: Bucket policy
        policy_data = None
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket["name"])
            policy_json = json.loads(policy_response['Policy'])
            policy_data = policy_json
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                policy_data = None
            else:
                raise e
        
        # Write policy evidence
        policy_file = bucket_dir / "policy.json"
        with open(policy_file, 'w', encoding='utf-8') as f:
            if policy_data:
                json.dump(policy_data, f, indent=2)
            else:
                json.dump({'has_policy': False}, f, indent=2)
        
        # 4c: Bucket ACL
        acl_grants = []
        public_acls = []
        try:
            acl_response = s3.get_bucket_acl(Bucket=bucket["name"])
            acl_data = {k: v for k, v in acl_response.items() if k != 'ResponseMetadata'}
            
            # Check for public grants
            for grant in acl_data.get('Grants', []):
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI')
                if uri in ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']:
                    public_acls.append({
                        'grantee': uri,
                        'permission': grant.get('Permission')
                    })
                    
        except ClientError as e:
            raise e
        
        # Write ACL evidence
        acl_file = bucket_dir / "acl.json"
        with open(acl_file, 'w', encoding='utf-8') as f:
            json.dump(acl_data, f, indent=2)
        
        # 4d: Determine status
        policy_public_details = []
        if is_public and policy_data:
            for i, statement in enumerate(policy_data.get('Statement', [])):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    is_public_principal = (principal == '*' or 
                                         (isinstance(principal, dict) and principal.get('AWS') == '*'))
                    has_conditions = 'Condition' in statement
                    
                    if is_public_principal and not has_conditions:
                        sid = statement.get('Sid', f"Statement {i}")
                        policy_public_details.append(f"Policy statement '{sid}' grants public access")
                    elif is_public_principal and has_conditions:
                        sid = statement.get('Sid', f"Statement {i}")
                        policy_public_details.append(f"Policy statement '{sid}' grants public access (has conditions, not evaluated)")
        
        acl_public_details = []
        for acl in public_acls:
            grantee_name = "AllUsers" if "AllUsers" in acl['grantee'] else "AuthenticatedUsers"
            acl_public_details.append(f"ACL grants {acl['permission']} to {grantee_name}")
        
        # 4e: Build detail and determine status
        if is_public or public_acls:
            status = 'FAIL'
            detail_parts = []
            if policy_public_details:
                detail_parts.extend(policy_public_details)
            if acl_public_details:
                detail_parts.extend(acl_public_details)
            detail = "Public access detected: " + "; ".join(detail_parts)
        else:
            status = 'PASS'
            detail = "No public access detected in bucket policy or ACL"
            
    except ClientError as e:
        logging.warning(f"Failed to check policy/ACL for bucket {bucket['name']}: {e.response['Error']['Code']}")
        status = 'ERROR'
        detail = f"API error checking policy/ACL: {e.response['Error']['Code']}"
    
    policy_finding = {
        'finding_id': f'CIS-AWS-2.1.5-{bucket["name"]}',
        'control_id': 'CIS-AWS-2.1.5',
        'scope': 'bucket',
        'resource_id': bucket["name"],
        'status': status,
        'severity': 'critical',
        'detail': detail,
        'evidence_ref': f'raw/buckets/{bucket["name"]}/'
    }
    findings.append(policy_finding)
    
    return findings


if __name__ == "__main__":
    main()