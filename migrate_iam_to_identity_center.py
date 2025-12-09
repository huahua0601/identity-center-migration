#!/usr/bin/env python3
"""
IAM User Group to AWS Identity Center Migration Script

This script migrates IAM user groups and their attached policies to 
AWS Identity Center groups and permission sets.

Features:
- Export IAM groups and their attached policies
- Create corresponding groups in Identity Center
- Create Permission Sets from IAM policies
- Associate Permission Sets with Identity Center groups
"""

import boto3
import json
import argparse
import logging
import sys
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'migration_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)


class IAMToIdentityCenterMigration:
    """Main class for handling IAM to Identity Center migration."""
    
    def __init__(self, region='us-east-1', dry_run=False, instance_arn=None, identity_store_id=None,
                 use_customer_managed_policy_ref=False):
        """
        Initialize the migration tool.
        
        Args:
            region: AWS region for Identity Center
            dry_run: If True, only simulate the migration without making changes
            instance_arn: Optional Identity Center instance ARN (auto-detected if not provided)
            identity_store_id: Optional Identity Store ID (auto-detected if not provided)
            use_customer_managed_policy_ref: If True, use Customer Managed Policy Reference instead of Inline Policy
        """
        self.region = region
        self.dry_run = dry_run
        self.use_customer_managed_policy_ref = use_customer_managed_policy_ref
        
        # Initialize AWS clients
        self.iam_client = boto3.client('iam')
        self.sso_admin_client = boto3.client('sso-admin', region_name=region)
        self.identitystore_client = boto3.client('identitystore', region_name=region)
        self.organizations_client = boto3.client('organizations')
        
        # Get Identity Center instance (use provided values or auto-detect)
        self.instance_arn = instance_arn
        self.identity_store_id = identity_store_id
        self._get_identity_center_instance()
        
    def _get_identity_center_instance(self):
        """Get the Identity Center instance ARN and Identity Store ID."""
        # Check if only one parameter is provided (should provide both or none)
        if bool(self.instance_arn) != bool(self.identity_store_id):
            if self.instance_arn:
                logger.warning("--instance-arn provided but --identity-store-id missing. Will try to auto-detect identity-store-id.")
            else:
                logger.warning("--identity-store-id provided but --instance-arn missing. Will try to auto-detect instance-arn.")
        
        # If both instance_arn and identity_store_id are provided, use them directly
        if self.instance_arn and self.identity_store_id:
            logger.info(f"Using provided Identity Center instance: {self.instance_arn}")
            logger.info(f"Using provided Identity Store ID: {self.identity_store_id}")
            return
        
        # Auto-detect if not provided (or partially provided)
        try:
            response = self.sso_admin_client.list_instances()
            if response['Instances']:
                instance = response['Instances'][0]
                if not self.instance_arn:
                    self.instance_arn = instance['InstanceArn']
                    logger.info(f"Auto-detected Identity Center instance: {self.instance_arn}")
                else:
                    logger.info(f"Using provided Identity Center instance: {self.instance_arn}")
                    
                if not self.identity_store_id:
                    self.identity_store_id = instance['IdentityStoreId']
                    logger.info(f"Auto-detected Identity Store ID: {self.identity_store_id}")
                else:
                    logger.info(f"Using provided Identity Store ID: {self.identity_store_id}")
            else:
                logger.error("No Identity Center instance found. Please enable Identity Center first or provide --instance-arn and --identity-store-id.")
                sys.exit(1)
        except ClientError as e:
            logger.error(f"Error getting Identity Center instance: {e}")
            logger.error("You can manually specify --instance-arn and --identity-store-id to bypass auto-detection.")
            sys.exit(1)
    
    def get_iam_groups(self, group_names=None):
        """
        Get IAM groups and their attached policies.
        
        Args:
            group_names: Optional list of specific group names to migrate
            
        Returns:
            List of dictionaries containing group info and policies
        """
        groups_data = []
        
        try:
            paginator = self.iam_client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page['Groups']:
                    if group_names and group['GroupName'] not in group_names:
                        continue
                    
                    group_info = {
                        'name': group['GroupName'],
                        'arn': group['Arn'],
                        'attached_policies': [],
                        'inline_policies': [],
                        'users': []
                    }
                    
                    # Get attached managed policies
                    attached_policies = self.iam_client.list_attached_group_policies(
                        GroupName=group['GroupName']
                    )
                    for policy in attached_policies['AttachedPolicies']:
                        policy_detail = self._get_policy_document(policy['PolicyArn'])
                        group_info['attached_policies'].append({
                            'name': policy['PolicyName'],
                            'arn': policy['PolicyArn'],
                            'document': policy_detail
                        })
                    
                    # Get inline policies
                    inline_policies = self.iam_client.list_group_policies(
                        GroupName=group['GroupName']
                    )
                    for policy_name in inline_policies['PolicyNames']:
                        policy_response = self.iam_client.get_group_policy(
                            GroupName=group['GroupName'],
                            PolicyName=policy_name
                        )
                        group_info['inline_policies'].append({
                            'name': policy_name,
                            'document': policy_response['PolicyDocument']
                        })
                    
                    # Get users in the group
                    group_users = self.iam_client.get_group(GroupName=group['GroupName'])
                    for user in group_users['Users']:
                        group_info['users'].append(user['UserName'])
                    
                    groups_data.append(group_info)
                    logger.info(f"Collected IAM group: {group['GroupName']} with "
                              f"{len(group_info['attached_policies'])} attached policies, "
                              f"{len(group_info['inline_policies'])} inline policies, "
                              f"{len(group_info['users'])} users")
        
        except ClientError as e:
            logger.error(f"Error getting IAM groups: {e}")
            raise
        
        return groups_data
    
    def _get_policy_document(self, policy_arn):
        """Get the policy document for a managed policy."""
        try:
            policy = self.iam_client.get_policy(PolicyArn=policy_arn)
            version_id = policy['Policy']['DefaultVersionId']
            
            policy_version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            return policy_version['PolicyVersion']['Document']
        except ClientError as e:
            logger.error(f"Error getting policy document for {policy_arn}: {e}")
            return None
    
    def create_identity_center_group(self, group_name, description=None):
        """
        Create a group in Identity Center.
        
        Args:
            group_name: Name of the group to create
            description: Optional description for the group
            
        Returns:
            Group ID if created successfully, None otherwise
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create Identity Center group: {group_name}")
            return f"dry-run-group-id-{group_name}"
        
        try:
            # Check if group already exists
            existing_group = self._find_identity_center_group(group_name)
            if existing_group:
                logger.info(f"Group '{group_name}' already exists with ID: {existing_group}")
                return existing_group
            
            response = self.identitystore_client.create_group(
                IdentityStoreId=self.identity_store_id,
                DisplayName=group_name,
                Description=description or f"Migrated from IAM group: {group_name}"
            )
            group_id = response['GroupId']
            logger.info(f"Created Identity Center group: {group_name} (ID: {group_id})")
            return group_id
            
        except ClientError as e:
            logger.error(f"Error creating Identity Center group '{group_name}': {e}")
            return None
    
    def _find_identity_center_group(self, group_name):
        """Find an existing Identity Center group by name."""
        try:
            response = self.identitystore_client.list_groups(
                IdentityStoreId=self.identity_store_id,
                Filters=[{
                    'AttributePath': 'DisplayName',
                    'AttributeValue': group_name
                }]
            )
            if response['Groups']:
                return response['Groups'][0]['GroupId']
            return None
        except ClientError as e:
            logger.error(f"Error finding Identity Center group: {e}")
            return None
    
    def create_permission_set(self, name, description=None, session_duration='PT8H'):
        """
        Create a Permission Set in Identity Center.
        
        Args:
            name: Name of the permission set
            description: Optional description
            session_duration: Session duration in ISO 8601 format (default: 8 hours)
            
        Returns:
            Permission Set ARN if created successfully, None otherwise
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create Permission Set: {name}")
            return f"arn:aws:sso:::permissionSet/dry-run/{name}"
        
        try:
            # Check if permission set already exists
            existing_ps = self._find_permission_set(name)
            if existing_ps:
                logger.info(f"Permission Set '{name}' already exists: {existing_ps}")
                return existing_ps
            
            response = self.sso_admin_client.create_permission_set(
                Name=name,
                Description=description or f"Migrated from IAM policy: {name}",
                InstanceArn=self.instance_arn,
                SessionDuration=session_duration
            )
            ps_arn = response['PermissionSet']['PermissionSetArn']
            logger.info(f"Created Permission Set: {name} (ARN: {ps_arn})")
            return ps_arn
            
        except ClientError as e:
            logger.error(f"Error creating Permission Set '{name}': {e}")
            return None
    
    def _find_permission_set(self, name):
        """Find an existing Permission Set by name."""
        try:
            paginator = self.sso_admin_client.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn=self.instance_arn):
                for ps_arn in page['PermissionSets']:
                    ps_detail = self.sso_admin_client.describe_permission_set(
                        InstanceArn=self.instance_arn,
                        PermissionSetArn=ps_arn
                    )
                    if ps_detail['PermissionSet']['Name'] == name:
                        return ps_arn
            return None
        except ClientError as e:
            logger.error(f"Error finding Permission Set: {e}")
            return None
    
    def attach_inline_policy_to_permission_set(self, permission_set_arn, policy_document):
        """
        Attach an inline policy to a Permission Set.
        
        Args:
            permission_set_arn: ARN of the Permission Set
            policy_document: Policy document (dict)
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would attach inline policy to Permission Set: {permission_set_arn}")
            return True
        
        try:
            self.sso_admin_client.put_inline_policy_to_permission_set(
                InstanceArn=self.instance_arn,
                PermissionSetArn=permission_set_arn,
                InlinePolicy=json.dumps(policy_document)
            )
            logger.info(f"Attached inline policy to Permission Set: {permission_set_arn}")
            return True
        except ClientError as e:
            logger.error(f"Error attaching inline policy: {e}")
            return False
    
    def attach_managed_policy_to_permission_set(self, permission_set_arn, policy_arn):
        """
        Attach a managed policy to a Permission Set.
        
        Args:
            permission_set_arn: ARN of the Permission Set
            policy_arn: ARN of the managed policy
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would attach managed policy {policy_arn} to Permission Set")
            return True
        
        try:
            # Check if it's an AWS managed policy
            if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                self.sso_admin_client.attach_managed_policy_to_permission_set(
                    InstanceArn=self.instance_arn,
                    PermissionSetArn=permission_set_arn,
                    ManagedPolicyArn=policy_arn
                )
                logger.info(f"Attached AWS managed policy {policy_arn} to Permission Set")
            else:
                # For customer managed policies, we need to use customer managed policy
                self.sso_admin_client.attach_customer_managed_policy_reference_to_permission_set(
                    InstanceArn=self.instance_arn,
                    PermissionSetArn=permission_set_arn,
                    CustomerManagedPolicyReference={
                        'Name': policy_arn.split('/')[-1],
                        'Path': '/'
                    }
                )
                logger.info(f"Attached customer managed policy reference to Permission Set")
            return True
        except ClientError as e:
            if 'ConflictException' in str(e):
                logger.warning(f"Policy already attached: {policy_arn}")
                return True
            logger.error(f"Error attaching managed policy: {e}")
            return False
    
    def _attach_customer_managed_policy_ref(self, permission_set_arn, policy_name, path='/'):
        """
        Attach a Customer Managed Policy Reference to a Permission Set.
        
        Args:
            permission_set_arn: ARN of the Permission Set
            policy_name: Name of the customer managed policy
            path: IAM policy path (default: '/')
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would attach customer managed policy reference: {policy_name}")
            return True
        
        try:
            self.sso_admin_client.attach_customer_managed_policy_reference_to_permission_set(
                InstanceArn=self.instance_arn,
                PermissionSetArn=permission_set_arn,
                CustomerManagedPolicyReference={
                    'Name': policy_name,
                    'Path': path
                }
            )
            logger.info(f"  -> Attached Customer Managed Policy Reference: {policy_name}")
            return True
        except ClientError as e:
            if 'ConflictException' in str(e):
                logger.warning(f"  -> Policy reference already attached: {policy_name}")
                return True
            logger.error(f"  -> Error attaching customer managed policy reference: {e}")
            return False
    
    def assign_permission_set_to_group(self, permission_set_arn, group_id, account_id):
        """
        Assign a Permission Set to a group for a specific account.
        
        Args:
            permission_set_arn: ARN of the Permission Set
            group_id: Identity Center Group ID
            account_id: AWS Account ID
            
        Returns:
            True if successful, False otherwise
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Would assign Permission Set to group {group_id} for account {account_id}")
            return True
        
        try:
            self.sso_admin_client.create_account_assignment(
                InstanceArn=self.instance_arn,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=permission_set_arn,
                PrincipalType='GROUP',
                PrincipalId=group_id
            )
            logger.info(f"Assigned Permission Set to group {group_id} for account {account_id}")
            return True
        except ClientError as e:
            if 'ConflictException' in str(e):
                logger.warning(f"Assignment already exists for group {group_id}")
                return True
            logger.error(f"Error creating account assignment: {e}")
            return False
    
    def get_organization_accounts(self):
        """Get all accounts in the organization."""
        accounts = []
        try:
            paginator = self.organizations_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                for account in page['Accounts']:
                    if account['Status'] == 'ACTIVE':
                        accounts.append({
                            'id': account['Id'],
                            'name': account['Name'],
                            'email': account['Email']
                        })
            logger.info(f"Found {len(accounts)} active accounts in organization")
            return accounts
        except ClientError as e:
            logger.error(f"Error listing organization accounts: {e}")
            # Fall back to current account
            sts = boto3.client('sts')
            current_account = sts.get_caller_identity()['Account']
            logger.info(f"Using current account: {current_account}")
            return [{'id': current_account, 'name': 'Current Account', 'email': ''}]
    
    def export_groups_to_json(self, groups_data, filename='iam_groups_export.json'):
        """Export IAM groups data to a JSON file for review."""
        export_data = {
            'export_date': datetime.now().isoformat(),
            'groups': groups_data
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Exported {len(groups_data)} groups to {filename}")
        
        # Print detailed policy summary
        logger.info("\n" + "=" * 60)
        logger.info("Detailed Policy Summary")
        logger.info("=" * 60)
        for group in groups_data:
            logger.info(f"\n📁 Group: {group['name']}")
            logger.info(f"   Users: {', '.join(group['users']) if group['users'] else 'None'}")
            
            if group['attached_policies']:
                logger.info(f"   Attached Policies ({len(group['attached_policies'])}):")
                for policy in group['attached_policies']:
                    policy_type = "AWS Managed" if policy['arn'].startswith('arn:aws:iam::aws:policy/') else "Customer Managed"
                    logger.info(f"     - {policy['name']} [{policy_type}]")
                    if policy['document']:
                        statements = policy['document'].get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        for stmt in statements[:3]:  # Show first 3 statements
                            actions = stmt.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            action_preview = ', '.join(actions[:3])
                            if len(actions) > 3:
                                action_preview += f" ... (+{len(actions)-3} more)"
                            logger.info(f"       Actions: {action_preview}")
            
            if group['inline_policies']:
                logger.info(f"   Inline Policies ({len(group['inline_policies'])}):")
                for policy in group['inline_policies']:
                    logger.info(f"     - {policy['name']}")
        
        logger.info("\n" + "=" * 60)
        return filename
    
    def migrate_group(self, group_data, target_accounts=None, create_combined_permission_set=True):
        """
        Migrate a single IAM group to Identity Center.
        
        Args:
            group_data: Dictionary containing group information and policies
            target_accounts: List of account IDs to assign permissions to
            create_combined_permission_set: If True, combine all policies into one Permission Set
            
        Returns:
            Migration result dictionary
        """
        result = {
            'group_name': group_data['name'],
            'success': False,
            'identity_center_group_id': None,
            'permission_sets': [],
            'errors': []
        }
        
        try:
            # Create Identity Center group
            group_id = self.create_identity_center_group(
                group_data['name'],
                f"Migrated from IAM group: {group_data['name']}"
            )
            
            if not group_id:
                result['errors'].append(f"Failed to create Identity Center group: {group_data['name']}")
                return result
            
            result['identity_center_group_id'] = group_id
            
            if create_combined_permission_set:
                # Create a single Permission Set with all policies combined
                # Permission Set name max length is 32 characters
                base_name = group_data['name'][:20] if len(group_data['name']) > 20 else group_data['name']
                ps_name = f"{base_name}-permissions"[:32]
                permission_set_arn = self.create_permission_set(
                    ps_name,
                    f"Combined permissions for {group_data['name']} group"
                )
                
                if permission_set_arn:
                    # Attach all attached managed policies
                    # Collect all customer managed policy documents to combine into one inline policy
                    customer_policy_statements = []
                    customer_policy_names = []
                    
                    for policy in group_data['attached_policies']:
                        if policy['arn'].startswith('arn:aws:iam::aws:policy/'):
                            # AWS Managed Policy - attach directly
                            self.attach_managed_policy_to_permission_set(
                                permission_set_arn, 
                                policy['arn']
                            )
                            logger.info(f"  -> Attached AWS Managed Policy: {policy['name']}")
                        elif policy['document']:
                            # Customer Managed Policy - collect for inline policy
                            customer_policy_names.append(policy['name'])
                            doc = policy['document']
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            statements = doc.get('Statement', [])
                            if isinstance(statements, list):
                                customer_policy_statements.extend(statements)
                            else:
                                customer_policy_statements.append(statements)
                            logger.info(f"  -> Collected Customer Managed Policy: {policy['name']} (will be added as inline)")
                    
                    # Combine all customer managed policies into one inline policy
                    if customer_policy_statements:
                        combined_policy = {
                            'Version': '2012-10-17',
                            'Statement': customer_policy_statements
                        }
                        self.attach_inline_policy_to_permission_set(
                            permission_set_arn,
                            combined_policy
                        )
                        logger.info(f"  -> Combined {len(customer_policy_names)} customer policies into inline policy: {', '.join(customer_policy_names)}")
                    
                    # Handle IAM inline policies (different from customer managed policies)
                    if group_data['inline_policies']:
                        inline_statements = []
                        inline_policy_names = []
                        for policy in group_data['inline_policies']:
                            inline_policy_names.append(policy['name'])
                            doc = policy['document']
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            statements = doc.get('Statement', [])
                            if isinstance(statements, list):
                                inline_statements.extend(statements)
                            else:
                                inline_statements.append(statements)
                        
                        if inline_statements:
                            # If we already have customer managed policies as inline, 
                            # we need to combine them (Permission Set only allows one inline policy)
                            if customer_policy_statements:
                                logger.warning(f"  -> Note: Inline policies will be combined with customer managed policies")
                                # Need to get existing inline policy and merge
                                all_statements = customer_policy_statements + inline_statements
                                combined_policy = {
                                    'Version': '2012-10-17',
                                    'Statement': all_statements
                                }
                                self.attach_inline_policy_to_permission_set(
                                    permission_set_arn,
                                    combined_policy
                                )
                            else:
                                combined_policy = {
                                    'Version': '2012-10-17',
                                    'Statement': inline_statements
                                }
                                self.attach_inline_policy_to_permission_set(
                                    permission_set_arn,
                                    combined_policy
                                )
                            logger.info(f"  -> Added IAM inline policies: {', '.join(inline_policy_names)}")
                    
                    result['permission_sets'].append({
                        'name': ps_name,
                        'arn': permission_set_arn
                    })
                    
                    # Assign to target accounts
                    if target_accounts:
                        for account_id in target_accounts:
                            self.assign_permission_set_to_group(
                                permission_set_arn,
                                group_id,
                                account_id
                            )
            else:
                # Create separate Permission Set for each policy
                for policy in group_data['attached_policies']:
                    # Use policy name directly as Permission Set name (max 32 chars)
                    ps_name = policy['name'][:32]
                    permission_set_arn = self.create_permission_set(
                        ps_name,
                        f"Migrated from IAM policy: {policy['name']}"
                    )
                    
                    if permission_set_arn:
                        if policy['arn'].startswith('arn:aws:iam::aws:policy/'):
                            # AWS Managed Policy - attach directly
                            self.attach_managed_policy_to_permission_set(
                                permission_set_arn,
                                policy['arn']
                            )
                            logger.info(f"  -> Attached AWS Managed Policy: {policy['name']}")
                        else:
                            # Customer Managed Policy
                            if self.use_customer_managed_policy_ref:
                                # Use Customer Managed Policy Reference
                                self._attach_customer_managed_policy_ref(
                                    permission_set_arn,
                                    policy['name']
                                )
                            elif policy['document']:
                                # Fallback to inline policy
                                self.attach_inline_policy_to_permission_set(
                                    permission_set_arn,
                                    policy['document']
                                )
                                logger.info(f"  -> Attached as Inline Policy: {policy['name']}")
                        
                        result['permission_sets'].append({
                            'name': ps_name,
                            'arn': permission_set_arn
                        })
                        
                        # Assign to group for target accounts
                        if target_accounts:
                            for account_id in target_accounts:
                                self.assign_permission_set_to_group(
                                    permission_set_arn,
                                    group_id,
                                    account_id
                                )
                
                # Handle IAM inline policies separately
                for policy in group_data['inline_policies']:
                    ps_name = f"{group_data['name']}-{policy['name']}"[:32]
                    permission_set_arn = self.create_permission_set(
                        ps_name,
                        f"Migrated from IAM inline policy: {policy['name']}"
                    )
                    if permission_set_arn and policy['document']:
                        doc = policy['document']
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        self.attach_inline_policy_to_permission_set(
                            permission_set_arn,
                            doc
                        )
                        logger.info(f"  -> Created Permission Set for inline policy: {policy['name']}")
                        
                        result['permission_sets'].append({
                            'name': ps_name,
                            'arn': permission_set_arn
                        })
                        
                        if target_accounts:
                            for account_id in target_accounts:
                                self.assign_permission_set_to_group(
                                    permission_set_arn,
                                    group_id,
                                    account_id
                                )
            
            result['success'] = True
            logger.info(f"Successfully migrated group: {group_data['name']}")
            
        except Exception as e:
            result['errors'].append(str(e))
            logger.error(f"Error migrating group {group_data['name']}: {e}")
        
        return result
    
    def run_migration(self, group_names=None, target_accounts=None, 
                     export_only=False, combined_permission_set=True):
        """
        Run the full migration process.
        
        Args:
            group_names: Optional list of specific group names to migrate
            target_accounts: List of account IDs to assign permissions to
            export_only: If True, only export groups without migrating
            combined_permission_set: If True, combine policies into single Permission Set
            
        Returns:
            Migration results summary
        """
        logger.info("=" * 60)
        logger.info("Starting IAM to Identity Center Migration")
        logger.info(f"Dry Run: {self.dry_run}")
        logger.info("=" * 60)
        
        # Get IAM groups
        logger.info("\n[Step 1] Collecting IAM groups and policies...")
        groups_data = self.get_iam_groups(group_names)
        
        if not groups_data:
            logger.warning("No IAM groups found to migrate")
            return {'success': False, 'message': 'No groups found'}
        
        # Export to JSON for review
        export_file = self.export_groups_to_json(groups_data)
        
        if export_only:
            logger.info(f"\nExport complete. Review the exported data in: {export_file}")
            return {'success': True, 'export_file': export_file, 'groups_count': len(groups_data)}
        
        # Get target accounts if not specified
        if not target_accounts:
            logger.info("\n[Step 2] Getting organization accounts...")
            accounts = self.get_organization_accounts()
            target_accounts = [acc['id'] for acc in accounts]
        
        # Migrate each group
        logger.info(f"\n[Step 3] Migrating {len(groups_data)} groups...")
        results = []
        for group_data in groups_data:
            result = self.migrate_group(
                group_data, 
                target_accounts,
                combined_permission_set
            )
            results.append(result)
        
        # Summary
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        
        logger.info("\n" + "=" * 60)
        logger.info("Migration Summary")
        logger.info("=" * 60)
        logger.info(f"Total groups processed: {len(results)}")
        logger.info(f"Successful migrations: {successful}")
        logger.info(f"Failed migrations: {failed}")
        
        if failed > 0:
            logger.info("\nFailed groups:")
            for r in results:
                if not r['success']:
                    logger.info(f"  - {r['group_name']}: {r['errors']}")
        
        return {
            'success': failed == 0,
            'total': len(results),
            'successful': successful,
            'failed': failed,
            'results': results
        }


def main():
    parser = argparse.ArgumentParser(
        description='Migrate IAM User Groups to AWS Identity Center',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export IAM groups for review (no changes made)
  python migrate_iam_to_identity_center.py --export-only

  # Dry run migration for all groups
  python migrate_iam_to_identity_center.py --dry-run

  # Migrate specific groups
  python migrate_iam_to_identity_center.py --groups Developers Admins

  # Migrate to specific accounts
  python migrate_iam_to_identity_center.py --accounts 123456789012 987654321098

  # Full migration with separate permission sets per policy
  python migrate_iam_to_identity_center.py --separate-permission-sets

  # Specify Identity Center instance manually
  python migrate_iam_to_identity_center.py --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef --identity-store-id d-1234567890
        """
    )
    
    parser.add_argument(
        '--region', '-r',
        default='us-east-1',
        help='AWS region for Identity Center (default: us-east-1)'
    )
    
    parser.add_argument(
        '--instance-arn',
        help='Identity Center instance ARN (auto-detected if not provided). Example: arn:aws:sso:::instance/ssoins-1234567890abcdef'
    )
    
    parser.add_argument(
        '--identity-store-id',
        help='Identity Store ID (auto-detected if not provided). Example: d-1234567890'
    )
    
    parser.add_argument(
        '--groups', '-g',
        nargs='+',
        help='Specific IAM group names to migrate (default: all groups)'
    )
    
    parser.add_argument(
        '--accounts', '-a',
        nargs='+',
        help='Target AWS account IDs for permission assignments'
    )
    
    parser.add_argument(
        '--dry-run', '-d',
        action='store_true',
        help='Simulate migration without making actual changes'
    )
    
    parser.add_argument(
        '--export-only', '-e',
        action='store_true',
        help='Only export IAM groups to JSON without migrating'
    )
    
    parser.add_argument(
        '--separate-permission-sets', '-s',
        action='store_true',
        help='Create separate Permission Sets for each policy (default: combined)'
    )
    
    parser.add_argument(
        '--use-customer-managed-policy-ref',
        action='store_true',
        help='Use Customer Managed Policy Reference instead of Inline Policy for customer managed policies'
    )
    
    args = parser.parse_args()
    
    try:
        migration = IAMToIdentityCenterMigration(
            region=args.region,
            dry_run=args.dry_run,
            instance_arn=args.instance_arn,
            identity_store_id=args.identity_store_id,
            use_customer_managed_policy_ref=args.use_customer_managed_policy_ref
        )
        
        results = migration.run_migration(
            group_names=args.groups,
            target_accounts=args.accounts,
            export_only=args.export_only,
            combined_permission_set=not args.separate_permission_sets
        )
        
        if results['success']:
            logger.info("\nMigration completed successfully!")
            sys.exit(0)
        else:
            logger.error("\nMigration completed with errors.")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

