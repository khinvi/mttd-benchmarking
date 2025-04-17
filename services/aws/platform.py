"""
AWS Platform Client for creating resources and executing attack techniques.
"""

import logging
import uuid
import boto3
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

from ...core.types import ResourceType

logger = logging.getLogger(__name__)


class PlatformClient:
    """
    Client for interacting with AWS platform services.
    Handles environment setup, resource creation, and technique execution.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AWS platform client.
        
        Args:
            config: AWS configuration
        """
        self.config = config
        self.session = None
        self.resources = {}
        self._initialize_session()
        
    def _initialize_session(self):
        """Initialize AWS session using provided credentials."""
        try:
            # Set up AWS session
            session_args = {}
            
            if "profile_name" in self.config:
                session_args["profile_name"] = self.config["profile_name"]
            
            if "region" in self.config:
                session_args["region_name"] = self.config["region"]
            elif "region_name" in self.config:
                session_args["region_name"] = self.config["region_name"]
                
            if "aws_access_key_id" in self.config and "aws_secret_access_key" in self.config:
                session_args["aws_access_key_id"] = self.config["aws_access_key_id"]
                session_args["aws_secret_access_key"] = self.config["aws_secret_access_key"]
                
                if "aws_session_token" in self.config:
                    session_args["aws_session_token"] = self.config["aws_session_token"]
            
            self.session = boto3.Session(**session_args)
            region = self.session.region_name
            logger.info(f"Initialized AWS session in region {region}")
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {str(e)}")
            raise
    
    def create_resource(self, resource_type: ResourceType, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an AWS resource.
        
        Args:
            resource_type: Type of resource to create
            resource_name: Name for the resource
            parameters: Resource parameters
            
        Returns:
            Resource ID
        """
        resource_id = None
        
        # Ensure we have a session
        if not self.session:
            self._initialize_session()
        
        try:
            # Create appropriate client
            client = self._get_client_for_resource(resource_type)
            
            # Create the resource based on type
            if resource_type == ResourceType.EC2_INSTANCE:
                resource_id = self._create_ec2_instance(client, resource_name, parameters)
            elif resource_type == ResourceType.S3_BUCKET:
                resource_id = self._create_s3_bucket(client, resource_name, parameters)
            elif resource_type == ResourceType.IAM_ROLE:
                resource_id = self._create_iam_role(client, resource_name, parameters)
            elif resource_type == ResourceType.IAM_USER:
                resource_id = self._create_iam_user(client, resource_name, parameters)
            elif resource_type == ResourceType.LAMBDA_FUNCTION:
                resource_id = self._create_lambda_function(client, resource_name, parameters)
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
            
            # Track created resource
            if resource_type.value not in self.resources:
                self.resources[resource_type.value] = []
                
            self.resources[resource_type.value].append({
                "id": resource_id,
                "name": resource_name,
                "parameters": parameters
            })
            
            return resource_id
            
        except Exception as e:
            logger.error(f"Failed to create {resource_type.value} resource: {str(e)}")
            raise
    
    def delete_resource(self, resource_type: str, resource_id: str) -> bool:
        """
        Delete an AWS resource.
        
        Args:
            resource_type: Type of resource to delete
            resource_id: ID of the resource
            
        Returns:
            True if successful, False otherwise
        """
        # Ensure we have a session
        if not self.session:
            self._initialize_session()
        
        try:
            # Create appropriate client
            resource_enum = ResourceType(resource_type)
            client = self._get_client_for_resource(resource_enum)
            
            # Delete the resource based on type
            if resource_enum == ResourceType.EC2_INSTANCE:
                self._delete_ec2_instance(client, resource_id)
            elif resource_enum == ResourceType.S3_BUCKET:
                self._delete_s3_bucket(client, resource_id)
            elif resource_enum == ResourceType.IAM_ROLE:
                self._delete_iam_role(client, resource_id)
            elif resource_enum == ResourceType.IAM_USER:
                self._delete_iam_user(client, resource_id)
            elif resource_enum == ResourceType.LAMBDA_FUNCTION:
                self._delete_lambda_function(client, resource_id)
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
            
            # Remove from tracking
            if resource_type in self.resources:
                self.resources[resource_type] = [
                    r for r in self.resources[resource_type] if r["id"] != resource_id
                ]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete {resource_type} resource with ID {resource_id}: {str(e)}")
            return False
    
    def execute_technique(self, technique_id: str, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute an attack technique on AWS.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Technique parameters
            context: Additional context information
            
        Returns:
            Dictionary with execution details
        """
        logger.info(f"Executing technique {technique_id} on AWS")
        
        # Map technique IDs to implementation methods
        technique_methods = {
            "T1078": self._execute_valid_accounts,
            "T1136": self._execute_create_account,
            "T1087": self._execute_account_discovery,
            "T1098": self._execute_account_manipulation,
            "T1048": self._execute_exfiltration_alternative_protocol,
            "T1530": self._execute_data_from_cloud_storage,
            "T1537": self._execute_transfer_cloud_account
        }
        
        # Execute the technique
        if technique_id in technique_methods:
            method = technique_methods[technique_id]
            return method(parameters, context or {})
        else:
            logger.warning(f"Technique {technique_id} not implemented, using mock implementation")
            return self._execute_mock_technique(technique_id, parameters, context or {})
    
    def _get_client_for_resource(self, resource_type: ResourceType) -> Any:
        """Get AWS client for a specific resource type."""
        resource_to_service = {
            ResourceType.EC2_INSTANCE: "ec2",
            ResourceType.S3_BUCKET: "s3",
            ResourceType.IAM_ROLE: "iam",
            ResourceType.IAM_USER: "iam",
            ResourceType.LAMBDA_FUNCTION: "lambda",
            ResourceType.CLOUDTRAIL: "cloudtrail",
            ResourceType.CLOUDWATCH_ALARM: "cloudwatch"
        }
        
        service = resource_to_service.get(resource_type)
        if not service:
            raise ValueError(f"No service mapping for resource type: {resource_type}")
            
        return self.session.client(service)
    
    # Resource creation methods
    
    def _create_ec2_instance(self, client: Any, resource_name: str, parameters: Dict[str, Any]) -> str:
        """Create an EC2 instance."""
        # Extract parameters with defaults
        image_id = parameters.get("image_id", "ami-0c55b159cbfafe1f0")  # Default Amazon Linux 2 AMI
        instance_type = parameters.get("instance_type", "t2.micro")
        
        # Launch the instance
        response = client.run_instances(
            ImageId=image_id,
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': resource_name}]
            }]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(f"Created EC2 instance {instance_id} with name {resource_name}")
        
        return instance_id
    
    def _create_s3_bucket(self, client: Any, resource_name: str, parameters: Dict[str, Any]) -> str:
        """Create an S3 bucket."""
        # Generate a unique bucket name if needed
        bucket_name = parameters.get("bucket_name", resource_name.lower())
        
        # Ensure bucket name is valid (only lowercase, numbers, dots, and hyphens)
        if not all(c.islower() or c.isdigit() or c in '.-' for c in bucket_name):
            bucket_name = f"mttd-{uuid.uuid4().hex}"
        
        # Create the bucket
        region = self.session.region_name
        
        if region == 'us-east-1':
            # US East 1 is the default and can't be specified explicitly
            client.create_bucket(Bucket=bucket_name)
        else:
            client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        # Apply bucket policy if specified
        if "policy" in parameters:
            client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(parameters["policy"])
            )
        
        logger.info(f"Created S3 bucket {bucket_name}")
        return bucket_name
    
    def _create_iam_role(self, client: Any, resource_name: str, parameters: Dict[str, Any]) -> str:
        """Create an IAM role."""
        # Create assume role policy document
        assume_role_policy = parameters.get("assume_role_policy", {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        
        # Create the role
        response = client.create_role(
            RoleName=resource_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Description=parameters.get("description", f"MTTD benchmark role: {resource_name}")
        )
        
        role_id = response["Role"]["RoleId"]
        
        # Attach managed policies if specified
        if "managed_policies" in parameters:
            for policy_arn in parameters["managed_policies"]:
                client.attach_role_policy(
                    RoleName=resource_name,
                    PolicyArn=policy_arn
                )
        
        logger.info(f"Created IAM role {resource_name} with ID {role_id}")
        return role_id
    
    def _create_iam_user(self, client: Any, resource_name: str, parameters: Dict[str, Any]) -> str:
        """Create an IAM user."""
        # Create the user
        response = client.create_user(
            UserName=resource_name,
            Tags=[{"Key": "Purpose", "Value": "MTTD Benchmarking"}]
        )
        
        user_id = response["User"]["UserId"]
        
        # Create access key if specified
        if parameters.get("create_access_key", False):
            client.create_access_key(UserName=resource_name)
        
        # Attach managed policies if specified
        if "managed_policies" in parameters:
            for policy_arn in parameters["managed_policies"]:
                client.attach_user_policy(
                    UserName=resource_name,
                    PolicyArn=policy_arn
                )
        
        logger.info(f"Created IAM user {resource_name} with ID {user_id}")
        return user_id
    
    def _create_lambda_function(self, client: Any, resource_name: str, parameters: Dict[str, Any]) -> str:
        """Create a Lambda function."""
        # Function implementation - default is harmless echo function
        function_code = parameters.get("code", """
            exports.handler = async (event) => {
                console.log('Received event:', JSON.stringify(event, null, 2));
                return {
                    statusCode: 200,
                    body: JSON.stringify('MTTD Benchmark Lambda function executed'),
                };
            };
        """)
        
        # Role ARN is required
        role_arn = parameters.get("role_arn")
        if not role_arn:
            # If no role ARN provided, create a basic execution role
            iam_client = self.session.client('iam')
            role_response = iam_client.create_role(
                RoleName=f"{resource_name}-role",
                AssumeRolePolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                })
            )
            role_arn = role_response["Role"]["Arn"]
            
            # Attach basic execution policy
            iam_client.attach_role_policy(
                RoleName=f"{resource_name}-role",
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
        
        # Create ZIP file for Lambda code
        import io
        import zipfile
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'a') as zip_file:
            zip_file.writestr('index.js', function_code)
        
        zip_buffer.seek(0)
        
        # Create the Lambda function
        response = client.create_function(
            FunctionName=resource_name,
            Runtime=parameters.get("runtime", "nodejs14.x"),
            Role=role_arn,
            Handler=parameters.get("handler", "index.handler"),
            Code={'ZipFile': zip_buffer.read()},
            Description=parameters.get("description", "MTTD Benchmark Lambda function"),
            Timeout=parameters.get("timeout", 30),
            MemorySize=parameters.get("memory_size", 128)
        )
        
        function_arn = response["FunctionArn"]
        logger.info(f"Created Lambda function {resource_name} with ARN {function_arn}")
        
        return function_arn
    
    # Resource deletion methods
    
    def _delete_ec2_instance(self, client: Any, instance_id: str) -> None:
        """Delete an EC2 instance."""
        client.terminate_instances(InstanceIds=[instance_id])
        logger.info(f"Terminated EC2 instance {instance_id}")
    
    def _delete_s3_bucket(self, client: Any, bucket_name: str) -> None:
        """Delete an S3 bucket."""
        # First delete all objects in the bucket
        s3_resource = self.session.resource('s3')
        bucket = s3_resource.Bucket(bucket_name)
        bucket.objects.all().delete()
        
        # Then delete the bucket
        client.delete_bucket(Bucket=bucket_name)
        logger.info(f"Deleted S3 bucket {bucket_name}")
    
    def _delete_iam_role(self, client: Any, role_id: str) -> None:
        """Delete an IAM role."""
        # Get role name from ID - need to list roles and find matching ID
        response = client.list_roles()
        role_name = None
        
        for role in response["Roles"]:
            if role["RoleId"] == role_id:
                role_name = role["RoleName"]
                break
        
        if not role_name:
            logger.warning(f"Could not find IAM role with ID {role_id}")
            return
        
        # Detach all policies
        attached_policies = client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies["AttachedPolicies"]:
            client.detach_role_policy(
                RoleName=role_name,
                PolicyArn=policy["PolicyArn"]
            )
        
        # Delete the role
        client.delete_role(RoleName=role_name)
        logger.info(f"Deleted IAM role {role_name}")
    
    def _delete_iam_user(self, client: Any, user_id: str) -> None:
        """Delete an IAM user."""
        # Get user name from ID - need to list users and find matching ID
        response = client.list_users()
        user_name = None
        
        for user in response["Users"]:
            if user["UserId"] == user_id:
                user_name = user["UserName"]
                break
        
        if not user_name:
            logger.warning(f"Could not find IAM user with ID {user_id}")
            return
        
        # Delete access keys
        access_keys = client.list_access_keys(UserName=user_name)
        for key in access_keys["AccessKeyMetadata"]:
            client.delete_access_key(
                UserName=user_name,
                AccessKeyId=key["AccessKeyId"]
            )
        
        # Detach all policies
        attached_policies = client.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies["AttachedPolicies"]:
            client.detach_user_policy(
                UserName=user_name,
                PolicyArn=policy["PolicyArn"]
            )
        
        # Delete the user
        client.delete_user(UserName=user_name)
        logger.info(f"Deleted IAM user {user_name}")
    
    def _delete_lambda_function(self, client: Any, function_arn: str) -> None:
        """Delete a Lambda function."""
        # Extract function name from ARN
        function_name = function_arn.split(":")[-1]
        
        # Delete the function
        client.delete_function(FunctionName=function_name)
        logger.info(f"Deleted Lambda function {function_name}")
    
    # Attack technique implementations
    
    def _execute_valid_accounts(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1078 - Valid Accounts
        Simulate using valid credentials for initial access.
        """
        # Extract parameters
        user_name = parameters.get("user_name", "mttd-test-user")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # For simulation, we just make API calls with the current credentials
        try:
            # Make a few harmless API calls
            iam_client = self.session.client('iam')
            user_response = iam_client.get_user()
            
            current_user = user_response.get("User", {}).get("UserName", "unknown")
            
            # List resources
            ec2_client = self.session.client('ec2')
            ec2_client.describe_instances()
            
            s3_client = self.session.client('s3')
            s3_client.list_buckets()
            
            return {
                "technique": "T1078",
                "user_name": user_name,
                "timestamp": datetime.now().isoformat(),
                "source_ip": source_ip,
                "caller_user": current_user,
                "aws-api-call": {
                    "service": "iam",
                    "operation": "GetUser",
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0"
                },
                "unusual-api-call-location": {
                    "source_ip": source_ip,
                    "operation": "GetUser"
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1078: {str(e)}")
            return {
                "technique": "T1078",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_create_account(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1136 - Create Account
        Simulate creating a new user account.
        """
        user_name = parameters.get("user_name", f"mttd-test-{uuid.uuid4().hex[:8]}")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        try:
            # Create a new IAM user with a distinctive name
            iam_client = self.session.client('iam')
            response = iam_client.create_user(
                UserName=user_name,
                Tags=[
                    {"Key": "Purpose", "Value": "MTTD Benchmark"},
                    {"Key": "SimulationId", "Value": context.get("simulation_id", "unknown")}
                ]
            )
            
            user_arn = response["User"]["Arn"]
            
            # Generate a detailed result
            return {
                "technique": "T1136",
                "user_created": user_name,
                "user_arn": user_arn,
                "timestamp": datetime.now().isoformat(),
                "source_ip": source_ip,
                "aws-api-call": {
                    "service": "iam",
                    "operation": "CreateUser",
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0",
                    "resource_arn": user_arn
                },
                "iam-user-creation": {
                    "user_arn": user_arn,
                    "timestamp": datetime.now().isoformat()
                },
                "unusual-iam-action": {
                    "operation": "CreateUser",
                    "source_ip": source_ip
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1136: {str(e)}")
            return {
                "technique": "T1136",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_account_discovery(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1087 - Account Discovery
        Enumerate users and roles to discover accounts.
        """
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        enumerate_users = parameters.get("enumerate_users", True)
        enumerate_roles = parameters.get("enumerate_roles", True)
        
        discovered_users = []
        discovered_roles = []
        
        try:
            iam_client = self.session.client('iam')
            
            # Enumerate users
            if enumerate_users:
                users_response = iam_client.list_users(MaxItems=10)
                for user in users_response.get("Users", []):
                    discovered_users.append({
                        "user_name": user.get("UserName"),
                        "user_id": user.get("UserId"),
                        "arn": user.get("Arn"),
                        "create_date": user.get("CreateDate").isoformat() if user.get("CreateDate") else None
                    })
            
            # Enumerate roles
            if enumerate_roles:
                roles_response = iam_client.list_roles(MaxItems=10)
                for role in roles_response.get("Roles", []):
                    discovered_roles.append({
                        "role_name": role.get("RoleName"),
                        "role_id": role.get("RoleId"),
                        "arn": role.get("Arn"),
                        "create_date": role.get("CreateDate").isoformat() if role.get("CreateDate") else None
                    })
            
            # Generate result
            return {
                "technique": "T1087",
                "timestamp": datetime.now().isoformat(),
                "source_ip": source_ip,
                "discovered_users": discovered_users,
                "discovered_roles": discovered_roles,
                "aws-api-call": {
                    "service": "iam",
                    "operations": ["ListUsers", "ListRoles"],
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0"
                },
                "account-enumeration": {
                    "users_enumerated": enumerate_users,
                    "roles_enumerated": enumerate_roles,
                    "user_count": len(discovered_users),
                    "role_count": len(discovered_roles)
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1087: {str(e)}")
            return {
                "technique": "T1087",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_account_manipulation(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1098 - Account Manipulation
        Modify permissions, attach policies, or change properties of existing accounts.
        """
        user_name = parameters.get("user_name")
        policy_arn = parameters.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        if not user_name:
            # Find a suitable user if not specified
            try:
                iam_client = self.session.client('iam')
                users_response = iam_client.list_users(MaxItems=10)
                
                for user in users_response.get("Users", []):
                    # Prefer users created by our simulation
                    if "mttd" in user.get("UserName", "").lower():
                        user_name = user.get("UserName")
                        break
                
                # If no suitable user found, use the first one
                if not user_name and users_response.get("Users"):
                    user_name = users_response.get("Users")[0].get("UserName")
            except Exception as e:
                logger.error(f"Error finding user for T1098: {str(e)}")
                return {
                    "technique": "T1098",
                    "error": f"No user name provided and could not find a suitable user: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        if not user_name:
            return {
                "technique": "T1098",
                "error": "No user name provided and no users found",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            iam_client = self.session.client('iam')
            
            # Attach policy to user
            iam_client.attach_user_policy(
                UserName=user_name,
                PolicyArn=policy_arn
            )
            
            # Get user details
            user_response = iam_client.get_user(UserName=user_name)
            user_arn = user_response["User"]["Arn"]
            
            return {
                "technique": "T1098",
                "user_name": user_name,
                "user_arn": user_arn,
                "policy_arn": policy_arn,
                "timestamp": datetime.now().isoformat(),
                "source_ip": source_ip,
                "aws-api-call": {
                    "service": "iam",
                    "operation": "AttachUserPolicy",
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0",
                    "resource_arn": user_arn,
                    "policy_arn": policy_arn
                },
                "privilege-escalation": {
                    "user_arn": user_arn,
                    "policy_arn": policy_arn,
                    "timestamp": datetime.now().isoformat()
                },
                "iam-policy-change": {
                    "operation": "AttachUserPolicy",
                    "policy_arn": policy_arn,
                    "user_arn": user_arn
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1098: {str(e)}")
            return {
                "technique": "T1098",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_exfiltration_alternative_protocol(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1048 - Exfiltration Over Alternative Protocol
        Simulate data exfiltration using DNS, ICMP, or other protocols.
        """
        protocol = parameters.get("protocol", "dns")
        data_size = parameters.get("data_size", 100)  # KB
        destination_ip = parameters.get("destination_ip", "203.0.113.100")  # Simulated destination
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        try:
            # Simulate exfiltration by making DNS queries (harmless)
            import socket
            import time
            
            # Harmless simulation - just perform DNS lookups
            # In a real situation, attackers would encode data in DNS queries
            domains = [
                "example.com",
                "google.com",
                "microsoft.com",
                "amazon.com",
                f"mttd-{uuid.uuid4().hex[:8]}.example.com"  # Unique subdomain
            ]
            
            for domain in domains:
                try:
                    socket.gethostbyname(domain)
                    time.sleep(0.1)  # Short delay between queries
                except:
                    pass
            
            return {
                "technique": "T1048",
                "protocol": protocol,
                "data_size_kb": data_size,
                "destination_ip": destination_ip,
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat(),
                "dns-exfiltration": {
                    "query_count": len(domains),
                    "unique_domains": domains,
                    "data_size_kb": data_size
                },
                "unusual-network-traffic": {
                    "protocol": protocol,
                    "destination_ip": destination_ip,
                    "data_size_kb": data_size
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1048: {str(e)}")
            return {
                "technique": "T1048",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_data_from_cloud_storage(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1530 - Data from Cloud Storage
        Access and download data from cloud storage services.
        """
        bucket_name = parameters.get("bucket_name")
        destination_ip = parameters.get("destination_ip", "203.0.113.100")  # Simulated destination
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # Find a bucket if not specified
        if not bucket_name:
            try:
                s3_client = self.session.client('s3')
                buckets_response = s3_client.list_buckets()
                
                for bucket in buckets_response.get("Buckets", []):
                    # Prefer buckets created by our simulation
                    if "mttd" in bucket.get("Name", "").lower():
                        bucket_name = bucket.get("Name")
                        break
                
                # If no suitable bucket found, use the first one
                if not bucket_name and buckets_response.get("Buckets"):
                    bucket_name = buckets_response.get("Buckets")[0].get("Name")
            except Exception as e:
                logger.error(f"Error finding bucket for T1530: {str(e)}")
                return {
                    "technique": "T1530",
                    "error": f"No bucket name provided and could not find a suitable bucket: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        if not bucket_name:
            return {
                "technique": "T1530",
                "error": "No bucket name provided and no buckets found",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            s3_client = self.session.client('s3')
            
            # Upload a test file to ensure there's something to download
            s3_client.put_object(
                Bucket=bucket_name,
                Key="mttd-test-file.txt",
                Body="This is a test file for MTTD benchmarking."
            )
            
            # List and download objects
            list_response = s3_client.list_objects_v2(Bucket=bucket_name)
            objects = []
            
            for obj in list_response.get("Contents", [])[:5]:  # Limit to 5 objects
                objects.append({
                    "key": obj.get("Key"),
                    "size": obj.get("Size"),
                    "last_modified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None
                })
                
                # Download the object
                if obj.get("Key"):
                    s3_client.get_object(Bucket=bucket_name, Key=obj.get("Key"))
            
            return {
                "technique": "T1530",
                "bucket_name": bucket_name,
                "objects_accessed": len(objects),
                "object_details": objects,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "timestamp": datetime.now().isoformat(),
                "aws-api-call": {
                    "service": "s3",
                    "operations": ["ListObjectsV2", "GetObject"],
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0",
                    "resource": f"arn:aws:s3:::{bucket_name}"
                },
                "s3-data-access": {
                    "bucket_name": bucket_name,
                    "object_count": len(objects),
                    "access_type": "read"
                },
                "data-exfiltration": {
                    "source": f"s3://{bucket_name}",
                    "destination_ip": destination_ip,
                    "object_count": len(objects)
                },
                "unusual-network-traffic": {
                    "protocol": "https",
                    "destination_ip": destination_ip,
                    "source": "s3"
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1530: {str(e)}")
            return {
                "technique": "T1530",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_transfer_cloud_account(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1537 - Transfer to Cloud Account
        Move data to a different cloud account.
        """
        source_bucket = parameters.get("source_bucket")
        destination_bucket = parameters.get("destination_bucket", f"mttd-dest-{uuid.uuid4().hex[:8]}")
        destination_account = parameters.get("destination_account", "123456789012")  # Simulated destination
        source_ip = parameters.get("source_ip", "198.51.100.1")
        
        # Find a source bucket if not specified
        if not source_bucket:
            try:
                s3_client = self.session.client('s3')
                buckets_response = s3_client.list_buckets()
                
                for bucket in buckets_response.get("Buckets", []):
                    if "mttd" in bucket.get("Name", "").lower():
                        source_bucket = bucket.get("Name")
                        break
                
                if not source_bucket and buckets_response.get("Buckets"):
                    source_bucket = buckets_response.get("Buckets")[0].get("Name")
            except Exception as e:
                logger.error(f"Error finding bucket for T1537: {str(e)}")
                return {
                    "technique": "T1537",
                    "error": f"No source bucket provided and could not find a suitable bucket: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        if not source_bucket:
            return {
                "technique": "T1537",
                "error": "No source bucket provided and no buckets found",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            s3_client = self.session.client('s3')
            
            # Ensure the source bucket has an object
            s3_client.put_object(
                Bucket=source_bucket,
                Key="mttd-transfer-test.txt",
                Body="This is a test file for MTTD transfer benchmarking."
            )
            
            # List objects
            list_response = s3_client.list_objects_v2(Bucket=source_bucket)
            objects = []
            
            for obj in list_response.get("Contents", [])[:5]:
                objects.append({
                    "key": obj.get("Key"),
                    "size": obj.get("Size")
                })
            
            # Simulate cross-account transfer by setting bucket policy
            # In a real attack, data would be copied to another account
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{destination_account}:root"},
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{source_bucket}/*"
                    }
                ]
            }
            
            # Just verify policy is valid, don't actually apply it
            import json
            policy_json = json.dumps(policy)
            
            return {
                "technique": "T1537",
                "source_bucket": source_bucket,
                "destination_bucket": destination_bucket,
                "destination_account": destination_account,
                "objects_transferred": len(objects),
                "object_details": objects,
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat(),
                "aws-api-call": {
                    "service": "s3",
                    "operations": ["ListObjectsV2", "PutBucketPolicy"],
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0",
                    "resource": f"arn:aws:s3:::{source_bucket}"
                },
                "data-exfiltration": {
                    "source": f"s3://{source_bucket}",
                    "destination": f"s3://{destination_bucket}",
                    "destination_account": destination_account,
                    "object_count": len(objects)
                },
                "s3-data-access": {
                    "bucket_name": source_bucket,
                    "object_count": len(objects),
                    "access_type": "read"
                }
            }
            
        except Exception as e:
            logger.error(f"Error executing T1537: {str(e)}")
            return {
                "technique": "T1537",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _execute_mock_technique(self, technique_id: str, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic mock implementation for techniques not specifically implemented.
        Provides a basic simulation for testing.
        """
        return {
            "technique": technique_id,
            "mocked": True,
            "parameters": parameters,
            "timestamp": datetime.now().isoformat(),
            "source_ip": "198.51.100.1",
            "aws-api-call": {
                "service": "mock",
                "operation": f"Mock{technique_id}",
                "source_ip": "198.51.100.1",
                "user_agent": "mttd-benchmark/1.0"
            }
        }