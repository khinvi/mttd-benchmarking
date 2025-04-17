"""
Google Cloud Platform (GCP) client for creating resources and executing attack techniques.
"""

import logging
import uuid
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

from ...core.types import ResourceType

logger = logging.getLogger(__name__)

# Try to import GCP libraries - handle gracefully if not available
try:
    from google.cloud import compute_v1
    from google.cloud import storage
    from google.cloud import iam_admin_v1
    from google.cloud import functions_v1
    from google.api_core.exceptions import GoogleAPIError
    GCP_LIBRARIES_AVAILABLE = True
except ImportError:
    logger.warning("Google Cloud libraries not available. Using mock implementations.")
    GCP_LIBRARIES_AVAILABLE = False


class PlatformClient:
    """
    Client for interacting with GCP platform services.
    Handles environment setup, resource creation, and technique execution.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the GCP platform client.
        
        Args:
            config: GCP configuration
        """
        self.config = config
        self.project_id = config.get("project_id")
        self.region = config.get("region", "us-central1")
        self.zone = config.get("zone", f"{self.region}-a")
        self.resources = {}
        
        # Check and set credentials
        self.credentials_file = config.get("credentials_file")
        if self.credentials_file:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials_file
            
        # Validate configuration
        if not self.project_id:
            raise ValueError("GCP project ID is required")
            
        logger.info(f"Initialized GCP client for project {self.project_id} in region {self.region}")
    
    def create_resource(self, resource_type: ResourceType, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create a GCP resource.
        
        Args:
            resource_type: Type of resource to create
            resource_name: Name for the resource
            parameters: Resource parameters
            
        Returns:
            Resource ID
        """
        logger.info(f"Creating GCP {resource_type.value} resource: {resource_name}")
        
        # If GCP libraries aren't available, use mock implementations
        if not GCP_LIBRARIES_AVAILABLE:
            return self._create_mock_resource(resource_type, resource_name, parameters)
        
        resource_id = None
        
        try:
            # Create resource based on type
            if resource_type == ResourceType.COMPUTE_INSTANCE:
                resource_id = self._create_compute_instance(resource_name, parameters)
            elif resource_type == ResourceType.STORAGE_BUCKET:
                resource_id = self._create_storage_bucket(resource_name, parameters)
            elif resource_type == ResourceType.IAM_SERVICE_ACCOUNT:
                resource_id = self._create_service_account(resource_name, parameters)
            elif resource_type == ResourceType.CLOUD_FUNCTION:
                resource_id = self._create_cloud_function(resource_name, parameters)
            else:
                raise ValueError(f"Unsupported GCP resource type: {resource_type}")
            
            # Track created resource
            if resource_type.value not in self.resources:
                self.resources[resource_type.value] = []
                
            self.resources[resource_type.value].append({
                "id": resource_id,
                "name": resource_name,
                "parameters": parameters
            })
            
            logger.info(f"Created GCP resource {resource_name} with ID {resource_id}")
            return resource_id
            
        except Exception as e:
            logger.error(f"Failed to create {resource_type.value} resource: {str(e)}")
            raise
    
    def _create_mock_resource(self, resource_type: ResourceType, resource_name: str, parameters: Dict[str, Any]) -> str:
        """Create a mock resource when GCP libraries aren't available."""
        # Generate a mock resource ID
        if resource_type == ResourceType.COMPUTE_INSTANCE:
            resource_id = f"projects/{self.project_id}/zones/{self.zone}/instances/{resource_name}"
        elif resource_type == ResourceType.STORAGE_BUCKET:
            resource_id = f"projects/{self.project_id}/buckets/{resource_name}"
        elif resource_type == ResourceType.IAM_SERVICE_ACCOUNT:
            resource_id = f"projects/{self.project_id}/serviceAccounts/{resource_name}@{self.project_id}.iam.gserviceaccount.com"
        elif resource_type == ResourceType.CLOUD_FUNCTION:
            resource_id = f"projects/{self.project_id}/locations/{self.region}/functions/{resource_name}"
        else:
            resource_id = f"projects/{self.project_id}/{resource_type.value}/{resource_name}-{uuid.uuid4().hex[:8]}"
        
        # Track created resource
        if resource_type.value not in self.resources:
            self.resources[resource_type.value] = []
            
        self.resources[resource_type.value].append({
            "id": resource_id,
            "name": resource_name,
            "parameters": parameters
        })
        
        logger.info(f"Created mock GCP resource {resource_name} with ID {resource_id}")
        return resource_id
    
    def _create_compute_instance(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create a GCP Compute Engine instance.
        
        Args:
            resource_name: Name for the instance
            parameters: VM parameters
            
        Returns:
            Instance ID
        """
        # Extract parameters with defaults
        machine_type = parameters.get("machine_type", "e2-micro")
        image_project = parameters.get("image_project", "debian-cloud")
        image_family = parameters.get("image_family", "debian-11")
        
        # Create the instance
        instance_client = compute_v1.InstancesClient()
        
        # Get the latest image
        image_client = compute_v1.ImagesClient()
        image = image_client.get_from_family(project=image_project, family=image_family)
        
        # Prepare the instance configuration
        instance = {
            "name": resource_name,
            "machine_type": f"zones/{self.zone}/machineTypes/{machine_type}",
            "disks": [
                {
                    "boot": True,
                    "auto_delete": True,
                    "initialize_params": {
                        "source_image": image.self_link
                    }
                }
            ],
            "network_interfaces": [
                {
                    "network": "global/networks/default",
                    "access_configs": [
                        {
                            "name": "External NAT",
                            "type": "ONE_TO_ONE_NAT"
                        }
                    ]
                }
            ]
        }
        
        # Create the instance
        operation = instance_client.insert(
            project=self.project_id,
            zone=self.zone,
            instance_resource=instance
        )
        
        # Wait for the operation to complete
        operation.result()
        
        # Return the instance ID
        return f"projects/{self.project_id}/zones/{self.zone}/instances/{resource_name}"
    
    def _create_storage_bucket(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create a GCP Cloud Storage bucket.
        
        Args:
            resource_name: Name for the bucket
            parameters: Bucket parameters
            
        Returns:
            Bucket ID
        """
        # Extract parameters with defaults
        location = parameters.get("location", self.region)
        storage_class = parameters.get("storage_class", "STANDARD")
        
        # Create the bucket
        storage_client = storage.Client()
        bucket = storage_client.create_bucket(resource_name, location=location)
        
        # Return the bucket ID
        return f"projects/{self.project_id}/buckets/{resource_name}"
    
    def _create_service_account(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create a GCP IAM service account.
        
        Args:
            resource_name: Name for the service account
            parameters: Service account parameters
            
        Returns:
            Service account ID
        """
        # Extract parameters with defaults
        display_name = parameters.get("display_name", f"MTTD Benchmark SA: {resource_name}")
        
        # Create the service account
        iam_client = iam_admin_v1.IAMClient()
        
        # The email will be resource_name@project_id.iam.gserviceaccount.com
        service_account = iam_client.create_service_account(
            request={
                "name": f"projects/{self.project_id}",
                "account_id": resource_name,
                "service_account": {
                    "display_name": display_name
                }
            }
        )
        
        # Return the service account ID
        return service_account.name
    
    def _create_cloud_function(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create a GCP Cloud Function.
        
        Args:
            resource_name: Name for the function
            parameters: Function parameters
            
        Returns:
            Function ID
        """
        # This is a simplified implementation - in a real system, we would need
        # to handle source code uploads, triggers, etc.
        
        # Extract parameters with defaults
        runtime = parameters.get("runtime", "python310")
        entry_point = parameters.get("entry_point", "hello_world")
        
        # Create a mock function ID
        function_id = f"projects/{self.project_id}/locations/{self.region}/functions/{resource_name}"
        
        logger.info(f"Created mock Cloud Function with ID {function_id}")
        return function_id
    
    def delete_resource(self, resource_type: str, resource_id: str) -> bool:
        """
        Delete a GCP resource.
        
        Args:
            resource_type: Type of resource to delete
            resource_id: ID of the resource
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting GCP {resource_type} resource: {resource_id}")
        
        # If GCP libraries aren't available, just remove from tracking
        if not GCP_LIBRARIES_AVAILABLE:
            if resource_type in self.resources:
                self.resources[resource_type] = [
                    r for r in self.resources[resource_type] if r["id"] != resource_id
                ]
            return True
        
        try:
            # Convert resource_type string to enum
            resource_enum = ResourceType(resource_type)
            
            # Delete resource based on type
            if resource_enum == ResourceType.COMPUTE_INSTANCE:
                self._delete_compute_instance(resource_id)
            elif resource_enum == ResourceType.STORAGE_BUCKET:
                self._delete_storage_bucket(resource_id)
            elif resource_enum == ResourceType.IAM_SERVICE_ACCOUNT:
                self._delete_service_account(resource_id)
            elif resource_enum == ResourceType.CLOUD_FUNCTION:
                self._delete_cloud_function(resource_id)
            else:
                raise ValueError(f"Unsupported GCP resource type: {resource_type}")
                
            # Remove from tracking
            if resource_type in self.resources:
                self.resources[resource_type] = [
                    r for r in self.resources[resource_type] if r["id"] != resource_id
                ]
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete {resource_type} resource {resource_id}: {str(e)}")
            return False
    
    def _delete_compute_instance(self, instance_id: str) -> None:
        """Delete a Compute Engine instance."""
        # Parse the instance ID to get the name
        parts = instance_id.split('/')
        if len(parts) < 5:
            logger.warning(f"Invalid instance ID format: {instance_id}")
            return
            
        instance_name = parts[-1]
        
        # Delete the instance
        instance_client = compute_v1.InstancesClient()
        operation = instance_client.delete(
            project=self.project_id,
            zone=self.zone,
            instance=instance_name
        )
        
        # Wait for the operation to complete
        operation.result()
        
        logger.info(f"Deleted Compute Engine instance {instance_name}")
    
    def _delete_storage_bucket(self, bucket_id: str) -> None:
        """Delete a Cloud Storage bucket."""
        # Parse the bucket ID to get the name
        parts = bucket_id.split('/')
        if len(parts) < 4:
            logger.warning(f"Invalid bucket ID format: {bucket_id}")
            return
            
        bucket_name = parts[-1]
        
        # Delete the bucket
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(bucket_name)
        
        # Delete all objects in the bucket first
        blobs = bucket.list_blobs()
        for blob in blobs:
            blob.delete()
            
        # Delete the bucket
        bucket.delete()
        
        logger.info(f"Deleted Cloud Storage bucket {bucket_name}")
    
    def _delete_service_account(self, service_account_id: str) -> None:
        """Delete an IAM service account."""
        # Service account ID is already in the format needed by the API
        iam_client = iam_admin_v1.IAMClient()
        iam_client.delete_service_account(name=service_account_id)
        
        logger.info(f"Deleted IAM service account {service_account_id}")
    
    def _delete_cloud_function(self, function_id: str) -> None:
        """Delete a Cloud Function."""
        functions_client = functions_v1.CloudFunctionsServiceClient()
        operation = functions_client.delete_function(name=function_id)
        
        # Wait for the operation to complete
        operation.result()
        
        logger.info(f"Deleted Cloud Function {function_id}")
    
    def execute_technique(self, technique_id: str, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute an attack technique on GCP.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Technique parameters
            context: Additional context information
            
        Returns:
            Dictionary with execution details
        """
        logger.info(f"Executing technique {technique_id} on GCP")
        
        # Map technique IDs to implementation methods
        technique_methods = {
            "T1078": self._execute_valid_accounts,
            "T1136": self._execute_create_account,
            "T1087": self._execute_account_discovery,
            "T1098": self._execute_account_manipulation,
            "T1525": self._execute_implant_container_image,
            "T1537": self._execute_transfer_cloud_account
        }
        
        # Execute the technique
        if technique_id in technique_methods:
            method = technique_methods[technique_id]
            return method(parameters, context or {})
        else:
            logger.warning(f"Technique {technique_id} not implemented, using mock implementation")
            return self._execute_mock_technique(technique_id, parameters, context or {})
    
    # Attack technique implementations
    
    def _execute_valid_accounts(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1078 - Valid Accounts
        Simulate using valid credentials for initial access.
        """
        # Extract parameters
        user_name = parameters.get("user_name", "mttd-test-user")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # For simulation, we just log the activity
        logger.info(f"Simulating technique T1078 - Using valid account {user_name}")
        
        return {
            "technique": "T1078",
            "user_name": user_name,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "gcp-api-call": {
                "service": "IAM",
                "method": "GetIamPolicy",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "unusual-api-call-location": {
                "source_ip": source_ip,
                "method": "GetIamPolicy"
            }
        }
    
    def _execute_create_account(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1136 - Create Account
        Simulate creating a new service account.
        """
        # Extract parameters
        account_name = parameters.get("account_name", f"mttd-test-{uuid.uuid4().hex[:8]}")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        logger.info(f"Simulating technique T1136 - Creating account {account_name}")
        
        # For simulation, we don't actually create a real service account
        account_id = f"projects/{self.project_id}/serviceAccounts/{account_name}@{self.project_id}.iam.gserviceaccount.com"
        
        return {
            "technique": "T1136",
            "account_name": account_name,
            "account_id": account_id,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "gcp-api-call": {
                "service": "IAM",
                "method": "CreateServiceAccount",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "account-creation": {
                "account_id": account_id,
                "timestamp": datetime.now().isoformat()
            },
            "unusual-activity": {
                "method": "CreateServiceAccount",
                "source_ip": source_ip
            }
        }
    
    def _execute_account_discovery(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1087 - Account Discovery
        Enumerate service accounts and roles.
        """
        # Extract parameters
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        logger.info(f"Simulating technique T1087 - Account discovery")
        
        # For simulation, we generate fictitious discovery results
        discovered_accounts = []
        for i in range(5):
            discovered_accounts.append({
                "name": f"sa-{i}@{self.project_id}.iam.gserviceaccount.com",
                "id": f"projects/{self.project_id}/serviceAccounts/sa-{i}@{self.project_id}.iam.gserviceaccount.com",
                "display_name": f"Service Account {i}"
            })
        
        return {
            "technique": "T1087",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "discovered_accounts": discovered_accounts,
            "gcp-api-call": {
                "service": "IAM",
                "method": "ListServiceAccounts",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "account-enumeration": {
                "count": len(discovered_accounts),
                "timestamp": datetime.now().isoformat()
            }
        }
    
    def _execute_account_manipulation(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1098 - Account Manipulation
        Modify permissions or IAM policies.
        """
        # Extract parameters
        account_name = parameters.get("account_name", "mttd-test-account")
        role = parameters.get("role", "roles/owner")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        logger.info(f"Simulating technique T1098 - Account manipulation for {account_name}")
        
        # For simulation, we don't actually modify IAM policies
        account_id = f"projects/{self.project_id}/serviceAccounts/{account_name}@{self.project_id}.iam.gserviceaccount.com"
        
        return {
            "technique": "T1098",
            "account_name": account_name,
            "account_id": account_id,
            "role": role,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "gcp-api-call": {
                "service": "IAM",
                "method": "SetIamPolicy",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "privilege-escalation": {
                "account_id": account_id,
                "role": role,
                "timestamp": datetime.now().isoformat()
            },
            "policy-change": {
                "method": "SetIamPolicy",
                "role": role,
                "account_id": account_id
            }
        }
    
    def _execute_implant_container_image(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1525 - Implant Container Image
        Simulate implanting a container image with malicious code.
        """
        # Extract parameters
        repository = parameters.get("repository", "gcr.io/mttd-project/images")
        image = parameters.get("image", "app-image")
        tag = parameters.get("tag", "latest")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        logger.info(f"Simulating technique T1525 - Implanting container image {repository}/{image}:{tag}")
        
        # For simulation, we don't actually modify container images
        image_url = f"{repository}/{image}:{tag}"
        
        return {
            "technique": "T1525",
            "repository": repository,
            "image": image,
            "tag": tag,
            "image_url": image_url,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "gcp-api-call": {
                "service": "Container Registry",
                "method": "DockerPush",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "malicious-image": {
                "image_url": image_url,
                "timestamp": datetime.now().isoformat()
            },
            "unusual-activity": {
                "method": "DockerPush",
                "source_ip": source_ip,
                "image_url": image_url
            }
        }
    
    def _execute_transfer_cloud_account(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1537 - Transfer to Cloud Account
        Simulate transferring data to another cloud account.
        """
        # Extract parameters
        source_bucket = parameters.get("source_bucket", "mttd-source-bucket")
        destination_bucket = parameters.get("destination_bucket", "external-destination-bucket")
        data_size = parameters.get("data_size", 100)  # MB
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        logger.info(f"Simulating technique T1537 - Transferring data from {source_bucket} to {destination_bucket}")
        
        return {
            "technique": "T1537",
            "source_bucket": source_bucket,
            "destination_bucket": destination_bucket,
            "data_size_mb": data_size,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "gcp-api-call": {
                "service": "Storage",
                "method": "CopyObject",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "data-exfiltration": {
                "source": f"gs://{source_bucket}",
                "destination": f"gs://{destination_bucket}",
                "data_size_mb": data_size
            },
            "unusual-storage-activity": {
                "method": "CopyObject",
                "source_ip": source_ip,
                "source_bucket": source_bucket,
                "destination_bucket": destination_bucket
            }
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
            "gcp-api-call": {
                "service": "mock",
                "method": f"Mock{technique_id}",
                "source_ip": "198.51.100.1",
                "user_agent": "mttd-benchmark/1.0"
            }
        }