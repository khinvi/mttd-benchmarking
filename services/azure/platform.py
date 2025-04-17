"""
Azure Platform Client for creating resources and executing attack techniques.
"""

import logging
import uuid
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient

from ...core.types import ResourceType

logger = logging.getLogger(__name__)


class PlatformClient:
    """
    Client for interacting with Azure platform services.
    Handles environment setup, resource creation, and technique execution.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Azure platform client.
        
        Args:
            config: Azure configuration
        """
        self.config = config
        self.credentials = None
        self.subscription_id = config.get("subscription_id")
        self.resource_group = config.get("resource_group")
        self.region = config.get("region", "eastus")
        self.resources = {}
        self._initialize_credentials()
    
    def _initialize_credentials(self):
        """Initialize Azure credentials."""
        try:
            # Check if service principal credentials are provided
            tenant_id = self.config.get("tenant_id")
            client_id = self.config.get("client_id")
            client_secret = self.config.get("client_secret")
            
            if tenant_id and client_id and client_secret:
                # Use service principal authentication
                self.credentials = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                logger.info("Initialized Azure credentials using service principal")
            else:
                # Use default authentication
                self.credentials = DefaultAzureCredential()
                logger.info("Initialized Azure credentials using default authentication")
                
            # Validate credentials by creating a resource client
            if not self.subscription_id:
                raise ValueError("Subscription ID is required for Azure operations")
                
            resource_client = ResourceManagementClient(self.credentials, self.subscription_id)
            
            # Check if resource group exists or create it
            if self.resource_group:
                if not self._resource_group_exists(resource_client, self.resource_group):
                    logger.info(f"Creating resource group {self.resource_group} in {self.region}")
                    resource_client.resource_groups.create_or_update(
                        self.resource_group,
                        {"location": self.region}
                    )
            else:
                # Create a default resource group if none specified
                self.resource_group = f"mttd-benchmark-{uuid.uuid4().hex[:8]}"
                logger.info(f"Creating default resource group {self.resource_group} in {self.region}")
                resource_client.resource_groups.create_or_update(
                    self.resource_group,
                    {"location": self.region}
                )
                
            logger.info(f"Azure client initialized for subscription {self.subscription_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure credentials: {str(e)}")
            raise
    
    def _resource_group_exists(self, client: ResourceManagementClient, resource_group: str) -> bool:
        """
        Check if a resource group exists.
        
        Args:
            client: ResourceManagementClient
            resource_group: Name of the resource group
            
        Returns:
            True if the resource group exists, False otherwise
        """
        return client.resource_groups.check_existence(resource_group)
    
    def create_resource(self, resource_type: ResourceType, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an Azure resource.
        
        Args:
            resource_type: Type of resource to create
            resource_name: Name for the resource
            parameters: Resource parameters
            
        Returns:
            Resource ID
        """
        resource_id = None
        
        # Ensure we have credentials
        if not self.credentials:
            self._initialize_credentials()
        
        try:
            # Create the resource based on type
            if resource_type == ResourceType.VM:
                resource_id = self._create_virtual_machine(resource_name, parameters)
            elif resource_type == ResourceType.STORAGE_ACCOUNT:
                resource_id = self._create_storage_account(resource_name, parameters)
            elif resource_type == ResourceType.MANAGED_IDENTITY:
                resource_id = self._create_managed_identity(resource_name, parameters)
            elif resource_type == ResourceType.APP_SERVICE:
                resource_id = self._create_app_service(resource_name, parameters)
            elif resource_type == ResourceType.LOGIC_APP:
                resource_id = self._create_logic_app(resource_name, parameters)
            else:
                raise ValueError(f"Unsupported Azure resource type: {resource_type}")
            
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
        Delete an Azure resource.
        
        Args:
            resource_type: Type of resource to delete
            resource_id: ID of the resource
            
        Returns:
            True if successful, False otherwise
        """
        # Ensure we have credentials
        if not self.credentials:
            self._initialize_credentials()
        
        try:
            # Convert resource_type string to enum
            resource_enum = ResourceType(resource_type)
            
            # Delete the resource based on type
            if resource_enum == ResourceType.VM:
                self._delete_virtual_machine(resource_id)
            elif resource_enum == ResourceType.STORAGE_ACCOUNT:
                self._delete_storage_account(resource_id)
            elif resource_enum == ResourceType.MANAGED_IDENTITY:
                self._delete_managed_identity(resource_id)
            elif resource_enum == ResourceType.APP_SERVICE:
                self._delete_app_service(resource_id)
            elif resource_enum == ResourceType.LOGIC_APP:
                self._delete_logic_app(resource_id)
            else:
                raise ValueError(f"Unsupported Azure resource type: {resource_type}")
            
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
        Execute an attack technique on Azure.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Technique parameters
            context: Additional context information
            
        Returns:
            Dictionary with execution details
        """
        logger.info(f"Executing technique {technique_id} on Azure")
        
        # Map technique IDs to implementation methods
        technique_methods = {
            "T1078": self._execute_valid_accounts,
            "T1136": self._execute_create_account,
            "T1087": self._execute_account_discovery,
            "T1098": self._execute_account_manipulation,
            "T1528": self._execute_steal_app_access_token,
            "T1537": self._execute_transfer_cloud_account
        }
        
        # Execute the technique
        if technique_id in technique_methods:
            method = technique_methods[technique_id]
            return method(parameters, context or {})
        else:
            logger.warning(f"Technique {technique_id} not implemented, using mock implementation")
            return self._execute_mock_technique(technique_id, parameters, context or {})
    
    # Resource creation methods
    
    def _create_virtual_machine(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an Azure Virtual Machine.
        
        Args:
            resource_name: Name for the VM
            parameters: VM parameters
            
        Returns:
            VM ID
        """
        # Extract parameters with defaults
        vm_size = parameters.get("vm_size", "Standard_B1s")
        admin_username = parameters.get("admin_username", "mttdadmin")
        os_type = parameters.get("os_type", "Linux")
        
        # Create compute client
        compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
        network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        
        # Create a network interface
        nic_name = f"{resource_name}-nic"
        
        # First create a public IP
        public_ip_name = f"{resource_name}-ip"
        public_ip_parameters = {
            'location': self.region,
            'sku': {'name': 'Standard'},
            'public_ip_allocation_method': 'Static',
            'public_ip_address_version': 'IPV4'
        }
        
        logger.info(f"Creating public IP address {public_ip_name}")
        ip_op = network_client.public_ip_addresses.begin_create_or_update(
            self.resource_group,
            public_ip_name,
            public_ip_parameters
        )
        public_ip = ip_op.result()
        
        # Create a virtual network
        vnet_name = f"{resource_name}-vnet"
        vnet_parameters = {
            'location': self.region,
            'address_space': {
                'address_prefixes': ['10.0.0.0/16']
            }
        }
        
        logger.info(f"Creating virtual network {vnet_name}")
        network_client.virtual_networks.begin_create_or_update(
            self.resource_group,
            vnet_name,
            vnet_parameters
        ).result()
        
        # Create a subnet
        subnet_name = f"{resource_name}-subnet"
        subnet_parameters = {
            'address_prefix': '10.0.0.0/24'
        }
        
        logger.info(f"Creating subnet {subnet_name}")
        network_client.subnets.begin_create_or_update(
            self.resource_group,
            vnet_name,
            subnet_name,
            subnet_parameters
        ).result()
        
        # Get subnet info
        subnet = network_client.subnets.get(
            self.resource_group,
            vnet_name,
            subnet_name
        )
        
        # Create network interface
        nic_parameters = {
            'location': self.region,
            'ip_configurations': [{
                'name': f"{resource_name}-ipconfig",
                'subnet': {'id': subnet.id},
                'public_ip_address': {'id': public_ip.id}
            }]
        }
        
        logger.info(f"Creating network interface {nic_name}")
        nic_op = network_client.network_interfaces.begin_create_or_update(
            self.resource_group,
            nic_name,
            nic_parameters
        )
        nic = nic_op.result()
        
        # Create VM parameters
        if os_type.lower() == "linux":
            vm_parameters = {
                'location': self.region,
                'os_profile': {
                    'computer_name': resource_name,
                    'admin_username': admin_username,
                    'admin_password': f"Mttd{uuid.uuid4().hex[:16]}!"  # Complex password
                },
                'hardware_profile': {
                    'vm_size': vm_size
                },
                'storage_profile': {
                    'image_reference': {
                        'publisher': 'Canonical',
                        'offer': 'UbuntuServer',
                        'sku': '18.04-LTS',
                        'version': 'latest'
                    },
                    'os_disk': {
                        'name': f"{resource_name}-disk",
                        'caching': 'ReadWrite',
                        'create_option': 'FromImage',
                        'managed_disk': {
                            'storage_account_type': 'Standard_LRS'
                        }
                    }
                },
                'network_profile': {
                    'network_interfaces': [{
                        'id': nic.id
                    }]
                }
            }
        else:
            # Windows VM
            vm_parameters = {
                'location': self.region,
                'os_profile': {
                    'computer_name': resource_name,
                    'admin_username': admin_username,
                    'admin_password': f"Mttd{uuid.uuid4().hex[:16]}!"  # Complex password
                },
                'hardware_profile': {
                    'vm_size': vm_size
                },
                'storage_profile': {
                    'image_reference': {
                        'publisher': 'MicrosoftWindowsServer',
                        'offer': 'WindowsServer',
                        'sku': '2019-Datacenter',
                        'version': 'latest'
                    },
                    'os_disk': {
                        'name': f"{resource_name}-disk",
                        'caching': 'ReadWrite',
                        'create_option': 'FromImage',
                        'managed_disk': {
                            'storage_account_type': 'Standard_LRS'
                        }
                    }
                },
                'network_profile': {
                    'network_interfaces': [{
                        'id': nic.id
                    }]
                }
            }
        
        # Create VM
        logger.info(f"Creating virtual machine {resource_name}")
        vm_op = compute_client.virtual_machines.begin_create_or_update(
            self.resource_group,
            resource_name,
            vm_parameters
        )
        vm_result = vm_op.result()
        
        logger.info(f"Created virtual machine {resource_name} with ID {vm_result.id}")
        return vm_result.id
    
    def _create_storage_account(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an Azure Storage Account.
        
        Args:
            resource_name: Name for the storage account (lowercase alphanumeric)
            parameters: Storage account parameters
            
        Returns:
            Storage account ID
        """
        # Storage account names must be lowercase alphanumeric and 3-24 characters
        storage_name = resource_name.lower()
        storage_name = ''.join(c for c in storage_name if c.isalnum())
        
        if len(storage_name) < 3:
            storage_name = f"mttd{storage_name}"
        
        if len(storage_name) > 24:
            storage_name = storage_name[:24]
        
        # Extract parameters with defaults
        kind = parameters.get("kind", "StorageV2")
        sku_name = parameters.get("sku_name", "Standard_LRS")
        
        # Create storage client
        storage_client = StorageManagementClient(self.credentials, self.subscription_id)
        
        # Create storage account parameters
        storage_parameters = {
            'location': self.region,
            'kind': kind,
            'sku': {'name': sku_name}
        }
        
        # Create storage account
        logger.info(f"Creating storage account {storage_name}")
        storage_op = storage_client.storage_accounts.begin_create(
            self.resource_group,
            storage_name,
            storage_parameters
        )
        storage_result = storage_op.result()
        
        logger.info(f"Created storage account {storage_name} with ID {storage_result.id}")
        return storage_result.id
    
    def _create_managed_identity(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an Azure Managed Identity.
        
        This is a stub implementation that would need to be expanded
        with actual Azure SDK calls in a production system.
        
        Args:
            resource_name: Name for the managed identity
            parameters: Managed identity parameters
            
        Returns:
            Managed identity ID
        """
        # In a real implementation, this would use the appropriate Azure SDK client
        # For now, return a mock ID
        identity_id = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{resource_name}"
        logger.info(f"Created managed identity {resource_name} with ID {identity_id}")
        return identity_id
    
    def _create_app_service(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an Azure App Service.
        
        This is a stub implementation that would need to be expanded
        with actual Azure SDK calls in a production system.
        
        Args:
            resource_name: Name for the app service
            parameters: App service parameters
            
        Returns:
            App service ID
        """
        # In a real implementation, this would use the WebSiteManagementClient
        # For now, return a mock ID
        app_service_id = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Web/sites/{resource_name}"
        logger.info(f"Created app service {resource_name} with ID {app_service_id}")
        return app_service_id
    
    def _create_logic_app(self, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create an Azure Logic App.
        
        This is a stub implementation that would need to be expanded
        with actual Azure SDK calls in a production system.
        
        Args:
            resource_name: Name for the logic app
            parameters: Logic app parameters
            
        Returns:
            Logic app ID
        """
        # In a real implementation, this would use the LogicManagementClient
        # For now, return a mock ID
        logic_app_id = f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Logic/workflows/{resource_name}"
        logger.info(f"Created logic app {resource_name} with ID {logic_app_id}")
        return logic_app_id
    
    # Resource deletion methods
    
    def _delete_virtual_machine(self, vm_id: str) -> None:
        """Delete an Azure VM."""
        # Extract resource name from ID
        # Azure resource IDs have format: /subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Compute/virtualMachines/{vmName}
        parts = vm_id.split('/')
        if len(parts) < 9:
            logger.warning(f"Invalid VM ID format: {vm_id}")
            return
        
        vm_name = parts[-1]
        
        # Create compute client
        compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
        network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        
        # Delete VM
        logger.info(f"Deleting virtual machine {vm_name}")
        compute_client.virtual_machines.begin_delete(self.resource_group, vm_name).wait()
        
        # Delete associated resources
        nic_name = f"{vm_name}-nic"
        public_ip_name = f"{vm_name}-ip"
        vnet_name = f"{vm_name}-vnet"
        
        try:
            # Delete NIC
            logger.info(f"Deleting network interface {nic_name}")
            network_client.network_interfaces.begin_delete(self.resource_group, nic_name).wait()
            
            # Delete public IP
            logger.info(f"Deleting public IP address {public_ip_name}")
            network_client.public_ip_addresses.begin_delete(self.resource_group, public_ip_name).wait()
            
            # Delete virtual network
            logger.info(f"Deleting virtual network {vnet_name}")
            network_client.virtual_networks.begin_delete(self.resource_group, vnet_name).wait()
        except Exception as e:
            logger.warning(f"Error deleting VM resources: {str(e)}")
    
    def _delete_storage_account(self, storage_id: str) -> None:
        """Delete an Azure Storage Account."""
        # Extract resource name from ID
        parts = storage_id.split('/')
        if len(parts) < 9:
            logger.warning(f"Invalid storage account ID format: {storage_id}")
            return
        
        storage_name = parts[-1]
        
        # Create storage client
        storage_client = StorageManagementClient(self.credentials, self.subscription_id)
        
        # Delete storage account
        logger.info(f"Deleting storage account {storage_name}")
        storage_client.storage_accounts.delete(self.resource_group, storage_name)
    
    def _delete_managed_identity(self, identity_id: str) -> None:
        """Delete an Azure Managed Identity."""
        # This is a stub implementation that would need to be expanded
        logger.info(f"Deleting managed identity {identity_id}")
        # In a real implementation, this would use the appropriate Azure SDK client
    
    def _delete_app_service(self, app_service_id: str) -> None:
        """Delete an Azure App Service."""
        # This is a stub implementation that would need to be expanded
        logger.info(f"Deleting app service {app_service_id}")
        # In a real implementation, this would use the WebSiteManagementClient
    
    def _delete_logic_app(self, logic_app_id: str) -> None:
        """Delete an Azure Logic App."""
        # This is a stub implementation that would need to be expanded
        logger.info(f"Deleting logic app {logic_app_id}")
        # In a real implementation, this would use the LogicManagementClient
    
    # Attack technique implementations
    
    def _execute_valid_accounts(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1078 - Valid Accounts
        Simulate using valid credentials for initial access.
        """
        # Extract parameters
        user_name = parameters.get("user_name", "mttd-test-user")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # For simulation, we just make harmless API calls
        resource_client = ResourceManagementClient(self.credentials, self.subscription_id)
        
        # List resource groups to simulate activity
        resource_groups = list(resource_client.resource_groups.list())
        
        return {
            "technique": "T1078",
            "user_name": user_name,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "azure-api-call": {
                "service": "ResourceManagementClient",
                "operation": "ListResourceGroups",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "unusual-api-call-location": {
                "source_ip": source_ip,
                "operation": "ListResourceGroups"
            }
        }
    
    def _execute_create_account(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1136 - Create Account
        Simulate creating a new user account.
        """
        user_name = parameters.get("user_name", f"mttd-test-{uuid.uuid4().hex[:8]}")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # This is a simulated technique - in a real implementation,
        # this would use the GraphClient to create users
        
        user_id = f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}"
        
        return {
            "technique": "T1136",
            "user_created": user_name,
            "user_id": user_id,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "azure-api-call": {
                "service": "GraphClient",
                "operation": "CreateUser",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "azure-user-creation": {
                "user_id": user_id,
                "timestamp": datetime.now().isoformat()
            },
            "unusual-user-activity": {
                "operation": "CreateUser",
                "source_ip": source_ip
            }
        }
    
    def _execute_account_discovery(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1087 - Account Discovery
        Enumerate users and roles to discover accounts.
        """
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # This is a simulated technique - in a real implementation,
        # this would use the GraphClient to enumerate users
        
        # Generate mock discovered users
        discovered_users = []
        for i in range(5):
            discovered_users.append({
                "user_name": f"user{i+1}@example.com",
                "user_id": f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}",
                "display_name": f"User {i+1}",
                "created_date": datetime.now().isoformat()
            })
        
        return {
            "technique": "T1087",
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "discovered_users": discovered_users,
            "azure-api-call": {
                "service": "GraphClient",
                "operations": ["ListUsers"],
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "account-enumeration": {
                "users_enumerated": True,
                "user_count": len(discovered_users)
            }
        }
    
    def _execute_account_manipulation(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1098 - Account Manipulation
        Modify permissions or change properties of existing accounts.
        """
        user_name = parameters.get("user_name", "mttd-test-user")
        role_name = parameters.get("role_name", "Owner")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # This is a simulated technique - in a real implementation,
        # this would use the appropriate client to modify roles
        
        user_id = f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}"
        
        return {
            "technique": "T1098",
            "user_name": user_name,
            "role_name": role_name,
            "user_id": user_id,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "azure-api-call": {
                "service": "AuthorizationManagementClient",
                "operation": "RoleAssignments.Create",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "privilege-escalation": {
                "user_id": user_id,
                "role_name": role_name,
                "timestamp": datetime.now().isoformat()
            },
            "role-assignment-change": {
                "operation": "RoleAssignments.Create",
                "role_name": role_name,
                "user_id": user_id
            }
        }
    
    def _execute_steal_app_access_token(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1528 - Steal Application Access Token
        Simulate stealing application access tokens.
        """
        app_name = parameters.get("app_name", "mttd-test-app")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # This is a simulated technique - in a real implementation,
        # this would simulate token theft in a safe way
        
        app_id = f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}"
        
        return {
            "technique": "T1528",
            "app_name": app_name,
            "app_id": app_id,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "azure-api-call": {
                "service": "GraphClient",
                "operation": "Applications.Get",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "token-access": {
                "app_id": app_id,
                "timestamp": datetime.now().isoformat()
            },
            "unusual-app-activity": {
                "operation": "TokenRequest",
                "source_ip": source_ip,
                "app_id": app_id
            }
        }
    
    def _execute_transfer_cloud_account(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        T1537 - Transfer to Cloud Account
        Move data to a different cloud account.
        """
        source_account = parameters.get("source_account", "source-account")
        destination_account = parameters.get("destination_account", "destination-account")
        source_ip = parameters.get("source_ip", "198.51.100.1")  # Simulated source
        
        # This is a simulated technique - in a real implementation,
        # this would simulate data transfer in a safe way
        
        storage_name = f"mttd{uuid.uuid4().hex[:8]}"
        
        return {
            "technique": "T1537",
            "source_account": source_account,
            "destination_account": destination_account,
            "storage_name": storage_name,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "azure-api-call": {
                "service": "StorageManagementClient",
                "operation": "StorageAccounts.ListKeys",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            },
            "data-exfiltration": {
                "source": source_account,
                "destination": destination_account,
                "storage_name": storage_name
            },
            "unusual-storage-activity": {
                "operation": "BlobCopy",
                "source_ip": source_ip,
                "storage_name": storage_name
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
            "azure-api-call": {
                "service": "mock",
                "operation": f"Mock{technique_id}",
                "source_ip": "198.51.100.1",
                "user_agent": "mttd-benchmark/1.0"
            }
        }