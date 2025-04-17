"""
Azure Sentinel security service client.
"""

import logging
import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.mgmt.securityinsight.models import (
    AlertRule,
    FusionAlertRule,
    MicrosoftSecurityIncidentCreationAlertRule,
    ScheduledAlertRule
)

logger = logging.getLogger(__name__)


class SecurityClient:
    """
    Client for monitoring Azure Sentinel security events.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Sentinel security client.
        
        Args:
            config: Sentinel configuration
        """
        self.config = config
        self.credentials = None
        self.subscription_id = config.get("subscription_id")
        self.resource_group = config.get("resource_group")
        self.workspace_id = config.get("workspace_id")
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
                
            # Validate credentials
            if not self.subscription_id:
                raise ValueError("Subscription ID is required for Azure Sentinel operations")
                
            if not self.resource_group:
                raise ValueError("Resource group is required for Azure Sentinel operations")
                
            if not self.workspace_id:
                raise ValueError("Log Analytics workspace ID is required for Azure Sentinel operations")
                
            # Initialize Sentinel client
            self.sentinel_client = SecurityInsights(
                credential=self.credentials,
                subscription_id=self.subscription_id
            )
            
            logger.info(f"Azure Sentinel client initialized for subscription {self.subscription_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure Sentinel credentials: {str(e)}")
            raise
    
    def get_security_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get Sentinel alerts within a time range.
        
        Args:
            start_time: Start time for alerts
            end_time: End time for alerts
            
        Returns:
            List of Sentinel alerts
        """
        events = []
        
        # Ensure we have credentials
        if not self.credentials:
            try:
                self._initialize_credentials()
            except Exception as e:
                logger.error(f"Failed to initialize credentials: {str(e)}")
                return events
        
        try:
            # List incidents
            incidents = list(self.sentinel_client.incidents.list(
                self.resource_group,
                self.workspace_id
            ))
            
            # Filter incidents by time
            for incident in incidents:
                # Extract creation time and convert to datetime
                created_time = None
                if incident.created_time_utc:
                    if isinstance(incident.created_time_utc, str):
                        created_time = datetime.fromisoformat(incident.created_time_utc.replace('Z', '+00:00'))
                    else:
                        created_time = incident.created_time_utc
                
                # Skip incidents outside the time range
                if not created_time or created_time < start_time or created_time > end_time:
                    continue
                
                # Convert incident to a dictionary
                incident_dict = {
                    "id": incident.name,
                    "title": incident.title,
                    "description": incident.description,
                    "severity": incident.severity,
                    "status": incident.status,
                    "timestamp": created_time.isoformat(),
                    "labels": [label.label_name for label in (incident.labels or [])],
                    "eventType": "Incident",
                    "_mttd_service": "azure_sentinel",
                    "relatedAlerts": []
                }
                
                # Get incident entities
                try:
                    entities = list(self.sentinel_client.incident_entities.list(
                        self.resource_group,
                        self.workspace_id,
                        incident.name
                    ))
                    
                    # Add entities to incident
                    incident_dict["entities"] = [
                        {
                            "type": entity.kind,
                            "name": getattr(entity, "friendly_name", None) or getattr(entity, "host_name", None) or getattr(entity, "account_name", None) or "Unknown",
                            "properties": self._extract_entity_properties(entity)
                        }
                        for entity in entities
                    ]
                except Exception as entity_e:
                    logger.warning(f"Failed to get entities for incident {incident.name}: {str(entity_e)}")
                
                # Add to events list
                events.append(incident_dict)
            
            logger.info(f"Retrieved {len(events)} Sentinel incidents")
            return events
            
        except Exception as e:
            logger.error(f"Failed to get Sentinel incidents: {str(e)}")
            return events
    
    def _extract_entity_properties(self, entity: Any) -> Dict[str, Any]:
        """
        Extract properties from an entity object.
        
        Args:
            entity: Entity object
            
        Returns:
            Dictionary of entity properties
        """
        properties = {}
        
        # Check entity type and extract relevant properties
        if entity.kind == "Account":
            if hasattr(entity, "account_name"):
                properties["account_name"] = entity.account_name
            if hasattr(entity, "user_principal_name"):
                properties["user_principal_name"] = entity.user_principal_name
            if hasattr(entity, "directory_role_id"):
                properties["directory_role_id"] = entity.directory_role_id
        
        elif entity.kind == "Host":
            if hasattr(entity, "host_name"):
                properties["host_name"] = entity.host_name
            if hasattr(entity, "netbios_name"):
                properties["netbios_name"] = entity.netbios_name
            if hasattr(entity, "os"):
                properties["os"] = entity.os
            if hasattr(entity, "private_ip_addresses"):
                properties["private_ip_addresses"] = entity.private_ip_addresses
        
        elif entity.kind == "IP":
            if hasattr(entity, "address"):
                properties["address"] = entity.address
            if hasattr(entity, "location"):
                properties["location"] = {
                    "country": entity.location.country_name if entity.location else None,
                    "city": entity.location.city if entity.location else None
                }
        
        # Add additional properties as needed for other entity types
        
        return properties
    
    def create_sample_alert(
        self, 
        technique_id: str, 
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a sample alert for testing purposes.
        
        This method can be used to generate synthetic alerts when
        actual Sentinel alerts are not available (e.g., in test environments).
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Alert parameters
            
        Returns:
            Dictionary with sample alert details
        """
        # Map attack techniques to Sentinel alert types
        technique_to_alert = {
            "T1078": "Account compromised",
            "T1136": "New user creation",
            "T1087": "User enumeration activity",
            "T1098": "Privileged role assignment",
            "T1528": "Application token theft",
            "T1537": "Data exfiltration to storage account"
        }
        
        alert_type = technique_to_alert.get(technique_id, "Suspicious activity")
        
        # Extract parameters with defaults
        source_ip = parameters.get("source_ip", "198.51.100.1")
        resource_type = parameters.get("resource_type", "User")
        resource_id = parameters.get("resource_id", f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachines/mttd-test-vm")
        severity = parameters.get("severity", "Medium")
        user_name = parameters.get("user_name", "mttd-test-user")
        
        # Create sample alert
        alert = {
            "id": f"incident-{uuid.uuid4()}",
            "title": f"[MTTD Sample] {alert_type}",
            "description": f"Sample Sentinel incident for MTTD benchmarking of technique {technique_id}",
            "severity": severity,
            "status": "New",
            "timestamp": datetime.now().isoformat(),
            "eventType": "Incident",
            "_mttd_service": "azure_sentinel",
            "entities": [
                {
                    "type": "Account",
                    "name": user_name,
                    "properties": {
                        "account_name": user_name,
                        "user_principal_name": f"{user_name}@example.com"
                    }
                },
                {
                    "type": "IP",
                    "name": source_ip,
                    "properties": {
                        "address": source_ip,
                        "location": {
                            "country": "United States",
                            "city": "Seattle"
                        }
                    }
                }
            ],
            "SimulationId": parameters.get("simulation_id", "unknown")
        }
        
        # Add technique-specific details
        if technique_id == "T1078":
            alert["entities"].append({
                "type": "SecurityAlert",
                "name": "Suspicious sign-in activity",
                "properties": {
                    "alert_type": "UnfamiliarSignIn",
                    "source_ip": source_ip,
                    "user_agent": "mttd-benchmark/1.0"
                }
            })
        
        elif technique_id == "T1136":
            alert["entities"].append({
                "type": "SecurityAlert",
                "name": "New user created",
                "properties": {
                    "alert_type": "NewUserCreated",
                    "created_by": "admin@example.com",
                    "roles_assigned": ["User"]
                }
            })
        
        elif technique_id == "T1087":
            alert["entities"].append({
                "type": "SecurityAlert",
                "name": "User enumeration activity",
                "properties": {
                    "alert_type": "EnumerationActivity",
                    "source_ip": source_ip,
                    "query_count": 15
                }
            })
        
        elif technique_id == "T1098":
            alert["entities"].append({
                "type": "SecurityAlert",
                "name": "Privileged role assignment",
                "properties": {
                    "alert_type": "PrivilegedRoleAssignment",
                    "role_name": "Global Administrator",
                    "assigned_by": "admin@example.com"
                }
            })
        
        return alert