"""
Azure Defender (Microsoft Defender for Cloud) security service client.
"""

import logging
import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.models import Alert

logger = logging.getLogger(__name__)


class SecurityClient:
    """
    Client for monitoring Azure Defender (Microsoft Defender for Cloud) security events.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Defender security client.
        
        Args:
            config: Defender configuration
        """
        self.config = config
        self.credentials = None
        self.subscription_id = config.get("subscription_id")
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
                raise ValueError("Subscription ID is required for Azure Defender operations")
                
            # Initialize Security Center client
            self.security_client = SecurityCenter(
                credential=self.credentials,
                subscription_id=self.subscription_id
            )
            
            logger.info(f"Azure Defender client initialized for subscription {self.subscription_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure Defender credentials: {str(e)}")
            raise
    
    def get_security_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get Defender alerts within a time range.
        
        Args:
            start_time: Start time for alerts
            end_time: End time for alerts
            
        Returns:
            List of Defender alerts
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
            # Get alerts for the specified time range
            # Convert to string format required by the SDK
            start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # List alerts
            alerts = self.security_client.alerts.list(
                filter=f"properties/createdTime ge {start_time_str} and properties/createdTime le {end_time_str}"
            )
            
            # Convert alerts to dictionaries
            for alert in alerts:
                alert_dict = self._alert_to_dict(alert)
                events.append(alert_dict)
            
            logger.info(f"Retrieved {len(events)} Defender alerts")
            return events
            
        except Exception as e:
            logger.error(f"Failed to get Defender alerts: {str(e)}")
            return events
    
    def _alert_to_dict(self, alert: Alert) -> Dict[str, Any]:
        """
        Convert an Alert object to a dictionary.
        
        Args:
            alert: Alert object
            
        Returns:
            Dictionary representation of the alert
        """
        # Extract properties from the Alert object
        alert_dict = {
            "id": alert.name,
            "title": alert.properties.alert_display_name,
            "description": alert.properties.description,
            "severity": alert.properties.severity,
            "status": alert.properties.state,
            "timestamp": alert.properties.created_time.isoformat() if alert.properties.created_time else datetime.now().isoformat(),
            "eventType": alert.properties.product_name or "Microsoft Defender for Cloud",
            "_mttd_service": "azure_defender",
            "resourceId": alert.properties.resource_identifiers.id if alert.properties.resource_identifiers else None,
            "resourceType": alert.properties.resource_identifiers.type if alert.properties.resource_identifiers else None,
            "alertType": alert.properties.alert_type
        }
        
        # Add additional properties if available
        if hasattr(alert.properties, "detected_time_utc") and alert.properties.detected_time_utc:
            alert_dict["detectedTime"] = alert.properties.detected_time_utc.isoformat()
            
        if hasattr(alert.properties, "remediation_steps") and alert.properties.remediation_steps:
            alert_dict["remediationSteps"] = alert.properties.remediation_steps
            
        if hasattr(alert.properties, "compromised_entity") and alert.properties.compromised_entity:
            alert_dict["compromisedEntity"] = alert.properties.compromised_entity
            
        if hasattr(alert.properties, "intent") and alert.properties.intent:
            alert_dict["intent"] = alert.properties.intent
            
        return alert_dict
    
    def create_sample_alert(
        self, 
        technique_id: str, 
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a sample alert for testing purposes.
        
        This method can be used to generate synthetic alerts when
        actual Defender alerts are not available (e.g., in test environments).
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Alert parameters
            
        Returns:
            Dictionary with sample alert details
        """
        # Map attack techniques to Defender alert types
        technique_to_alert = {
            "T1078": "Suspicious sign-in activity detected",
            "T1136": "Addition of account with privileged role detected",
            "T1087": "Account enumeration activity detected",
            "T1098": "Account manipulation activity detected",
            "T1528": "Suspicious application consent detected",
            "T1537": "Data exfiltration to storage detected"
        }
        
        alert_type = technique_to_alert.get(technique_id, "Suspicious activity detected")
        
        # Extract parameters with defaults
        source_ip = parameters.get("source_ip", "198.51.100.1")
        resource_type = parameters.get("resource_type", "virtualMachines")
        resource_id = parameters.get("resource_id", f"/subscriptions/{self.subscription_id}/resourceGroups/mttd-test/providers/Microsoft.Compute/virtualMachines/mttd-test-vm")
        severity = parameters.get("severity", "Medium")
        user_name = parameters.get("user_name", "mttd-test-user")
        
        # Create a sample alert
        alert = {
            "id": f"alert-{uuid.uuid4()}",
            "title": alert_type,
            "description": f"Sample Defender alert for MTTD benchmarking of technique {technique_id}",
            "severity": severity,
            "status": "Active",
            "timestamp": datetime.now().isoformat(),
            "eventType": "Microsoft Defender for Cloud",
            "_mttd_service": "azure_defender",
            "resourceId": resource_id,
            "resourceType": resource_type,
            "alertType": alert_type,
            "detectedTime": (datetime.now() - timedelta(minutes=1)).isoformat(),
            "sourceIp": source_ip,
            "userName": user_name,
            "SimulationId": parameters.get("simulation_id", "unknown")
        }
        
        # Add technique-specific details
        if technique_id == "T1078":  # Valid Accounts
            alert["additionalData"] = {
                "loginType": "Interactive",
                "authenticationMethod": "Password",
                "userPrincipalName": f"{user_name}@example.com",
                "sourceIpAddress": source_ip,
                "userAgent": "Mozilla/5.0",
                "location": "United States"
            }
            
        elif technique_id == "T1136":  # Create Account
            alert["additionalData"] = {
                "createdAccountName": f"new-user-{uuid.uuid4().hex[:8]}@example.com",
                "createdByName": f"{user_name}@example.com",
                "createdByIpAddress": source_ip,
                "assignedRoles": ["Global Administrator"],
                "actionType": "Add"
            }
            
        elif technique_id == "T1087":  # Account Discovery
            alert["additionalData"] = {
                "queryCount": 15,
                "queryType": "DirectoryObjects.Read",
                "queryByName": f"{user_name}@example.com",
                "queryIpAddress": source_ip,
                "objectsReturned": 25
            }
            
        elif technique_id == "T1098":  # Account Manipulation
            alert["additionalData"] = {
                "targetAccountName": f"target-user@example.com",
                "modifiedByName": f"{user_name}@example.com",
                "modifiedByIpAddress": source_ip,
                "modificationType": "RoleAssignment",
                "newRoles": ["Global Administrator"]
            }
            
        elif technique_id == "T1528":  # Steal Application Access Token
            alert["additionalData"] = {
                "applicationName": "Sample App",
                "applicationId": f"app-id-{uuid.uuid4().hex[:8]}",
                "consentedBy": f"{user_name}@example.com",
                "consentIpAddress": source_ip,
                "permissionsRequested": ["Directory.ReadWrite.All", "Mail.Read"]
            }
            
        elif technique_id == "T1537":  # Exfiltration to Cloud Account
            alert["additionalData"] = {
                "storageAccountName": f"storage{uuid.uuid4().hex[:8]}",
                "dataSize": "500 MB",
                "destinationIpAddress": source_ip,
                "accessByName": f"{user_name}@example.com",
                "accessType": "Blob.Read"
            }
            
        return alert