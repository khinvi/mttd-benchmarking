"""
Generic client implementations for platform and security services.
"""

import logging
import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from ...core.types import ResourceType

logger = logging.getLogger(__name__)


class GenericPlatformClient:
    """
    Generic platform client that provides mock implementations.
    Used as a fallback when specific clients are not available.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the generic platform client.
        
        Args:
            config: Configuration
        """
        self.config = config
        self.resources = {}
        self.provider = config.get("provider", "generic")
        self.region = config.get("region", "us-east-1")
        logger.info(f"Initialized generic platform client for provider {self.provider}")
    
    def create_resource(self, resource_type: ResourceType, resource_name: str, parameters: Dict[str, Any]) -> str:
        """
        Create a mock resource.
        
        Args:
            resource_type: Type of resource to create
            resource_name: Name for the resource
            parameters: Resource parameters
            
        Returns:
            Resource ID
        """
        logger.info(f"Creating mock {resource_type.value} resource: {resource_name}")
        
        # Generate a mock resource ID
        resource_id = f"resource/{self.provider}/{resource_type.value}/{resource_name}-{uuid.uuid4().hex[:8]}"
        
        # Track created resource
        if resource_type.value not in self.resources:
            self.resources[resource_type.value] = []
            
        self.resources[resource_type.value].append({
            "id": resource_id,
            "name": resource_name,
            "parameters": parameters,
            "created_time": datetime.now().isoformat()
        })
        
        logger.info(f"Created mock resource {resource_name} with ID {resource_id}")
        return resource_id
    
    def delete_resource(self, resource_type: str, resource_id: str) -> bool:
        """
        Delete a mock resource.
        
        Args:
            resource_type: Type of resource to delete
            resource_id: ID of the resource
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting mock {resource_type} resource: {resource_id}")
        
        # Remove from tracking
        if resource_type in self.resources:
            self.resources[resource_type] = [
                r for r in self.resources[resource_type] if r["id"] != resource_id
            ]
        
        return True
    
    def execute_technique(self, technique_id: str, parameters: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute a mock attack technique.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Technique parameters
            context: Additional context information
            
        Returns:
            Dictionary with execution details
        """
        logger.info(f"Executing mock technique {technique_id}")
        
        # Get standard parameters
        user_name = parameters.get("user_name", "mttd-test-user")
        source_ip = parameters.get("source_ip", "198.51.100.1")
        
        # Create a generic indicator key based on the technique
        indicator_key = f"{self.provider.lower()}-api-call"
        
        # Execute technique (all mocked)
        result = {
            "technique": technique_id,
            "mocked": True,
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            indicator_key: {
                "service": "Generic",
                "operation": f"MockOperation{technique_id}",
                "source_ip": source_ip,
                "user_agent": "mttd-benchmark/1.0"
            }
        }
        
        # Add technique-specific details
        if technique_id == "T1078":  # Valid Accounts
            result["user_name"] = user_name
            result["unusual-login"] = {
                "user": user_name,
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat()
            }
            
        elif technique_id == "T1136":  # Create Account
            result["user_created"] = user_name
            result["user-creation"] = {
                "user": user_name,
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat()
            }
            
        elif technique_id == "T1087":  # Account Discovery
            result["discovered_users"] = [
                {"user_name": f"user{i}", "id": f"id-{i}"} for i in range(1, 6)
            ]
            result["account-enumeration"] = {
                "count": 5,
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat()
            }
            
        elif technique_id == "T1098":  # Account Manipulation
            result["user_name"] = user_name
            result["role_name"] = parameters.get("role_name", "Admin")
            result["privilege-escalation"] = {
                "user": user_name,
                "role": parameters.get("role_name", "Admin"),
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat()
            }
            
        elif technique_id == "T1530" or technique_id == "T1537":  # Data from Cloud Storage or Transfer to Cloud Account
            result["storage_name"] = parameters.get("storage_name", f"storage-{uuid.uuid4().hex[:8]}")
            result["data-access"] = {
                "storage": result["storage_name"],
                "source_ip": source_ip,
                "timestamp": datetime.now().isoformat()
            }
        
        return result


class GenericSecurityClient:
    """
    Generic security client that provides mock implementations.
    Used as a fallback when specific clients are not available.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the generic security client.
        
        Args:
            config: Configuration
        """
        self.config = config
        self.provider = config.get("provider", "generic")
        self.service_name = config.get("service_name", "generic_security")
        logger.info(f"Initialized generic security client for provider {self.provider}")
        
        # Store some sample events to return
        self.sample_events = []
        
        # Automatic generation of some sample events
        self._create_sample_events()
    
    def _create_sample_events(self):
        """Create some sample security events."""
        # Add a few sample events with different timestamps
        now = datetime.now()
        
        # Sample account compromise event
        self.sample_events.append({
            "id": f"event-{uuid.uuid4()}",
            "title": "Suspicious sign-in detected",
            "description": "A sign-in from an unusual location was detected",
            "severity": "Medium",
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "eventType": "AccountCompromise",
            "_mttd_service": self.service_name,
            "sourceIp": "198.51.100.1",
            "userName": "user1@example.com",
            "resource": "Azure Active Directory"
        })
        
        # Sample privilege escalation event
        self.sample_events.append({
            "id": f"event-{uuid.uuid4()}",
            "title": "Privilege escalation detected",
            "description": "A user was added to a privileged role",
            "severity": "High",
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "eventType": "PrivilegeEscalation",
            "_mttd_service": self.service_name,
            "sourceIp": "198.51.100.2",
            "userName": "user2@example.com",
            "resource": "Azure Resource Manager",
            "role": "Owner"
        })
        
        # Sample data exfiltration event
        self.sample_events.append({
            "id": f"event-{uuid.uuid4()}",
            "title": "Potential data exfiltration",
            "description": "Large amount of data accessed from storage account",
            "severity": "High",
            "timestamp": (now - timedelta(minutes=15)).isoformat(),
            "eventType": "DataExfiltration",
            "_mttd_service": self.service_name,
            "sourceIp": "198.51.100.3",
            "userName": "user3@example.com",
            "resource": "mttd-storage",
            "dataSize": "1.2 GB"
        })
    
    def get_security_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get security events within a time range.
        
        Args:
            start_time: Start time for events
            end_time: End time for events
            
        Returns:
            List of security events
        """
        logger.info(f"Getting security events from {start_time} to {end_time}")
        
        # Filter events by time range
        filtered_events = []
        
        for event in self.sample_events:
            # Parse event timestamp
            event_time = None
            if "timestamp" in event:
                try:
                    if isinstance(event["timestamp"], str):
                        event_time = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
                    else:
                        event_time = event["timestamp"]
                except ValueError:
                    logger.warning(f"Invalid timestamp format in event: {event['id']}")
                    continue
            
            # Skip events outside the time range
            if not event_time or event_time < start_time or event_time > end_time:
                continue
                
            # Add to filtered events
            filtered_events.append(event)
        
        logger.info(f"Found {len(filtered_events)} events in the specified time range")
        return filtered_events
    
    def create_sample_event(
        self, 
        technique_id: str, 
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a sample security event for testing purposes.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Event parameters
            
        Returns:
            Dictionary with sample event details
        """
        # Map attack techniques to event types
        technique_to_event = {
            "T1078": "AccountCompromise",
            "T1136": "UserCreation",
            "T1087": "AccountDiscovery",
            "T1098": "PrivilegeEscalation",
            "T1528": "TokenTheft",
            "T1530": "DataAccess",
            "T1537": "DataExfiltration"
        }
        
        event_type = technique_to_event.get(technique_id, "SuspiciousActivity")
        
        # Extract parameters with defaults
        source_ip = parameters.get("source_ip", "198.51.100.1")
        severity = parameters.get("severity", "Medium")
        user_name = parameters.get("user_name", "mttd-test-user@example.com")
        resource = parameters.get("resource", "Generic Resource")
        
        # Create sample event
        event = {
            "id": f"event-{uuid.uuid4()}",
            "title": f"[MTTD Sample] {event_type}",
            "description": f"Sample security event for MTTD benchmarking of technique {technique_id}",
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "eventType": event_type,
            "_mttd_service": self.service_name,
            "sourceIp": source_ip,
            "userName": user_name,
            "resource": resource,
            "SimulationId": parameters.get("simulation_id", "unknown")
        }
        
        # Add technique-specific details
        if technique_id == "T1078":  # Valid Accounts
            event["loginType"] = "Interactive"
            event["location"] = "Seattle, US"
            
        elif technique_id == "T1136":  # Create Account
            event["createdUser"] = f"new-user-{uuid.uuid4().hex[:8]}@example.com"
            event["userType"] = "Standard"
            
        elif technique_id == "T1087":  # Account Discovery
            event["queryCount"] = 15
            event["queryType"] = "UserEnumeration"
            
        elif technique_id == "T1098":  # Account Manipulation
            event["roleName"] = parameters.get("role_name", "Administrator")
            event["previousRole"] = "User"
            
        elif technique_id == "T1528":  # Steal Application Access Token
            event["appName"] = parameters.get("app_name", "Generic App")
            event["tokenType"] = "OAuth"
            
        elif technique_id == "T1530" or technique_id == "T1537":  # Data Access or Transfer
            event["storageName"] = parameters.get("storage_name", f"storage-{uuid.uuid4().hex[:8]}")
            event["dataSize"] = "500 MB"
            
            if technique_id == "T1537":
                event["destinationAccount"] = parameters.get("destination_account", "external-account")
        
        # Add event to sample events list
        self.sample_events.append(event)
        
        return event