"""
Google Cloud Platform (GCP) Security Command Center client.
"""

import logging
import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Try to import GCP libraries - handle gracefully if not available
try:
    from google.cloud import securitycenter_v1
    from google.api_core.exceptions import GoogleAPIError
    GCP_LIBRARIES_AVAILABLE = True
except ImportError:
    logger.warning("Google Cloud Security Center libraries not available. Using mock implementations.")
    GCP_LIBRARIES_AVAILABLE = False


class SecurityClient:
    """
    Client for monitoring GCP Security Command Center findings.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Security Command Center client.
        
        Args:
            config: Security Command Center configuration
        """
        self.config = config
        self.project_id = config.get("project_id")
        self.organization_id = config.get("organization_id")
        
        # Check if organization ID or project ID is provided
        if not self.organization_id and not self.project_id:
            raise ValueError("Either organization_id or project_id must be provided")
        
        logger.info(f"Initialized GCP Security Command Center client for {'organization ' + self.organization_id if self.organization_id else 'project ' + self.project_id}")
    
    def get_security_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get Security Command Center findings within a time range.
        
        Args:
            start_time: Start time for findings
            end_time: End time for findings
            
        Returns:
            List of Security Command Center findings
        """
        events = []
        
        # If GCP libraries aren't available, use mock implementations
        if not GCP_LIBRARIES_AVAILABLE:
            return self._get_mock_security_events(start_time, end_time)
        
        try:
            # Create Security Command Center client
            client = securitycenter_v1.SecurityCenterClient()
            
            # Determine parent resource
            if self.organization_id:
                parent = f"organizations/{self.organization_id}"
            else:
                parent = f"projects/{self.project_id}"
            
            # Create filter for the time range
            time_filter = (
                f"event_time >= \"{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}\" AND "
                f"event_time <= \"{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}\""
            )
            
            # List findings
            findings_iterator = client.list_findings(
                request={
                    "parent": parent,
                    "filter": time_filter
                }
            )
            
            # Process findings
            for finding_result in findings_iterator:
                for finding in finding_result.findings:
                    # Convert finding to dictionary
                    finding_dict = self._finding_to_dict(finding)
                    events.append(finding_dict)
            
            logger.info(f"Retrieved {len(events)} Security Command Center findings")
            return events
            
        except Exception as e:
            logger.error(f"Failed to get Security Command Center findings: {str(e)}")
            return self._get_mock_security_events(start_time, end_time)
    
    def _finding_to_dict(self, finding: Any) -> Dict[str, Any]:
        """
        Convert a Finding object to a dictionary.
        
        Args:
            finding: Finding object
            
        Returns:
            Dictionary representation of the finding
        """
        # Extract properties from the Finding object
        finding_dict = {
            "id": finding.name,
            "category": finding.category,
            "resource_name": finding.resource_name,
            "severity": finding.severity.name,
            "event_time": finding.event_time.isoformat() if hasattr(finding, "event_time") and finding.event_time else datetime.now().isoformat(),
            "state": finding.state.name,
            "_mttd_service": "gcp_security_command",
            "eventType": finding.category,
            "timestamp": finding.event_time.isoformat() if hasattr(finding, "event_time") and finding.event_time else datetime.now().isoformat()
        }
        
        # Add source properties if available
        if hasattr(finding, "source_properties") and finding.source_properties:
            finding_dict["sourceProperties"] = {}
            for key, value in finding.source_properties.items():
                finding_dict["sourceProperties"][key] = value
        
        return finding_dict
    
    def _get_mock_security_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """
        Get mock security events when GCP libraries aren't available.
        
        Args:
            start_time: Start time for events
            end_time: End time for events
            
        Returns:
            List of mock security events
        """
        # Create some mock events with timestamps within the specified range
        events = []
        
        # Calculate a time within the range
        event_time = start_time + (end_time - start_time) / 2
        
        # Add a privilege escalation event
        events.append({
            "id": f"organizations/{self.organization_id or '123456789'}/sources/12345/findings/{uuid.uuid4()}",
            "category": "PRIVILEGED_ROLE_GRANT",
            "resource_name": f"//cloudresourcemanager.googleapis.com/projects/{self.project_id or 'mttd-project'}",
            "severity": "HIGH",
            "event_time": event_time.isoformat(),
            "state": "ACTIVE",
            "_mttd_service": "gcp_security_command",
            "eventType": "PRIVILEGED_ROLE_GRANT",
            "timestamp": event_time.isoformat(),
            "sourceProperties": {
                "role": "roles/owner",
                "principal": "user:attacker@example.com",
                "callerIp": "198.51.100.1"
            }
        })
        
        # Add an abnormal API usage event
        events.append({
            "id": f"organizations/{self.organization_id or '123456789'}/sources/12345/findings/{uuid.uuid4()}",
            "category": "ABNORMAL_API_USAGE",
            "resource_name": f"//cloudresourcemanager.googleapis.com/projects/{self.project_id or 'mttd-project'}",
            "severity": "MEDIUM",
            "event_time": (event_time + timedelta(minutes=5)).isoformat(),
            "state": "ACTIVE",
            "_mttd_service": "gcp_security_command",
            "eventType": "ABNORMAL_API_USAGE",
            "timestamp": (event_time + timedelta(minutes=5)).isoformat(),
            "sourceProperties": {
                "apiMethodName": "google.iam.admin.v1.CreateServiceAccount",
                "callerIp": "198.51.100.1",
                "frequency": "RARE"
            }
        })
        
        # Add a data exfiltration event
        events.append({
            "id": f"organizations/{self.organization_id or '123456789'}/sources/12345/findings/{uuid.uuid4()}",
            "category": "DATA_EXFILTRATION",
            "resource_name": f"//storage.googleapis.com/projects/{self.project_id or 'mttd-project'}/buckets/sensitive-data",
            "severity": "CRITICAL",
            "event_time": (event_time + timedelta(minutes=10)).isoformat(),
            "state": "ACTIVE",
            "_mttd_service": "gcp_security_command",
            "eventType": "DATA_EXFILTRATION",
            "timestamp": (event_time + timedelta(minutes=10)).isoformat(),
            "sourceProperties": {
                "objectsCopied": "25",
                "dataSize": "500MB",
                "destinationIp": "198.51.100.2"
            }
        })
        
        logger.info(f"Generated {len(events)} mock Security Command Center findings")
        return events
    
    def create_sample_finding(
        self, 
        technique_id: str, 
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a sample finding for testing purposes.
        
        This method can be used to generate synthetic findings when
        actual Security Command Center findings are not available.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Finding parameters
            
        Returns:
            Dictionary with sample finding details
        """
        # Map attack techniques to Security Command Center finding categories
        technique_to_category = {
            "T1078": "IAM_ABNORMAL_GRANT",
            "T1136": "IAM_ANOMALOUS_ACCOUNT_CREATION",
            "T1087": "IAM_ANOMALOUS_ACCOUNT_ENUMERATION",
            "T1098": "IAM_PRIVILEGED_ACCESS_GRANT",
            "T1525": "CONTAINER_SUSPICIOUS_IMAGE_PUSH",
            "T1537": "STORAGE_EXFILTRATION"
        }
        
        # Map severity labels
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }
        
        category = technique_to_category.get(technique_id, "GENERIC_SUSPICIOUS_ACTIVITY")
        
        # Extract parameters with defaults
        source_ip = parameters.get("source_ip", "198.51.100.1")
        severity = parameters.get("severity", "MEDIUM")
        resource_type = parameters.get("resource_type", "PROJECT")
        resource_name = parameters.get("resource_name", f"projects/{self.project_id or 'mttd-project'}")
        
        # Determine parent resource
        if self.organization_id:
            parent = f"organizations/{self.organization_id}"
        else:
            parent = f"projects/{self.project_id or 'mttd-project'}"
        
        # Create a unique finding ID
        finding_id = str(uuid.uuid4())
        
        # Create the base finding
        finding = {
            "id": f"{parent}/sources/12345/findings/{finding_id}",
            "category": category,
            "resource_name": resource_name,
            "severity": severity_map.get(severity, "MEDIUM"),
            "event_time": datetime.now().isoformat(),
            "state": "ACTIVE",
            "_mttd_service": "gcp_security_command",
            "eventType": category,
            "timestamp": datetime.now().isoformat(),
            "sourceProperties": {
                "callerIp": source_ip,
                "simulationId": parameters.get("simulation_id", "unknown")
            }
        }
        
        # Add technique-specific details
        if technique_id == "T1078":  # Valid Accounts
            finding["sourceProperties"].update({
                "principalEmail": parameters.get("user_name", "attacker@example.com"),
                "authenticationMethod": "PASSWORD",
                "anomalyScore": 0.85,
                "apiMethod": "iam.googleapis.com/SignIn"
            })
            
        elif technique_id == "T1136":  # Create Account
            finding["sourceProperties"].update({
                "creatorEmail": parameters.get("user_name", "attacker@example.com"),
                "accountType": "SERVICE_ACCOUNT",
                "accountEmail": f"{parameters.get('account_name', 'malicious-sa')}@{self.project_id or 'mttd-project'}.iam.gserviceaccount.com",
                "apiMethod": "iam.googleapis.com/CreateServiceAccount"
            })
            
        elif technique_id == "T1087":  # Account Discovery
            finding["sourceProperties"].update({
                "callerEmail": parameters.get("user_name", "attacker@example.com"),
                "apiCalls": ["ListServiceAccounts", "GetIamPolicy", "ListRoles"],
                "callCount": 15,
                "timeWindow": "PT5M"  # 5 minutes
            })
            
        elif technique_id == "T1098":  # Account Manipulation
            finding["sourceProperties"].update({
                "modifierEmail": parameters.get("user_name", "attacker@example.com"),
                "targetResource": f"projects/{self.project_id or 'mttd-project'}/serviceAccounts/{parameters.get('account_name', 'target-sa')}",
                "roleName": parameters.get("role", "roles/owner"),
                "previousRoles": ["roles/viewer"],
                "apiMethod": "iam.googleapis.com/SetIamPolicy"
            })
            
        elif technique_id == "T1525":  # Implant Container Image
            finding["sourceProperties"].update({
                "repository": parameters.get("repository", "gcr.io/mttd-project/images"),
                "image": parameters.get("image", "app-image"),
                "tag": parameters.get("tag", "latest"),
                "digestSha": f"sha256:{uuid.uuid4().hex}",
                "vulnerabilitiesFound": 3,
                "maliciousCodeDetected": True
            })
            
        elif technique_id == "T1537":  # Transfer to Cloud Account
            finding["sourceProperties"].update({
                "sourceBucket": parameters.get("source_bucket", "mttd-source-bucket"),
                "destinationBucket": parameters.get("destination_bucket", "external-destination-bucket"),
                "objectsTransferred": 25,
                "dataSizeBytes": parameters.get("data_size", 100) * 1024 * 1024,  # Convert MB to bytes
                "destinationProject": "external-project-123",
                "apiMethod": "storage.googleapis.com/CopyObject"
            })
            
        return finding