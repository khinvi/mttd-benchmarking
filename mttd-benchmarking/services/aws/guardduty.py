"""
AWS GuardDuty security service client.
"""

import logging
import uuid
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class SecurityClient:
    """
    Client for monitoring AWS GuardDuty security events.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the GuardDuty security client.
        
        Args:
            config: GuardDuty configuration
        """
        self.config = config
        self.session = None
        self.detector_ids = []
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
            logger.info(f"Initialized AWS session for GuardDuty in region {region}")
            
            # Get detector IDs
            self._get_detector_ids()
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS session for GuardDuty: {str(e)}")
            raise
    
    def _get_detector_ids(self):
        """Get all GuardDuty detector IDs in the account."""
        try:
            client = self.session.client('guardduty')
            response = client.list_detectors()
            self.detector_ids = response.get("DetectorIds", [])
            
            if not self.detector_ids:
                logger.warning("No GuardDuty detectors found in the account")
            else:
                logger.info(f"Found {len(self.detector_ids)} GuardDuty detectors")
        except Exception as e:
            logger.error(f"Error getting GuardDuty detector IDs: {str(e)}")
            # Continue even if we couldn't get detector IDs
    
    def get_security_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get GuardDuty findings within a time range.
        
        Args:
            start_time: Start time for findings
            end_time: End time for findings
            
        Returns:
            List of GuardDuty findings
        """
        events = []
        
        # Ensure we have a session
        if not self.session:
            try:
                self._initialize_session()
            except Exception as e:
                logger.error(f"Failed to initialize session: {str(e)}")
                return events
        
        try:
            client = self.session.client('guardduty')
            
            # Check if we need to refresh detector IDs
            if not self.detector_ids:
                self._get_detector_ids()
            
            # Return empty list if no detectors
            if not self.detector_ids:
                return events
            
            # Convert timestamps to epoch seconds for GuardDuty API
            start_timestamp = int(start_time.timestamp())
            end_timestamp = int(end_time.timestamp())
            
            for detector_id in self.detector_ids:
                # Get findings for this detector
                finding_ids = self._list_findings(
                    client, 
                    detector_id, 
                    start_timestamp, 
                    end_timestamp
                )
                
                # Get finding details
                if finding_ids:
                    findings = self._get_findings(client, detector_id, finding_ids)
                    events.extend(findings)
            
            logger.info(f"Retrieved {len(events)} GuardDuty findings")
            return events
            
        except Exception as e:
            logger.error(f"Failed to get GuardDuty findings: {str(e)}")
            return events
    
    def _list_findings(
        self, 
        client: Any, 
        detector_id: str, 
        start_timestamp: int, 
        end_timestamp: int
    ) -> List[str]:
        """
        List GuardDuty finding IDs.
        
        Args:
            client: GuardDuty boto3 client
            detector_id: GuardDuty detector ID
            start_timestamp: Start time in epoch seconds
            end_timestamp: End time in epoch seconds
            
        Returns:
            List of finding IDs
        """
        try:
            response = client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'updatedAt': {
                            'Gte': start_timestamp,
                            'Lte': end_timestamp
                        }
                    }
                },
                MaxResults=50  # Limit results
            )
            
            return response.get("FindingIds", [])
            
        except Exception as e:
            logger.error(f"Error listing findings for detector {detector_id}: {str(e)}")
            return []
    
    def _get_findings(self, client: Any, detector_id: str, finding_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Get detailed information for GuardDuty findings.
        
        Args:
            client: GuardDuty boto3 client
            detector_id: GuardDuty detector ID
            finding_ids: List of finding IDs
            
        Returns:
            List of finding details
        """
        findings = []
        
        try:
            # GuardDuty API limits to 50 findings per request
            for i in range(0, len(finding_ids), 50):
                batch = finding_ids[i:i+50]
                
                response = client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=batch
                )
                
                # Process findings to add metadata
                for finding in response.get("Findings", []):
                    # Enrich finding with additional metadata
                    finding["guardduty_detector_id"] = detector_id
                    finding["_mttd_service"] = "aws_guardduty"
                    
                    # Map common fields to standard format
                    if "CreatedAt" in finding:
                        finding["timestamp"] = finding["CreatedAt"]
                    
                    if "Type" in finding:
                        finding["eventType"] = finding["Type"]
                    
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error getting findings for detector {detector_id}: {str(e)}")
            return []

    def create_sample_finding(self, technique_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a sample finding for testing purposes.
        
        This method can be used to generate synthetic findings when
        actual GuardDuty findings are not available (e.g., in test environments).
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Finding parameters
            
        Returns:
            Dictionary with sample finding details
        """
        # Map attack techniques to GuardDuty finding types
        technique_to_finding = {
            "T1078": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "T1136": "Persistence:IAMUser/UserPermissions",
            "T1087": "Discovery:IAMUser/AnomalousBehavior",
            "T1098": "Persistence:IAMUser/UserPermissions",
            "T1048": "Exfiltration:S3/MaliciousIPCaller",
            "T1530": "Discovery:S3/BucketEnumeration",
            "T1537": "Exfiltration:S3/ObjectRead"
        }
        
        finding_type = technique_to_finding.get(technique_id, "Policy:IAMUser/RootCredentialUsage")
        
        # Extract parameters with defaults
        source_ip = parameters.get("source_ip", "198.51.100.1")
        resource_type = parameters.get("resource_type", "S3Bucket")
        resource_id = parameters.get("resource_id", f"arn:aws:s3:::mttd-test-{uuid.uuid4().hex[:8]}")
        severity = parameters.get("severity", 5)
        user_name = parameters.get("user_name", "mttd-test-user")
        
        # Create sample finding
        finding = {
            "id": f"mttd-sample-{uuid.uuid4()}",
            "guardduty_detector_id": "sample-detector-id",
            "_mttd_service": "aws_guardduty",
            "timestamp": datetime.now().isoformat(),
            "eventType": finding_type,
            "Type": finding_type,
            "SchemaVersion": "2.0",
            "CreatedAt": datetime.now().isoformat(),
            "UpdatedAt": datetime.now().isoformat(),
            "Severity": severity,
            "AccountId": "123456789012",
            "Region": self.session.region_name if self.session else "us-west-2",
            "Resource": {
                "ResourceType": resource_type,
                "AccessKeyDetails": {
                    "UserName": user_name
                },
                "S3BucketDetails": [
                    {
                        "Arn": resource_id,
                        "Name": resource_id.split(":")[-1] if ":" in resource_id else resource_id,
                        "Type": "Destination"
                    }
                ]
            },
            "Service": {
                "ServiceName": "guardduty",
                "EventFirstSeen": datetime.now().isoformat(),
                "EventLastSeen": datetime.now().isoformat(),
                "Count": 1
            },
            "Title": f"Sample GuardDuty finding for {technique_id}",
            "Description": f"This is a sample GuardDuty finding for MTTD benchmarking of technique {technique_id}",
            "SimulationId": parameters.get("simulation_id", "unknown")
        }
        
        # Add specific details based on finding type
        if "IAMUser" in finding_type:
            finding["Resource"]["AccessKeyDetails"] = {
                "UserName": user_name,
                "AccessKeyId": "AKIA" + uuid.uuid4().hex[:16].upper()
            }
        
        if "MaliciousIP" in finding_type or "BucketEnumeration" in finding_type:
            finding["Service"]["Action"] = {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "ListBuckets",
                    "ServiceName": "s3.amazonaws.com",
                    "RemoteIpDetails": {
                        "IpAddressV4": source_ip,
                        "Country": {
                            "CountryName": "United States"
                        }
                    }
                }
            }
        
        return finding