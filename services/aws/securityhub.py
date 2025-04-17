"""
AWS Security Hub security service client.
"""

import logging
import boto3
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class SecurityClient:
    """
    Client for monitoring AWS Security Hub security events.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Security Hub client.
        
        Args:
            config: Security Hub configuration
        """
        self.config = config
        self.session = None
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
            logger.info(f"Initialized AWS session for Security Hub in region {region}")
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS session for Security Hub: {str(e)}")
            raise
    
    def get_security_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get Security Hub findings within a time range.
        
        Args:
            start_time: Start time for findings
            end_time: End time for findings
            
        Returns:
            List of Security Hub findings
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
            client = self.session.client('securityhub')
            
            # Create filters for the findings
            filters = {
                'UpdatedAt': [
                    {
                        'Start': start_time.isoformat(),
                        'End': end_time.isoformat()
                    }
                ]
            }
            
            # Get findings
            paginator = client.get_paginator('get_findings')
            
            # Paginate through findings
            for page in paginator.paginate(Filters=filters):
                for finding in page.get('Findings', []):
                    # Process finding to add metadata
                    finding["_mttd_service"] = "aws_securityhub"
                    
                    # Map common fields to standard format
                    if "UpdatedAt" in finding:
                        finding["timestamp"] = finding["UpdatedAt"]
                    
                    if "Title" in finding:
                        finding["title"] = finding["Title"]
                    
                    if "Types" in finding and finding["Types"]:
                        finding["eventType"] = finding["Types"][0]
                    
                    events.append(finding)
            
            logger.info(f"Retrieved {len(events)} Security Hub findings")
            return events
            
        except Exception as e:
            logger.error(f"Failed to get Security Hub findings: {str(e)}")
            return events
    
    def create_sample_finding(self, technique_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a sample finding for testing purposes.
        
        This method can be used to generate synthetic findings when
        actual Security Hub findings are not available (e.g., in test environments).
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            parameters: Finding parameters
            
        Returns:
            Dictionary with sample finding details
        """
        # Map attack techniques to Security Hub finding types
        technique_to_finding = {
            "T1078": "TTPs/Initial.Access/UnauthorizedAccess",
            "T1136": "TTPs/Persistence/Account.Creation",
            "T1087": "TTPs/Discovery/Account.Discovery",
            "T1098": "TTPs/Persistence/Account.Manipulation",
            "T1048": "TTPs/Exfiltration/Exfiltration.Over.Alternative.Protocol",
            "T1530": "TTPs/Collection/Data.from.Cloud.Storage",
            "T1537": "TTPs/Exfiltration/Transfer.to.Cloud.Account"
        }
        
        finding_type = technique_to_finding.get(technique_id, "TTPs/Unknown")
        
        # Extract parameters with defaults
        source_ip = parameters.get("source_ip", "198.51.100.1")
        resource_type = parameters.get("resource_type", "AwsS3Bucket")
        resource_id = parameters.get("resource_id", f"arn:aws:s3:::mttd-test-{uuid.uuid4().hex[:8]}")
        severity = parameters.get("severity", "MEDIUM")
        user_name = parameters.get("user_name", "mttd-test-user")
        
        # Mapped severity
        severity_map = {
            "CRITICAL": {"Label": "CRITICAL", "Original": 90},
            "HIGH": {"Label": "HIGH", "Original": 70},
            "MEDIUM": {"Label": "MEDIUM", "Original": 50},
            "LOW": {"Label": "LOW", "Original": 30},
            "INFORMATIONAL": {"Label": "INFORMATIONAL", "Original": 10}
        }
        
        mapped_severity = severity_map.get(severity, severity_map["MEDIUM"])
        
        # Create unique finding ID
        finding_id = f"mttd-sample-{uuid.uuid4()}"
        
        # Create sample finding
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": finding_id,
            "ProductArn": f"arn:aws:securityhub:{self.session.region_name if self.session else 'us-west-2'}:123456789012:product/aws/securityhub",
            "GeneratorId": "mttd-benchmark",
            "AwsAccountId": "123456789012",
            "Types": [finding_type],
            "FirstObservedAt": datetime.now().isoformat(),
            "UpdatedAt": datetime.now().isoformat(),
            "CreatedAt": datetime.now().isoformat(),
            "Severity": {
                "Label": mapped_severity["Label"],
                "Original": mapped_severity["Original"]
            },
            "Title": f"Sample finding for {technique_id}",
            "Description": f"This is a sample Security Hub finding for MTTD benchmarking of technique {technique_id}",
            "_mttd_service": "aws_securityhub",
            "timestamp": datetime.now().isoformat(),
            "eventType": finding_type,
            "Resources": [
                {
                    "Type": resource_type,
                    "Id": resource_id,
                    "Partition": "aws",
                    "Region": self.session.region_name if self.session else "us-west-2"
                }
            ],
            "SourceUrl": "https://console.aws.amazon.com/securityhub",
            "ProductFields": {
                "ProviderName": "MTTD Benchmark",
                "ProviderVersion": "1.0.0"
            },
            "RecordState": "ACTIVE",
            "SimulationId": parameters.get("simulation_id", "unknown")
        }
        
        # Add technique-specific details
        if technique_id == "T1078":  # Valid Accounts
            finding["Action"] = {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "AssumeRole",
                    "ServiceName": "sts.amazonaws.com",
                    "RemoteIpDetails": {
                        "IpAddressV4": source_ip,
                        "Country": {
                            "CountryName": "United States"
                        }
                    }
                }
            }
            
        elif technique_id == "T1136":  # Create Account
            finding["Action"] = {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "CreateUser",
                    "ServiceName": "iam.amazonaws.com",
                    "RemoteIpDetails": {
                        "IpAddressV4": source_ip,
                        "Country": {
                            "CountryName": "United States"
                        }
                    }
                }
            }
            
        elif technique_id == "T1087":  # Account Discovery
            finding["Action"] = {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "ListUsers",
                    "ServiceName": "iam.amazonaws.com",
                    "RemoteIpDetails": {
                        "IpAddressV4": source_ip,
                        "Country": {
                            "CountryName": "United States"
                        }
                    }
                }
            }
            
        elif technique_id == "T1098":  # Account Manipulation
            finding["Action"] = {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "AttachUserPolicy",
                    "ServiceName": "iam.amazonaws.com",
                    "RemoteIpDetails": {
                        "IpAddressV4": source_ip,
                        "Country": {
                            "CountryName": "United States"
                        }
                    }
                }
            }
            
        elif technique_id == "T1048" or technique_id == "T1537":  # Exfiltration
            finding["Action"] = {
                "ActionType": "NETWORK_CONNECTION",
                "NetworkConnectionAction": {
                    "Protocol": "TCP",
                    "LocalPortDetails": {
                        "Port": 443,
                        "PortName": "HTTPS"
                    },
                    "RemoteIpDetails": {
                        "IpAddressV4": source_ip,
                        "Country": {
                            "CountryName": "United States"
                        }
                    },
                    "Direction": "OUTBOUND"
                }
            }
            
        elif technique_id == "T1530":  # Data from Cloud Storage
            finding["Action"] = {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "GetObject",
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