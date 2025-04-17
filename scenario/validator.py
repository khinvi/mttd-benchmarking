"""
Scenario validator for ensuring scenario integrity.
"""

import logging
import json
import jsonschema
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class ScenarioValidator:
    """
    Validates scenario definitions to ensure they meet the requirements
    for successful execution.
    """
    
    def __init__(self):
        """Initialize the validator with the scenario schema."""
        # Define JSON schema for scenarios
        self.schema = {
            "type": "object",
            "required": ["id", "name", "platform", "steps"],
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "platform": {
                    "type": "object",
                    "required": ["name", "service_name"],
                    "properties": {
                        "name": {"type": "string", "enum": ["aws", "azure", "gcp"]},
                        "service_name": {"type": "string"},
                        "region": {"type": "string"}
                    }
                },
                "steps": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["name", "technique_id"],
                        "properties": {
                            "name": {"type": "string"},
                            "technique_id": {"type": "string"},
                            "description": {"type": "string"},
                            "parameters": {"type": "object"},
                            "expected_indicators": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                },
                "environment_config": {
                    "type": "object",
                    "properties": {
                        "resources": {"type": "object"}
                    }
                },
                "expected_alerts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["service", "finding_type", "severity"],
                        "properties": {
                            "service": {"type": "string"},
                            "finding_type": {"type": "string"},
                            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]},
                            "time_to_detect_range": {
                                "type": "array",
                                "minItems": 2,
                                "maxItems": 2,
                                "items": {"type": "number"}
                            }
                        }
                    }
                }
            }
        }
    
    def validate_scenario(self, scenario_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a scenario against the schema and additional business rules.
        
        Args:
            scenario_data: Scenario data to validate
            
        Returns:
            Dictionary with validation results
        """
        errors = []
        
        # Validate against schema
        try:
            jsonschema.validate(instance=scenario_data, schema=self.schema)
        except jsonschema.exceptions.ValidationError as e:
            errors.append(f"Schema validation error: {e.message}")
            
        # Additional business rule validations
        if not errors:
            errors.extend(self._validate_techniques(scenario_data))
            errors.extend(self._validate_resources(scenario_data))
            errors.extend(self._validate_expected_alerts(scenario_data))
        
        # Return validation result
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def _validate_techniques(self, scenario_data: Dict[str, Any]) -> List[str]:
        """
        Validate attack techniques in the scenario.
        
        Args:
            scenario_data: Scenario data to validate
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Get steps
        steps = scenario_data.get("steps", [])
        
        # Validate technique IDs
        valid_technique_prefix = "T"
        for i, step in enumerate(steps):
            technique_id = step.get("technique_id", "")
            
            # Check if technique ID is in expected format (e.g., T1078)
            if not technique_id.startswith(valid_technique_prefix) or not any(c.isdigit() for c in technique_id):
                errors.append(f"Step {i+1}: Invalid technique ID format '{technique_id}'. "
                             f"Expected format is '{valid_technique_prefix}' followed by digits.")
            
            # Check if expected indicators are provided
            if not step.get("expected_indicators"):
                errors.append(f"Step {i+1}: No expected indicators provided for technique '{technique_id}'.")
        
        return errors
    
    def _validate_resources(self, scenario_data: Dict[str, Any]) -> List[str]:
        """
        Validate resources defined in the scenario.
        
        Args:
            scenario_data: Scenario data to validate
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Get resources
        resources = scenario_data.get("environment_config", {}).get("resources", {})
        
        # Validate resources based on platform
        platform = scenario_data.get("platform", {})
        provider = platform.get("name", "").lower()
        
        if provider and resources:
            # Validate AWS resources
            if provider == "aws":
                valid_resources = {"ec2_instance", "s3_bucket", "iam_role", "iam_user", 
                                   "lambda_function", "cloudtrail", "cloudwatch_alarm"}
                
                for resource_type in resources.keys():
                    if resource_type not in valid_resources:
                        errors.append(f"Invalid AWS resource type: {resource_type}. "
                                     f"Valid types are: {', '.join(valid_resources)}.")
            
            # Validate Azure resources
            elif provider == "azure":
                valid_resources = {"virtual_machine", "storage_account", "managed_identity", 
                                   "app_service", "logic_app"}
                
                for resource_type in resources.keys():
                    if resource_type not in valid_resources:
                        errors.append(f"Invalid Azure resource type: {resource_type}. "
                                     f"Valid types are: {', '.join(valid_resources)}.")
            
            # Validate GCP resources
            elif provider == "gcp":
                valid_resources = {"compute_instance", "storage_bucket", "iam_service_account", 
                                   "cloud_function"}
                
                for resource_type in resources.keys():
                    if resource_type not in valid_resources:
                        errors.append(f"Invalid GCP resource type: {resource_type}. "
                                     f"Valid types are: {', '.join(valid_resources)}.")
        
        return errors
    
    def _validate_expected_alerts(self, scenario_data: Dict[str, Any]) -> List[str]:
        """
        Validate expected alerts in the scenario.
        
        Args:
            scenario_data: Scenario data to validate
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Get expected alerts
        expected_alerts = scenario_data.get("expected_alerts", [])
        service_name = scenario_data.get("platform", {}).get("service_name", "")
        
        for i, alert in enumerate(expected_alerts):
            # Check if time_to_detect_range is valid (min <= max)
            time_range = alert.get("time_to_detect_range", [0, 0])
            if len(time_range) == 2 and time_range[0] > time_range[1]:
                errors.append(f"Alert {i+1}: Invalid time_to_detect_range: min ({time_range[0]}) "
                             f"is greater than max ({time_range[1]}).")
            
            # Check if service matches the scenario's service
            if alert.get("service") != service_name:
                # This is just a warning, not an error
                logger.warning(f"Alert {i+1} service '{alert.get('service')}' does not match "
                              f"scenario service '{service_name}'.")
        
        return errors
    
    def validate_scenario_file(self, file_path: str) -> Dict[str, Any]:
        """
        Validate a scenario file.
        
        Args:
            file_path: Path to the scenario file
            
        Returns:
            Dictionary with validation results
        """
        try:
            with open(file_path, 'r') as f:
                scenario_data = json.load(f)
            
            return self.validate_scenario(scenario_data)
            
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Error reading or parsing scenario file: {str(e)}"]
            }