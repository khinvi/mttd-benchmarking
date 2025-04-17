"""
Threat Simulation Engine for executing attack scenarios.
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from ..core.types import (
    ThreatScenario, 
    SimulationResult, 
    CloudProvider,
    AttackStep,
    ResourceConfig
)
from ..services.factory import get_platform_client

logger = logging.getLogger(__name__)


class ThreatSimulationEngine:
    """
    Core engine for executing attack simulations across different cloud environments.
    Implements various attack techniques based on the MITRE ATT&CK framework.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the threat simulation engine.
        
        Args:
            config: Configuration parameters for the simulation engine
        """
        self.config = config
        self.simulation_id = None
        self.platform_clients = {}
    
    def execute_scenario(self, scenario: ThreatScenario) -> SimulationResult:
        """
        Execute a specific threat scenario.
        
        Args:
            scenario: The threat scenario to execute
            
        Returns:
            SimulationResult containing execution details and timestamps
        """
        self.simulation_id = str(uuid.uuid4())
        logger.info(f"Starting simulation {self.simulation_id} - Scenario: {scenario.name}")
        
        result = SimulationResult(
            simulation_id=self.simulation_id,
            scenario_id=scenario.id,
            start_time=datetime.now(),
            status="initializing"
        )
        
        try:
            # Get platform client
            platform_client = get_platform_client(
                provider=scenario.platform.provider,
                config=scenario.platform.config,
                region=scenario.platform.region
            )
            
            # Execute pre-simulation setup
            self._prepare_environment(scenario, platform_client, result)
            
            # Execute attack steps
            result.status = "executing"
            for step in scenario.steps:
                step_result = self._execute_step(step, platform_client, scenario)
                result.execution_steps.append(step_result)
                
                # Generate indicators for detection
                indicators = self._generate_indicators(step, step_result)
                result.indicators.extend(indicators)
                
                if step_result.get("status") == "failed":
                    logger.warning(f"Step {step.name} failed, continuing scenario")
            
            result.status = "completed"
            result.end_time = datetime.now()
            
        except Exception as e:
            logger.error(f"Simulation failed: {str(e)}")
            result.status = "failed"
            result.end_time = datetime.now()
            result.error = str(e)
            
        finally:
            # Always attempt cleanup
            try:
                if 'platform_client' in locals():
                    self._cleanup_environment(scenario, platform_client, result)
            except Exception as e:
                logger.error(f"Cleanup failed: {str(e)}")
                result.cleanup_error = str(e)
            
        return result
    
    def _prepare_environment(self, scenario: ThreatScenario, platform_client: Any, result: SimulationResult):
        """
        Prepare the environment for simulation.
        
        Args:
            scenario: The scenario being executed
            platform_client: The platform client to use
            result: The simulation result to update
        """
        logger.info(f"Preparing environment for {scenario.platform.provider.value}")
        
        # Create resources defined in the scenario
        created_resources = []
        
        for resource_config in scenario.resources:
            try:
                logger.debug(f"Creating resource {resource_config.type.value}")
                
                # Generate resource name if not provided
                if not resource_config.name:
                    resource_config.name = f"mttd-{resource_config.type.value}-{uuid.uuid4().hex[:8]}"
                
                # Create the resource
                resource_id = platform_client.create_resource(
                    resource_type=resource_config.type,
                    resource_name=resource_config.name,
                    parameters=resource_config.parameters
                )
                
                created_resources.append({
                    "resource_id": resource_id,
                    "resource_type": resource_config.type.value,
                    "resource_name": resource_config.name
                })
                
                logger.info(f"Created resource {resource_config.type.value} with ID {resource_id}")
                
            except Exception as e:
                logger.error(f"Failed to create resource {resource_config.type.value}: {str(e)}")
                # Continue with other resources instead of failing immediately
        
        # Update result with created resources
        result.resources_created = created_resources
        result.preparation_time = datetime.now()
    
    def _execute_step(self, step: AttackStep, platform_client: Any, scenario: ThreatScenario) -> Dict:
        """
        Execute a single attack step.
        
        Args:
            step: The attack step to execute
            platform_client: The platform client to use
            scenario: The complete scenario (for context)
            
        Returns:
            Dictionary with execution details
        """
        step_id = str(uuid.uuid4())
        logger.info(f"Executing step {step.name} ({step_id})")
        
        start_time = datetime.now()
        
        step_result = {
            "step_id": step_id,
            "step_name": step.name,
            "technique_id": step.technique_id,
            "category": step.category.value if step.category else None,
            "start_time": start_time.isoformat(),
            "status": "executing"
        }
        
        try:
            # Prepare parameters with resource references
            enriched_parameters = self._enrich_step_parameters(step.parameters, scenario.resources)
            
            # Execute the technique
            execution_result = platform_client.execute_technique(
                technique_id=step.technique_id,
                parameters=enriched_parameters,
                context={
                    "simulation_id": self.simulation_id,
                    "scenario_id": scenario.id,
                    "resources": [r for r in scenario.resources]
                }
            )
            
            step_result.update({
                "status": "completed",
                "end_time": datetime.now().isoformat(),
                "execution_details": execution_result
            })
            
        except Exception as e:
            logger.error(f"Step execution failed: {str(e)}")
            step_result.update({
                "status": "failed",
                "end_time": datetime.now().isoformat(),
                "error": str(e)
            })
        
        return step_result
    
    def _enrich_step_parameters(self, parameters: Dict[str, Any], resources: List[ResourceConfig]) -> Dict[str, Any]:
        """
        Enrich step parameters with actual resource info.
        
        Args:
            parameters: The original parameters
            resources: Available resources
            
        Returns:
            Enriched parameters
        """
        # Create a copy to avoid modifying the original
        enriched = parameters.copy()
        
        # Replace resource references
        for key, value in enriched.items():
            # Check for resource references (e.g., "$resource:s3_bucket_1")
            if isinstance(value, str) and value.startswith("$resource:"):
                resource_name = value.split(":", 1)[1]
                
                # Find the resource
                for resource in resources:
                    if resource.name == resource_name:
                        enriched[key] = resource.name
                        break
                else:
                    logger.warning(f"Resource reference not found: {value}")
        
        return enriched
    
    def _generate_indicators(self, step: AttackStep, step_result: Dict) -> List[Dict]:
        """
        Generate detection indicators for a step.
        
        Args:
            step: The executed step
            step_result: The step execution result
            
        Returns:
            List of indicators
        """
        indicators = []
        
        # Extract indicator info from step result
        if step_result.get("status") == "completed":
            for indicator_type in step.expected_indicators:
                indicator = {
                    "indicator_id": str(uuid.uuid4()),
                    "type": indicator_type,
                    "simulation_id": self.simulation_id,
                    "step_id": step_result.get("step_id"),
                    "step_name": step_result.get("step_name"),
                    "technique_id": step.technique_id,
                    "generation_time": datetime.now().isoformat(),
                    "details": step_result.get("execution_details", {}).get(indicator_type, {})
                }
                indicators.append(indicator)
        
        return indicators
    
    def _cleanup_environment(self, scenario: ThreatScenario, platform_client: Any, result: SimulationResult):
        """
        Clean up after simulation.
        
        Args:
            scenario: The scenario that was executed
            platform_client: The platform client to use
            result: The simulation result to update
        """
        logger.info(f"Cleaning up environment for {scenario.platform.provider.value}")
        
        # Clean up created resources in reverse order
        for resource in reversed(result.resources_created):
            try:
                logger.debug(f"Deleting resource {resource['resource_type']} with ID {resource['resource_id']}")
                
                platform_client.delete_resource(
                    resource_type=resource['resource_type'],
                    resource_id=resource['resource_id']
                )
                
                logger.info(f"Deleted resource {resource['resource_type']} with ID {resource['resource_id']}")
                
            except Exception as e:
                logger.error(f"Failed to delete resource {resource['resource_type']} with ID {resource['resource_id']}: {str(e)}")
                # Continue with other resources
        
        result.cleanup_time = datetime.now()