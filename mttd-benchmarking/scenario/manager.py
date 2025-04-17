"""
Scenario Manager for orchestrating test execution.
"""

import logging
import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union

from ..core.types import ThreatScenario, CloudPlatform, CloudProvider
from ..simulation.engine import ThreatSimulationEngine
from ..detection.monitor import DetectionMonitor
from ..metrics.collector import MetricsCollector
from ..reporting.generators import ReportGenerator
from .validator import ScenarioValidator

logger = logging.getLogger(__name__)


class ScenarioManager:
    """
    Manages the execution of test scenarios, orchestrating the entire
    testing lifecycle from setup to metrics collection and reporting.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the scenario manager.
        
        Args:
            config: Configuration for the scenario manager
        """
        self.config = config
        self.scenarios_dir = config.get("scenarios_dir", "config/scenarios")
        self.results_dir = config.get("results_dir", "results")
        
        # Initialize components
        self.simulation_engine = ThreatSimulationEngine(config.get("simulation", {}))
        self.detection_monitor = DetectionMonitor(config.get("monitoring", {}))
        self.metrics_collector = MetricsCollector(config.get("metrics", {}))
        self.report_generator = ReportGenerator(config.get("reporting", {}))
        self.validator = ScenarioValidator()
        
        # Create directories
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.scenarios_dir, exist_ok=True)
    
    def load_scenario(self, scenario_id: str) -> ThreatScenario:
        """
        Load a scenario from the scenarios directory.
        
        Args:
            scenario_id: ID of the scenario to load
            
        Returns:
            ThreatScenario object
        """
        # Find scenario file - check both with and without .json extension
        scenario_path = os.path.join(self.scenarios_dir, f"{scenario_id}.json")
        if not os.path.exists(scenario_path) and not scenario_id.endswith(".json"):
            scenario_path = os.path.join(self.scenarios_dir, scenario_id)
        
        logger.info(f"Loading scenario from {scenario_path}")
        
        if not os.path.exists(scenario_path):
            raise FileNotFoundError(f"Scenario file not found: {scenario_path}")
            
        with open(scenario_path, 'r') as f:
            scenario_data = json.load(f)
        
        # Validate scenario
        validation_result = self.validator.validate_scenario(scenario_data)
        if not validation_result["valid"]:
            error_msg = f"Invalid scenario: {', '.join(validation_result['errors'])}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Create scenario object
        scenario = ThreatScenario.from_dict(scenario_data)
        
        return scenario
    
    def list_available_scenarios(self) -> List[Dict[str, str]]:
        """
        List all available scenarios.
        
        Returns:
            List of dictionaries with scenario ID and name
        """
        scenarios = []
        
        for filename in os.listdir(self.scenarios_dir):
            if filename.endswith(".json"):
                scenario_id = os.path.splitext(filename)[0]
                
                try:
                    with open(os.path.join(self.scenarios_dir, filename), 'r') as f:
                        data = json.load(f)
                        scenarios.append({
                            "id": scenario_id,
                            "name": data.get("name", "Unknown"),
                            "description": data.get("description", ""),
                            "provider": data.get("platform", {}).get("name", "unknown"),
                            "service": data.get("platform", {}).get("service_name", "unknown")
                        })
                except Exception as e:
                    logger.error(f"Error reading scenario {filename}: {str(e)}")
        
        return scenarios
    
    def execute_scenario(self, scenario_id: str, service_override: str = None) -> Dict[str, Any]:
        """
        Execute a scenario and collect metrics.
        
        Args:
            scenario_id: ID of the scenario to execute
            service_override: Optional service name to override scenario's service
            
        Returns:
            Dictionary with execution results and metrics
        """
        logger.info(f"Executing scenario {scenario_id}")
        
        # Load scenario
        scenario = self.load_scenario(scenario_id)
        
        # Override service if specified
        if service_override:
            logger.info(f"Overriding service {scenario.platform.service_name} with {service_override}")
            scenario.platform.service_name = service_override
        
        # Execute simulation
        simulation_result = self.simulation_engine.execute_scenario(scenario)
        
        # Start monitoring for detections
        self.detection_monitor.start_monitoring(simulation_result, scenario)
        
        # Collect metrics
        metrics_result = self.metrics_collector.collect_metrics(
            simulation_result=simulation_result,
            detection_monitor=self.detection_monitor,
            wait_for_detections=True
        )
        
        # Stop monitoring
        self.detection_monitor.stop_monitoring(simulation_result.simulation_id)
        
        # Save results
        self._save_execution_results(scenario, simulation_result, metrics_result)
        
        # Return results
        return {
            "scenario": {
                "id": scenario.id,
                "name": scenario.name,
                "provider": scenario.platform.provider.value,
                "service": scenario.platform.service_name
            },
            "simulation": {
                "id": simulation_result.simulation_id,
                "status": simulation_result.status,
                "start_time": simulation_result.start_time.isoformat(),
                "end_time": simulation_result.end_time.isoformat() if simulation_result.end_time else None,
                "steps_executed": len(simulation_result.execution_steps),
                "indicators_generated": len(simulation_result.indicators)
            },
            "metrics": {
                "id": metrics_result.metrics_id,
                "mttd": metrics_result.mttd,
                "detection_rate": metrics_result.detection_rate,
                "false_positives": metrics_result.false_positives,
                "severity_distribution": metrics_result.severity_distribution
            }
        }
    
    def execute_benchmark(self, scenario_ids: List[str], services: List[str] = None) -> Dict[str, Any]:
        """
        Execute a benchmark across multiple scenarios and services.
        
        Args:
            scenario_ids: List of scenario IDs to execute
            services: List of service names to benchmark
            
        Returns:
            Dictionary with benchmark results
        """
        logger.info(f"Executing benchmark with {len(scenario_ids)} scenarios")
        
        # Load scenarios
        scenarios = []
        for scenario_id in scenario_ids:
            try:
                scenario = self.load_scenario(scenario_id)
                scenarios.append(scenario)
            except Exception as e:
                logger.error(f"Error loading scenario {scenario_id}: {str(e)}")
                # Continue with other scenarios
        
        if not scenarios:
            raise ValueError("No valid scenarios found")
            
        # Determine services to test
        if not services:
            # If no services specified, use the services from the scenarios
            services = list(set(scenario.platform.service_name for scenario in scenarios))
        
        logger.info(f"Benchmarking across {len(services)} services: {', '.join(services)}")
        
        # Track results
        all_simulation_results = []
        all_metrics_results = []
        service_details = {}
        
        # Collect service details
        for service_name in services:
            service_config = self.config.get("services", {}).get(service_name, {})
            service_details[service_name] = {
                "name": service_name,
                "type": service_config.get("type", "unknown"),
                "version": service_config.get("version", "unknown"),
                "provider": service_config.get("provider", "unknown")
            }
        
        # Execute each scenario for each service
        for scenario in scenarios:
            original_service = scenario.platform.service_name
            
            for service_name in services:
                try:
                    # Clone and modify scenario to use this service
                    scenario.platform.service_name = service_name
                    
                    logger.info(f"Executing scenario {scenario.id} with service {service_name}")
                    
                    # Execute simulation
                    simulation_result = self.simulation_engine.execute_scenario(scenario)
                    all_simulation_results.append(simulation_result)
                    
                    # Monitor for detections
                    self.detection_monitor.start_monitoring(simulation_result, scenario)
                    
                    # Collect metrics
                    metrics_result = self.metrics_collector.collect_metrics(
                        simulation_result=simulation_result,
                        detection_monitor=self.detection_monitor,
                        wait_for_detections=True
                    )
                    all_metrics_results.append(metrics_result)
                    
                    # Stop monitoring
                    self.detection_monitor.stop_monitoring(simulation_result.simulation_id)
                    
                    # Save individual results
                    self._save_execution_results(scenario, simulation_result, metrics_result)
                    
                except Exception as e:
                    logger.error(f"Error in benchmark execution for {scenario.id} on {service_name}: {str(e)}")
            
            # Restore original service
            scenario.platform.service_name = original_service
        
        # Generate benchmark report
        benchmark_report = self.report_generator.generate_benchmark_report(
            metrics_results=all_metrics_results,
            simulation_results=all_simulation_results,
            service_details=service_details
        )
        
        # Save benchmark report
        self._save_benchmark_report(benchmark_report)
        
        # Return benchmark summary
        return {
            "report_id": benchmark_report.report_id,
            "services_compared": list(service_details.keys()),
            "scenarios_executed": [scenario.id for scenario in scenarios],
            "service_comparison": benchmark_report.service_comparison,
            "execution_count": len(all_simulation_results),
            "generation_time": benchmark_report.generation_time.isoformat()
        }
    
    def _save_execution_results(
        self, 
        scenario: ThreatScenario, 
        simulation_result: Any, 
        metrics_result: Any
    ) -> None:
        """
        Save execution results to files.
        
        Args:
            scenario: The executed scenario
            simulation_result: The simulation result
            metrics_result: The metrics result
        """
        # Create results directory for this simulation
        sim_dir = os.path.join(self.results_dir, simulation_result.simulation_id)
        os.makedirs(sim_dir, exist_ok=True)
        
        # Save scenario summary
        with open(os.path.join(sim_dir, "scenario.json"), 'w') as f:
            json.dump({
                "id": scenario.id,
                "name": scenario.name,
                "description": scenario.description,
                "platform": {
                    "provider": scenario.platform.provider.value,
                    "service_name": scenario.platform.service_name,
                    "region": scenario.platform.region
                }
            }, f, indent=2)
        
        # Save simulation result summary
        with open(os.path.join(sim_dir, "simulation.json"), 'w') as f:
            json.dump({
                "simulation_id": simulation_result.simulation_id,
                "scenario_id": scenario.id,
                "status": simulation_result.status,
                "start_time": simulation_result.start_time.isoformat(),
                "end_time": simulation_result.end_time.isoformat() if simulation_result.end_time else None,
                "steps_executed": len(simulation_result.execution_steps),
                "indicators_generated": len(simulation_result.indicators)
            }, f, indent=2)
        
        # Save detailed execution steps
        with open(os.path.join(sim_dir, "execution_steps.json"), 'w') as f:
            json.dump(simulation_result.execution_steps, f, indent=2)
        
        # Save indicators
        with open(os.path.join(sim_dir, "indicators.json"), 'w') as f:
            json.dump(simulation_result.indicators, f, indent=2)
        
        # Metrics are saved by the metrics collector
        
        logger.info(f"Saved execution results to {sim_dir}")
    
    def _save_benchmark_report(self, benchmark_report: Any) -> None:
        """
        Save benchmark report to file.
        
        Args:
            benchmark_report: The benchmark report
        """
        # Ensure reports directory exists
        reports_dir = os.path.join(self.results_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Save report as JSON
        report_file = os.path.join(reports_dir, f"benchmark_{benchmark_report.report_id}.json")
        
        # Convert to dictionary
        report_dict = {
            "report_id": benchmark_report.report_id,
            "generation_time": benchmark_report.generation_time.isoformat(),
            "service_comparison": benchmark_report.service_comparison,
            "service_details": benchmark_report.service_details
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_dict, f, indent=2)
            
        logger.info(f"Saved benchmark report to {report_file}")
    
    def create_scenario(self, scenario_data: Dict[str, Any]) -> str:
        """
        Create a new scenario from provided data.
        
        Args:
            scenario_data: Dictionary with scenario data
            
        Returns:
            ID of the created scenario
        """
        # Validate scenario
        validation_result = self.validator.validate_scenario(scenario_data)
        if not validation_result["valid"]:
            error_msg = f"Invalid scenario: {', '.join(validation_result['errors'])}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Generate ID if not provided
        if "id" not in scenario_data:
            # Create ID based on name
            if "name" in scenario_data:
                base_id = scenario_data["name"].lower().replace(" ", "-")
                # Keep only alphanumeric and hyphen characters
                base_id = ''.join(c for c in base_id if c.isalnum() or c == '-')
                # Append timestamp to ensure uniqueness
                scenario_data["id"] = f"{base_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            else:
                scenario_data["id"] = f"scenario-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Save scenario
        scenario_path = os.path.join(self.scenarios_dir, f"{scenario_data['id']}.json")
        
        with open(scenario_path, 'w') as f:
            json.dump(scenario_data, f, indent=2)
            
        logger.info(f"Created scenario {scenario_data['id']}")
        
        return scenario_data["id"]
    
    def update_scenario(self, scenario_id: str, scenario_data: Dict[str, Any]) -> bool:
        """
        Update an existing scenario.
        
        Args:
            scenario_id: ID of the scenario to update
            scenario_data: Updated scenario data
            
        Returns:
            True if successful, False otherwise
        """
        # Validate scenario
        validation_result = self.validator.validate_scenario(scenario_data)
        if not validation_result["valid"]:
            error_msg = f"Invalid scenario: {', '.join(validation_result['errors'])}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Find scenario file
        scenario_path = os.path.join(self.scenarios_dir, f"{scenario_id}.json")
        if not os.path.exists(scenario_path) and not scenario_id.endswith(".json"):
            scenario_path = os.path.join(self.scenarios_dir, scenario_id)
            
        if not os.path.exists(scenario_path):
            logger.error(f"Scenario not found: {scenario_id}")
            return False
        
        # Ensure ID is preserved
        scenario_data["id"] = scenario_id
        
        # Save updated scenario
        with open(scenario_path, 'w') as f:
            json.dump(scenario_data, f, indent=2)
            
        logger.info(f"Updated scenario {scenario_id}")
        
        return True
    
    def delete_scenario(self, scenario_id: str) -> bool:
        """
        Delete a scenario.
        
        Args:
            scenario_id: ID of the scenario to delete
            
        Returns:
            True if successful, False otherwise
        """
        # Find scenario file
        scenario_path = os.path.join(self.scenarios_dir, f"{scenario_id}.json")
        if not os.path.exists(scenario_path) and not scenario_id.endswith(".json"):
            scenario_path = os.path.join(self.scenarios_dir, scenario_id)
            
        if not os.path.exists(scenario_path):
            logger.error(f"Scenario not found: {scenario_id}")
            return False
        
        # Delete scenario
        os.remove(scenario_path)
        logger.info(f"Deleted scenario {scenario_id}")
        
        return True
    
    def get_benchmark_reports(self) -> List[Dict[str, Any]]:
        """
        Get a list of all benchmark reports.
        
        Returns:
            List of benchmark report summaries
        """
        reports = []
        reports_dir = os.path.join(self.results_dir, "reports")
        
        if not os.path.exists(reports_dir):
            return reports
            
        for filename in os.listdir(reports_dir):
            if filename.startswith("benchmark_") and filename.endswith(".json"):
                report_path = os.path.join(reports_dir, filename)
                
                try:
                    with open(report_path, 'r') as f:
                        report_data = json.load(f)
                        
                    # Create a summary
                    reports.append({
                        "report_id": report_data.get("report_id"),
                        "generation_time": report_data.get("generation_time"),
                        "services": list(report_data.get("service_comparison", {}).get("mttd", {}).keys()),
                        "file_path": report_path
                    })
                    
                except Exception as e:
                    logger.error(f"Error reading report {filename}: {str(e)}")
        
        # Sort by generation time (most recent first)
        reports.sort(key=lambda r: r.get("generation_time", ""), reverse=True)
        
        return reports
    
    def get_benchmark_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific benchmark report.
        
        Args:
            report_id: ID of the report to get
            
        Returns:
            Benchmark report or None if not found
        """
        report_path = os.path.join(self.results_dir, "reports", f"benchmark_{report_id}.json")
        
        if not os.path.exists(report_path):
            logger.warning(f"Benchmark report not found: {report_id}")
            return None
            
        try:
            with open(report_path, 'r') as f:
                report_data = json.load(f)
                
            return report_data
            
        except Exception as e:
            logger.error(f"Error reading benchmark report {report_id}: {str(e)}")
            return None