"""
Metrics Collection for gathering and managing detection metrics.
"""

import logging
import uuid
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union

from ..core.types import SimulationResult, DetectionEvent, MetricsResult
from ..detection.monitor import DetectionMonitor
from .analyzer import MetricsAnalyzer

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Collects and analyzes metrics related to threat detection,
    calculating MTTD and other key performance indicators.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the metrics collector.
        
        Args:
            config: Configuration for the metrics collector
        """
        self.config = config
        self.detection_timeout = config.get("detection_timeout", 3600)  # Default 1 hour
        self.results_dir = config.get("results_dir", "results")
        self.analyzer = MetricsAnalyzer(config.get("analyzer", {}))
        
        # Create results directory if it doesn't exist
        os.makedirs(self.results_dir, exist_ok=True)
    
    def collect_metrics(
        self, 
        simulation_result: SimulationResult,
        detection_monitor: DetectionMonitor,
        wait_for_detections: bool = True
    ) -> MetricsResult:
        """
        Collect and analyze metrics for a completed simulation.
        
        Args:
            simulation_result: The completed simulation result
            detection_monitor: The detection monitor instance
            wait_for_detections: Whether to wait for detection events
            
        Returns:
            MetricsResult containing analyzed metrics
        """
        logger.info(f"Collecting metrics for simulation {simulation_result.simulation_id}")
        
        # Get service name from simulation context
        service_name = self._extract_service_name(simulation_result)
        
        # Collect detection events with timeout if waiting
        timeout = self.detection_timeout if wait_for_detections else 0
        detection_events = detection_monitor.get_detection_events(
            simulation_result.simulation_id,
            timeout=timeout
        )
        
        logger.info(f"Collected {len(detection_events)} detection events for analysis")
        
        # Analyze detection events
        metrics_result = self.analyzer.analyze_detection_events(
            simulation_result=simulation_result,
            detection_events=detection_events,
            service_name=service_name
        )
        
        # Save metrics result
        self._save_metrics_result(metrics_result, simulation_result.simulation_id)
        
        return metrics_result
    
    def collect_metrics_for_benchmark(
        self,
        simulation_results: List[SimulationResult],
        detection_monitor: DetectionMonitor
    ) -> Dict[str, Union[List[MetricsResult], Dict[str, Any]]]:
        """
        Collect metrics for multiple simulations in a benchmark.
        
        Args:
            simulation_results: List of simulation results
            detection_monitor: The detection monitor instance
            
        Returns:
            Dictionary with lists of metrics results and aggregated metrics
        """
        all_metrics = []
        metrics_by_service = {}
        
        # Collect metrics for each simulation
        for simulation_result in simulation_results:
            metrics_result = self.collect_metrics(
                simulation_result=simulation_result,
                detection_monitor=detection_monitor,
                wait_for_detections=True
            )
            
            all_metrics.append(metrics_result)
            
            # Group by service
            service_name = metrics_result.service_name
            if service_name not in metrics_by_service:
                metrics_by_service[service_name] = []
                
            metrics_by_service[service_name].append(metrics_result)
        
        # Calculate aggregate metrics for each service
        aggregate_metrics = {}
        for service_name, metrics_list in metrics_by_service.items():
            aggregate_metrics[service_name] = self.analyzer.calculate_aggregate_metrics(metrics_list)
        
        # Return all metrics and aggregated metrics
        return {
            "metrics_results": all_metrics,
            "aggregate_metrics": aggregate_metrics
        }
    
    def _extract_service_name(self, simulation_result: SimulationResult) -> str:
        """Extract service name from simulation result context."""
        # This would typically come from the scenario, but we don't have that context here
        # In a real implementation, this would be passed in or stored in the simulation result
        return "unknown_service"
    
    def _save_metrics_result(self, metrics_result: MetricsResult, simulation_id: str) -> None:
        """
        Save metrics result to file.
        
        Args:
            metrics_result: The metrics result to save
            simulation_id: The simulation ID
        """
        # Create directory for this simulation if it doesn't exist
        simulation_dir = os.path.join(self.results_dir, simulation_id)
        os.makedirs(simulation_dir, exist_ok=True)
        
        # Save metrics as JSON
        metrics_file = os.path.join(simulation_dir, f"metrics_{metrics_result.metrics_id}.json")
        
        # Convert to dictionary
        metrics_dict = {
            "metrics_id": metrics_result.metrics_id,
            "simulation_id": metrics_result.simulation_id,
            "scenario_id": metrics_result.scenario_id,
            "service_name": metrics_result.service_name,
            "calculation_time": metrics_result.calculation_time.isoformat(),
            "mttd": metrics_result.mttd,
            "detection_rate": metrics_result.detection_rate,
            "false_positives": metrics_result.false_positives,
            "severity_distribution": metrics_result.severity_distribution,
            "technique_detection_times": metrics_result.technique_detection_times,
            "indicator_detection_times": metrics_result.indicator_detection_times,
            "alerts_matched": metrics_result.alerts_matched,
            "alerts_missed": metrics_result.alerts_missed
        }
        
        with open(metrics_file, 'w') as f:
            json.dump(metrics_dict, f, indent=2)
            
        logger.info(f"Saved metrics result to {metrics_file}")
    
    def load_metrics_result(self, metrics_id: str, simulation_id: str) -> Optional[MetricsResult]:
        """
        Load metrics result from file.
        
        Args:
            metrics_id: The metrics ID
            simulation_id: The simulation ID
            
        Returns:
            Loaded MetricsResult or None if not found
        """
        metrics_file = os.path.join(self.results_dir, simulation_id, f"metrics_{metrics_id}.json")
        
        if not os.path.exists(metrics_file):
            logger.warning(f"Metrics file not found: {metrics_file}")
            return None
        
        try:
            with open(metrics_file, 'r') as f:
                metrics_dict = json.load(f)
            
            # Convert to MetricsResult
            return MetricsResult(
                metrics_id=metrics_dict["metrics_id"],
                simulation_id=metrics_dict["simulation_id"],
                scenario_id=metrics_dict["scenario_id"],
                service_name=metrics_dict["service_name"],
                calculation_time=datetime.fromisoformat(metrics_dict["calculation_time"]),
                mttd=metrics_dict["mttd"],
                detection_rate=metrics_dict["detection_rate"],
                false_positives=metrics_dict["false_positives"],
                severity_distribution=metrics_dict["severity_distribution"],
                technique_detection_times=metrics_dict["technique_detection_times"],
                indicator_detection_times=metrics_dict["indicator_detection_times"],
                alerts_matched=metrics_dict["alerts_matched"],
                alerts_missed=metrics_dict["alerts_missed"]
            )
            
        except Exception as e:
            logger.error(f"Error loading metrics file {metrics_file}: {str(e)}")
            return None
    
    def get_all_metrics_for_simulation(self, simulation_id: str) -> List[MetricsResult]:
        """
        Get all metrics results for a simulation.
        
        Args:
            simulation_id: The simulation ID
            
        Returns:
            List of MetricsResult objects
        """
        simulation_dir = os.path.join(self.results_dir, simulation_id)
        
        if not os.path.exists(simulation_dir):
            logger.warning(f"Simulation directory not found: {simulation_dir}")
            return []
        
        metrics_results = []
        
        # Find all metrics files
        for filename in os.listdir(simulation_dir):
            if filename.startswith("metrics_") and filename.endswith(".json"):
                metrics_id = filename[8:-5]  # Extract metrics ID from filename
                
                metrics_result = self.load_metrics_result(metrics_id, simulation_id)
                if metrics_result:
                    metrics_results.append(metrics_result)
        
        return metrics_results