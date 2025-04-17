"""
Detection Monitoring System for tracking security alerts.
"""

import logging
import threading
import queue
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
import uuid

from ..core.types import (
    SimulationResult, 
    ThreatScenario, 
    DetectionEvent,
    DetectionSeverity
)
from ..services.factory import get_security_client
from .correlation import EventCorrelator

logger = logging.getLogger(__name__)


class DetectionMonitor:
    """
    Monitors cloud security services for detection events related to
    simulated threats and correlates them with simulation activities.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the detection monitor.
        
        Args:
            config: Configuration for the detection monitor
        """
        self.config = config
        self.is_monitoring = False
        self.monitoring_threads = {}
        self.event_queues = {}
        self.active_simulations = {}
        self.service_clients = {}
        self.correlator = EventCorrelator()
        self.polling_interval = config.get("polling_interval", 30)  # seconds
        self.correlation_threshold = config.get("correlation_threshold", 0.6)  # 60% confidence
    
    def start_monitoring(self, simulation_result: SimulationResult, scenario: ThreatScenario) -> None:
        """
        Start monitoring for detection events related to a simulation.
        
        Args:
            simulation_result: The active simulation to monitor
            scenario: The scenario being executed
        """
        simulation_id = simulation_result.simulation_id
        
        # Initialize queue for this simulation
        if simulation_id not in self.event_queues:
            self.event_queues[simulation_id] = queue.Queue()
        
        # Store simulation details
        self.active_simulations[simulation_id] = {
            "scenario": scenario,
            "result": simulation_result,
            "start_time": datetime.now()
        }
        
        # Initialize security service client if not already done
        service_name = scenario.platform.service_name
        if service_name not in self.service_clients:
            try:
                self.service_clients[service_name] = get_security_client(
                    service_name=service_name,
                    provider=scenario.platform.provider,
                    region=scenario.platform.region,
                    config=scenario.platform.config
                )
                logger.info(f"Initialized security client for service: {service_name}")
            except Exception as e:
                logger.error(f"Failed to initialize security client for {service_name}: {str(e)}")
                # Continue even without the client, as we might have others
        
        # Start monitoring thread if not already running for this service
        if service_name not in self.monitoring_threads or not self.monitoring_threads[service_name].is_alive():
            thread = threading.Thread(
                target=self._monitoring_worker,
                args=(service_name,),
                daemon=True,
                name=f"monitor-{service_name}"
            )
            self.monitoring_threads[service_name] = thread
            thread.start()
            logger.info(f"Started monitoring thread for service: {service_name}")
    
    def stop_monitoring(self, simulation_id: str) -> None:
        """
        Stop monitoring for a specific simulation.
        
        Args:
            simulation_id: ID of the simulation to stop monitoring
        """
        if simulation_id in self.active_simulations:
            # Get the service being used by this simulation
            service_name = self.active_simulations[simulation_id]["scenario"].platform.service_name
            
            # Remove simulation from active simulations
            del self.active_simulations[simulation_id]
            logger.info(f"Stopped monitoring for simulation {simulation_id}")
            
            # Check if this service has any other active simulations
            service_has_simulations = any(
                self.active_simulations[sim_id]["scenario"].platform.service_name == service_name
                for sim_id in self.active_simulations
            )
            
            # If no more simulations use this service, stop the monitoring thread
            if not service_has_simulations and service_name in self.monitoring_threads:
                # Thread will exit on next polling cycle when it checks active_simulations
                logger.info(f"No more simulations using service {service_name}, monitoring thread will exit")
    
    def get_detection_events(self, simulation_id: str, timeout: int = 0) -> List[DetectionEvent]:
        """
        Get detection events for a specific simulation.
        
        Args:
            simulation_id: The ID of the simulation
            timeout: How long to wait for events in seconds (0 = no wait)
            
        Returns:
            List of detection events related to the simulation
        """
        if simulation_id not in self.event_queues:
            logger.warning(f"No event queue for simulation {simulation_id}")
            return []
            
        events = []
        queue = self.event_queues[simulation_id]
        start_time = time.time()
        
        while True:
            try:
                event = queue.get(block=timeout > 0, timeout=1)
                events.append(event)
                queue.task_done()
            except queue.Empty:
                # No more events available right now
                pass
                
            # Check if we've waited long enough or got some events with no timeout
            if (timeout > 0 and time.time() - start_time >= timeout) or (timeout == 0 and events):
                break
        
        return events
    
    def _monitoring_worker(self, service_name: str) -> None:
        """
        Worker thread that polls security services for events.
        
        Args:
            service_name: The security service to monitor
        """
        logger.info(f"Monitoring worker started for service {service_name}")
        client = self.service_clients.get(service_name)
        
        if not client:
            logger.error(f"No client available for service {service_name}")
            return
            
        # Track the last poll time to avoid duplicate events
        last_poll_time = datetime.now() - timedelta(minutes=5)
        
        while True:
            # Check if service has any active simulations
            service_simulations = [
                sim_id for sim_id, details in self.active_simulations.items()
                if details["scenario"].platform.service_name == service_name
            ]
            
            # Exit if no active simulations for this service
            if not service_simulations:
                logger.info(f"No active simulations for service {service_name}, exiting monitoring worker")
                break
                
            # Poll for new security events
            try:
                current_time = datetime.now()
                
                new_events = client.get_security_events(
                    start_time=last_poll_time,
                    end_time=current_time
                )
                
                last_poll_time = current_time
                
                # Process and correlate events
                if new_events:
                    logger.info(f"Retrieved {len(new_events)} new events from {service_name}")
                    self._process_events(new_events, service_name, service_simulations)
                    
            except Exception as e:
                logger.error(f"Error polling {service_name}: {str(e)}")
            
            # Sleep before next polling cycle
            time.sleep(self.polling_interval)
    
    def _process_events(self, 
                       raw_events: List[Dict[str, Any]], 
                       service_name: str, 
                       simulation_ids: List[str]) -> None:
        """
        Process and correlate raw security events.
        
        Args:
            raw_events: Raw events from the security service
            service_name: Name of the service that produced the events
            simulation_ids: IDs of active simulations using this service
        """
        # Process each event
        for raw_event in raw_events:
            try:
                # Extract basic event details
                event_id = self._extract_event_id(raw_event)
                detection_time = self._extract_detection_time(raw_event)
                event_type = self._extract_event_type(raw_event)
                severity = self._extract_severity(raw_event)
                
                if not event_id or not detection_time:
                    logger.warning(f"Skipping event with missing ID or timestamp: {raw_event}")
                    continue
                
                # For each active simulation, try to correlate the event
                for sim_id in simulation_ids:
                    simulation_data = self.active_simulations.get(sim_id)
                    
                    if not simulation_data:
                        continue
                        
                    # Get simulation result with indicators
                    sim_result = simulation_data["result"]
                    
                    # Skip if event time is before simulation start
                    if detection_time < simulation_data["start_time"]:
                        continue
                    
                    # Correlate event with simulation indicators
                    correlation_result = self.correlator.correlate_event(
                        raw_event=raw_event,
                        simulation_result=sim_result,
                        correlation_threshold=self.correlation_threshold
                    )
                    
                    # If correlated, create detection event and add to queue
                    if correlation_result["correlated"]:
                        logger.info(f"Event {event_id} correlated with simulation {sim_id} "
                                    f"(confidence: {correlation_result['confidence']:.2f})")
                        
                        detection_event = DetectionEvent(
                            event_id=event_id,
                            simulation_id=sim_id,
                            service_name=service_name,
                            detection_time=detection_time,
                            event_type=event_type,
                            severity=severity,
                            related_indicators=correlation_result["indicators"],
                            raw_event=raw_event,
                            is_false_positive=correlation_result["is_false_positive"]
                        )
                        
                        # Add to the queue
                        if sim_id in self.event_queues:
                            self.event_queues[sim_id].put(detection_event)
            
            except Exception as e:
                logger.error(f"Error processing event: {str(e)}")
    
    def _extract_event_id(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract event ID from raw event."""
        for field in ["id", "eventId", "findingId", "alertId", "uuid"]:
            if field in event:
                return str(event[field])
        
        # Generate ID if not found
        return str(uuid.uuid4())
    
    def _extract_detection_time(self, event: Dict[str, Any]) -> Optional[datetime]:
        """Extract detection timestamp from raw event."""
        for field in ["timestamp", "detectionTime", "eventTime", "time", "createdAt", "updateTime", "firstObservedAt"]:
            if field in event:
                try:
                    # Handle string timestamps
                    if isinstance(event[field], str):
                        return datetime.fromisoformat(event[field].replace('Z', '+00:00'))
                    # Handle epoch timestamps
                    elif isinstance(event[field], (int, float)):
                        return datetime.fromtimestamp(event[field])
                except (ValueError, TypeError):
                    pass
        
        # Use current time if not found
        return datetime.now()
    
    def _extract_event_type(self, event: Dict[str, Any]) -> str:
        """Extract event type from raw event."""
        for field in ["eventType", "type", "category", "findingType", "alertType"]:
            if field in event:
                return str(event[field])
        return "unknown"
    
    def _extract_severity(self, event: Dict[str, Any]) -> DetectionSeverity:
        """Extract severity from raw event."""
        # Default to medium severity
        default_severity = DetectionSeverity.MEDIUM
        
        # Check common severity fields
        for field in ["severity", "criticalLevel", "priority", "riskLevel"]:
            if field in event:
                severity_value = event[field]
                
                # Map string severities to our enum
                if isinstance(severity_value, str):
                    severity_map = {
                        "critical": DetectionSeverity.CRITICAL,
                        "high": DetectionSeverity.HIGH,
                        "medium": DetectionSeverity.MEDIUM,
                        "low": DetectionSeverity.LOW,
                        "informational": DetectionSeverity.INFORMATIONAL,
                        "info": DetectionSeverity.INFORMATIONAL
                    }
                    
                    return severity_map.get(severity_value.lower(), default_severity)
                
                # Map numeric severities (assuming 1-5 scale, 5 being highest)
                elif isinstance(severity_value, (int, float)):
                    if severity_value >= 4:
                        return DetectionSeverity.CRITICAL
                    elif severity_value >= 3:
                        return DetectionSeverity.HIGH
                    elif severity_value >= 2:
                        return DetectionSeverity.MEDIUM
                    elif severity_value >= 1:
                        return DetectionSeverity.LOW
                    else:
                        return DetectionSeverity.INFORMATIONAL
        
        return default_severity