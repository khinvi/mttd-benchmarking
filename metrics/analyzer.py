"""
Metrics analysis for calculating MTTD and other security metrics.
"""

import logging
import uuid
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple, Union

from ..core.types import SimulationResult, DetectionEvent, MetricsResult, IndicatorMatch, DetectionSeverity

logger = logging.getLogger(__name__)


class MetricsAnalyzer:
    """
    Analyzes detection events to calculate MTTD and other key metrics.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the metrics analyzer.
        
        Args:
            config: Configuration for the analyzer
        """
        self.config = config or {}
    
    def analyze_detection_events(
        self,
        simulation_result: SimulationResult,
        detection_events: List[DetectionEvent],
        service_name: str
    ) -> MetricsResult:
        """
        Analyze detection events to calculate MTTD and other metrics.
        
        Args:
            simulation_result: The simulation result to analyze
            detection_events: List of detection events to analyze
            service_name: Name of the security service
            
        Returns:
            MetricsResult containing the analysis results
        """
        logger.info(f"Analyzing {len(detection_events)} detection events for simulation {simulation_result.simulation_id}")
        
        # Process indicators from simulation result
        indicators = self._process_indicators(simulation_result.indicators)
        
        # Match indicators with detection events
        indicator_matches = self._match_indicators_with_events(indicators, detection_events)
        
        # Calculate MTTD
        mttd, technique_detection_times, indicator_detection_times = self._calculate_mttd(indicator_matches)
        
        # Calculate detection rate
        detection_rate = self._calculate_detection_rate(indicators, indicator_matches)
        
        # Identify false positives
        false_positives = self._identify_false_positives(detection_events, indicator_matches)
        
        # Analyze severity distribution
        severity_distribution = self._analyze_severity_distribution(detection_events)
        
        # Create metrics result
        metrics_result = MetricsResult(
            metrics_id=str(uuid.uuid4()),
            simulation_id=simulation_result.simulation_id,
            scenario_id=simulation_result.scenario_id,
            service_name=service_name,
            calculation_time=datetime.now(),
            mttd=mttd,
            detection_rate=detection_rate,
            false_positives=len(false_positives),
            severity_distribution=severity_distribution,
            technique_detection_times=technique_detection_times,
            indicator_detection_times=indicator_detection_times,
            alerts_matched=[match.event_id for match in indicator_matches],
            alerts_missed=[]  # Would need expected alerts for this
        )
        
        logger.info(f"Metrics analysis complete - MTTD: {mttd} seconds, Detection rate: {detection_rate*100:.2f}%")
        return metrics_result
    
    def _process_indicators(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process indicators from simulation result.
        
        Args:
            indicators: List of indicators from simulation result
            
        Returns:
            Processed indicators
        """
        processed = []
        
        for indicator in indicators:
            # Clone the indicator
            processed_indicator = indicator.copy()
            
            # Convert timestamp string to datetime if needed
            if "generation_time" in indicator and isinstance(indicator["generation_time"], str):
                try:
                    processed_indicator["generation_time"] = datetime.fromisoformat(
                        indicator["generation_time"].replace('Z', '+00:00')
                    )
                except ValueError:
                    logger.warning(f"Invalid timestamp format: {indicator['generation_time']}")
                    # Use current time as fallback
                    processed_indicator["generation_time"] = datetime.now()
            
            # Ensure required fields
            if "indicator_id" not in processed_indicator:
                processed_indicator["indicator_id"] = str(uuid.uuid4())
                
            if "generation_time" not in processed_indicator:
                processed_indicator["generation_time"] = datetime.now()
            
            processed.append(processed_indicator)
        
        return processed
    
    def _match_indicators_with_events(
        self,
        indicators: List[Dict[str, Any]],
        events: List[DetectionEvent]
    ) -> List[IndicatorMatch]:
        """
        Match indicators with detection events.
        
        Args:
            indicators: List of processed indicators
            events: List of detection events
            
        Returns:
            List of indicator-event matches
        """
        matches = []
        
        # Create mapping of indicator IDs to indicators
        indicator_map = {indicator["indicator_id"]: indicator for indicator in indicators}
        
        # Check each event for matches with indicators
        for event in events:
            # Skip false positives
            if event.is_false_positive:
                continue
                
            # Check related indicators
            for indicator_id in event.related_indicators:
                if indicator_id in indicator_map:
                    indicator = indicator_map[indicator_id]
                    
                    matches.append(IndicatorMatch(
                        indicator_id=indicator_id,
                        event_id=event.event_id,
                        simulation_id=event.simulation_id,
                        indicator_time=indicator["generation_time"],
                        detection_time=event.detection_time
                    ))
        
        return matches
    
    def _calculate_mttd(
        self,
        indicator_matches: List[IndicatorMatch]
    ) -> Tuple[float, Dict[str, float], Dict[str, float]]:
        """
        Calculate Mean Time To Detect (MTTD) from indicator matches.
        
        Args:
            indicator_matches: List of indicator-event matches
            
        Returns:
            Tuple of (overall MTTD, technique detection times, indicator detection times)
        """
        if not indicator_matches:
            return -1.0, {}, {}
        
        # Calculate detection times by indicator
        indicator_detection_times = {}
        technique_detection_times_list = {}
        
        for match in indicator_matches:
            indicator_id = match.indicator_id
            time_to_detect = match.time_to_detect
            
            # Add to indicator detection times
            if indicator_id not in indicator_detection_times or time_to_detect < indicator_detection_times[indicator_id]:
                indicator_detection_times[indicator_id] = time_to_detect
        
        # Calculate overall MTTD
        if indicator_detection_times:
            mttd = sum(indicator_detection_times.values()) / len(indicator_detection_times)
        else:
            mttd = -1.0
        
        # No technique information in this simple implementation
        technique_detection_times = {}
        
        return mttd, technique_detection_times, indicator_detection_times
    
    def _calculate_detection_rate(
        self,
        indicators: List[Dict[str, Any]],
        indicator_matches: List[IndicatorMatch]
    ) -> float:
        """
        Calculate detection rate (percentage of indicators detected).
        
        Args:
            indicators: List of all indicators
            indicator_matches: List of indicator-event matches
            
        Returns:
            Detection rate as a fraction (0.0 to 1.0)
        """
        if not indicators:
            return 0.0
        
        # Count unique detected indicators
        detected_indicators = set(match.indicator_id for match in indicator_matches)
        
        # Calculate detection rate
        return len(detected_indicators) / len(indicators)
    
    def _identify_false_positives(
        self,
        events: List[DetectionEvent],
        indicator_matches: List[IndicatorMatch]
    ) -> List[DetectionEvent]:
        """
        Identify false positive detection events.
        
        Args:
            events: List of all detection events
            indicator_matches: List of indicator-event matches
            
        Returns:
            List of false positive events
        """
        # Get set of matched event IDs
        matched_event_ids = set(match.event_id for match in indicator_matches)
        
        # Find events that weren't matched with any indicator
        false_positives = [
            event for event in events 
            if event.event_id not in matched_event_ids and not event.is_false_positive
        ]
        
        return false_positives
    
    def _analyze_severity_distribution(self, events: List[DetectionEvent]) -> Dict[str, int]:
        """
        Analyze the distribution of detection events by severity.
        
        Args:
            events: List of detection events
            
        Returns:
            Dictionary mapping severity levels to counts
        """
        severity_counts = {}
        
        # Count events by severity
        for event in events:
            severity = event.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
    
    def calculate_aggregate_metrics(self, metrics_results: List[MetricsResult]) -> Dict[str, Any]:
        """
        Calculate aggregate metrics across multiple test runs.
        
        Args:
            metrics_results: List of metrics results from different runs
            
        Returns:
            Dictionary with aggregate metrics
        """
        if not metrics_results:
            return {
                "mttd": -1.0,
                "detection_rate": 0.0,
                "false_positive_rate": 0.0,
                "severity_distribution": {}
            }
        
        # Extract MTTDs (ignoring missing values)
        mttds = [result.mttd for result in metrics_results if result.mttd >= 0]
        
        # Calculate aggregate metrics
        aggregate = {
            "mttd": {
                "mean": statistics.mean(mttds) if mttds else -1.0,
                "median": statistics.median(mttds) if mttds else -1.0,
                "min": min(mttds) if mttds else -1.0,
                "max": max(mttds) if mttds else -1.0,
                "std_dev": statistics.stdev(mttds) if len(mttds) > 1 else 0.0
            },
            "detection_rate": {
                "mean": statistics.mean(result.detection_rate for result in metrics_results),
                "median": statistics.median(result.detection_rate for result in metrics_results),
                "min": min(result.detection_rate for result in metrics_results),
                "max": max(result.detection_rate for result in metrics_results)
            },
            "false_positive_rate": self._calculate_aggregate_fp_rate(metrics_results),
            "severity_distribution": self._aggregate_severity_distribution(metrics_results),
            "sample_size": len(metrics_results)
        }
        
        return aggregate
    
    def _calculate_aggregate_fp_rate(self, metrics_results: List[MetricsResult]) -> Dict[str, float]:
        """Calculate aggregate false positive rate."""
        total_alerts = 0
        total_false_positives = 0
        
        for result in metrics_results:
            matched_alerts = len(result.alerts_matched)
            false_positives = result.false_positives
            
            total_alerts += matched_alerts + false_positives
            total_false_positives += false_positives
        
        if total_alerts > 0:
            fp_rate = total_false_positives / total_alerts
        else:
            fp_rate = 0.0
            
        return {
            "rate": fp_rate,
            "total_alerts": total_alerts,
            "total_false_positives": total_false_positives
        }
    
    def _aggregate_severity_distribution(self, metrics_results: List[MetricsResult]) -> Dict[str, int]:
        """Aggregate severity distributions."""
        aggregate_distribution = {}
        
        for result in metrics_results:
            for severity, count in result.severity_distribution.items():
                aggregate_distribution[severity] = aggregate_distribution.get(severity, 0) + count
                
        return aggregate_distribution