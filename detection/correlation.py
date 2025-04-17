"""
Event correlation logic for matching security events to simulated threats.
"""

import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Union, Tuple

from ..core.types import SimulationResult

logger = logging.getLogger(__name__)


class EventCorrelator:
    """
    Correlates security events with simulated attack indicators.
    Uses a multi-factor approach to determine if an event is related to a simulation.
    """
    
    def __init__(self):
        """Initialize the event correlator."""
        # Define correlation strategies
        self.correlation_strategies = [
            self._correlate_by_id,            # Direct ID references
            self._correlate_by_resource,      # Resource references
            self._correlate_by_ip_address,    # IP address matches
            self._correlate_by_user,          # User account matches
            self._correlate_by_time_window,   # Time proximity
            self._correlate_by_action_type    # Action/technique type
        ]
        
        # Weights for different correlation strategies (must sum to 1.0)
        self.strategy_weights = {
            "id": 0.3,             # Direct ID references are high confidence
            "resource": 0.25,      # Resource references are high confidence
            "ip_address": 0.15,    # IP matches are moderate confidence
            "user": 0.15,          # User matches are moderate confidence
            "time_window": 0.05,   # Time proximity is low confidence
            "action_type": 0.1     # Action type is low confidence
        }
    
    def correlate_event(
        self, 
        raw_event: Dict[str, Any], 
        simulation_result: SimulationResult,
        correlation_threshold: float = 0.6
    ) -> Dict[str, Any]:
        """
        Correlate a security event with a simulation result.
        
        Args:
            raw_event: The raw event from a security service
            simulation_result: The simulation result to correlate with
            correlation_threshold: Minimum confidence for correlation
            
        Returns:
            Dictionary with correlation results:
            {
                "correlated": bool,
                "confidence": float,
                "indicators": List[str],
                "correlation_factors": Dict[str, float],
                "is_false_positive": bool
            }
        """
        # Convert indicators from string timestamps to datetime objects for processing
        indicators = self._process_indicators(simulation_result.indicators)
        
        # Initialize correlation result
        correlation_result = {
            "correlated": False,
            "confidence": 0.0,
            "indicators": [],
            "correlation_factors": {},
            "is_false_positive": False
        }
        
        # Skip if no indicators
        if not indicators:
            return correlation_result
        
        # Apply each correlation strategy
        matched_indicators = set()
        total_confidence = 0.0
        
        for strategy, weight_key in [
            (self._correlate_by_id, "id"),
            (self._correlate_by_resource, "resource"),
            (self._correlate_by_ip_address, "ip_address"),
            (self._correlate_by_user, "user"),
            (self._correlate_by_time_window, "time_window"),
            (self._correlate_by_action_type, "action_type")
        ]:
            # Apply strategy
            strategy_result = strategy(raw_event, indicators)
            
            # Record confidence for this strategy
            confidence = strategy_result["confidence"] * self.strategy_weights[weight_key]
            correlation_result["correlation_factors"][weight_key] = confidence
            
            # Track matched indicators
            matched_indicators.update(strategy_result["indicators"])
            
            # Add to total confidence
            total_confidence += confidence
        
        # Set overall confidence
        correlation_result["confidence"] = total_confidence
        
        # Check if the event is correlated
        if total_confidence >= correlation_threshold:
            correlation_result["correlated"] = True
            correlation_result["indicators"] = list(matched_indicators)
            
            # Determine if false positive
            correlation_result["is_false_positive"] = len(matched_indicators) == 0
        
        return correlation_result
    
    def _process_indicators(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process indicators to convert timestamps and extract key information."""
        processed = []
        
        for indicator in indicators:
            processed_indicator = indicator.copy()
            
            # Convert string timestamp to datetime
            if "generation_time" in indicator and isinstance(indicator["generation_time"], str):
                try:
                    processed_indicator["generation_time"] = datetime.fromisoformat(
                        indicator["generation_time"].replace('Z', '+00:00')
                    )
                except ValueError:
                    # Keep original if conversion fails
                    pass
            
            processed.append(processed_indicator)
        
        return processed
    
    def _correlate_by_id(
        self, 
        event: Dict[str, Any], 
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate event by explicit ID references.
        
        Returns:
            Dictionary with correlation results.
        """
        result = {
            "confidence": 0.0,
            "indicators": []
        }
        
        # Check if simulation ID is in the event
        simulation_ids = self._extract_all_values(event, ["simulation_id", "simulationId"])
        
        if simulation_ids:
            # Perfect match if simulation ID is found
            result["confidence"] = 1.0
            
            # Add all indicator IDs since we have a direct simulation match
            result["indicators"] = [ind["indicator_id"] for ind in indicators if "indicator_id" in ind]
            return result
            
        # Check for indicator IDs
        indicator_ids = self._extract_all_values(event, ["indicator_id", "indicatorId"])
        
        if indicator_ids:
            # Check against each indicator
            for indicator in indicators:
                if "indicator_id" in indicator and indicator["indicator_id"] in indicator_ids:
                    result["indicators"].append(indicator["indicator_id"])
            
            # Set confidence based on matches
            if result["indicators"]:
                result["confidence"] = 1.0
        
        return result
    
    def _correlate_by_resource(
        self, 
        event: Dict[str, Any], 
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate event by resource identifiers.
        
        Returns:
            Dictionary with correlation results.
        """
        result = {
            "confidence": 0.0,
            "indicators": []
        }
        
        # Extract resource identifiers from the event
        resource_ids = set()
        resource_ids.update(self._extract_all_values(event, [
            "resourceId", "resource_id", "resourceName", "resource", "targetResource",
            "instanceId", "instance_id", "bucketName", "bucket_name", "functionName",
            "roleId", "role_id", "userId", "user_id"
        ]))
        
        # For AWS events, check the ARN fields
        arns = self._extract_all_values(event, ["arn", "resourceArn", "userArn", "roleArn"])
        for arn in arns:
            # Extract the resource name from the ARN
            if isinstance(arn, str):
                parts = arn.split(":")
                if len(parts) >= 6:
                    resource_name = parts[5].split("/")[-1]  # Get last part of the resource path
                    resource_ids.add(resource_name)
        
        # Check against each indicator
        for indicator in indicators:
            indicator_resources = set()
            
            # Extract resource IDs from the indicator details
            if "details" in indicator and isinstance(indicator["details"], dict):
                indicator_resources.update(self._extract_all_values(
                    indicator["details"], 
                    ["resourceId", "resource_id", "resourceName", "resource"]
                ))
            
            # Check for intersection
            if resource_ids.intersection(indicator_resources):
                result["indicators"].append(indicator["indicator_id"])
                result["confidence"] = 1.0
        
        return result
    
    def _correlate_by_ip_address(
        self, 
        event: Dict[str, Any], 
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate event by IP addresses.
        
        Returns:
            Dictionary with correlation results.
        """
        result = {
            "confidence": 0.0,
            "indicators": []
        }
        
        # Extract IP addresses from the event (both IPv4 and IPv6)
        event_ips = set()
        ip_fields = ["sourceIPAddress", "source_ip", "sourceIp", "remoteIp", "remote_ip", 
                     "ipAddress", "ip_address", "destinationIP", "destination_ip"]
        
        for ip in self._extract_all_values(event, ip_fields):
            if isinstance(ip, str) and self._is_valid_ip(ip):
                event_ips.add(ip)
        
        # Check for IP addresses in nested fields
        for nested_field in ["sourceAddress", "source", "destination", "target", "connection"]:
            if nested_field in event and isinstance(event[nested_field], dict):
                nested_ips = self._extract_all_values(event[nested_field], ip_fields)
                for ip in nested_ips:
                    if isinstance(ip, str) and self._is_valid_ip(ip):
                        event_ips.add(ip)
        
        # Check against each indicator
        matched_indicators = []
        for indicator in indicators:
            indicator_ips = set()
            
            # Extract IPs from the indicator details
            if "details" in indicator and isinstance(indicator["details"], dict):
                for ip in self._extract_all_values(indicator["details"], ip_fields):
                    if isinstance(ip, str) and self._is_valid_ip(ip):
                        indicator_ips.add(ip)
            
            # Check for intersection
            if event_ips.intersection(indicator_ips):
                matched_indicators.append(indicator["indicator_id"])
        
        # Set confidence based on number of matched indicators
        if matched_indicators:
            result["indicators"] = matched_indicators
            result["confidence"] = min(1.0, len(matched_indicators) / 5)  # Scale confidence
        
        return result
    
    def _correlate_by_user(
        self, 
        event: Dict[str, Any], 
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate event by user identifiers.
        
        Returns:
            Dictionary with correlation results.
        """
        result = {
            "confidence": 0.0,
            "indicators": []
        }
        
        # Extract user identifiers from the event
        event_users = set()
        user_fields = ["userName", "user_name", "userIdentity", "user", "principal", 
                       "userArn", "userId", "user_id", "identity"]
        
        for user in self._extract_all_values(event, user_fields):
            if isinstance(user, str):
                event_users.add(user)
            elif isinstance(user, dict):
                # Handle nested user information (common in AWS CloudTrail)
                for user_value in self._extract_all_values(user, 
                                                         ["userName", "arn", "userId", "principalId"]):
                    if isinstance(user_value, str):
                        event_users.add(user_value)
        
        # Check against each indicator
        matched_indicators = []
        for indicator in indicators:
            indicator_users = set()
            
            # Extract users from the indicator details
            if "details" in indicator and isinstance(indicator["details"], dict):
                for user in self._extract_all_values(indicator["details"], user_fields):
                    if isinstance(user, str):
                        indicator_users.add(user)
            
            # Check for intersection
            if event_users.intersection(indicator_users):
                matched_indicators.append(indicator["indicator_id"])
        
        # Set confidence based on number of matched indicators
        if matched_indicators:
            result["indicators"] = matched_indicators
            result["confidence"] = min(1.0, len(matched_indicators) / 3)  # Scale confidence
        
        return result
    
    def _correlate_by_time_window(
        self, 
        event: Dict[str, Any], 
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate event by time proximity to indicators.
        
        Returns:
            Dictionary with correlation results.
        """
        result = {
            "confidence": 0.0,
            "indicators": []
        }
        
        # Extract event time
        event_time = None
        for field in ["timestamp", "eventTime", "time", "createdAt", "updateTime"]:
            if field in event:
                try:
                    # Handle string timestamps
                    if isinstance(event[field], str):
                        event_time = datetime.fromisoformat(event[field].replace('Z', '+00:00'))
                        break
                    # Handle epoch timestamps
                    elif isinstance(event[field], (int, float)):
                        event_time = datetime.fromtimestamp(event[field])
                        break
                except (ValueError, TypeError):
                    pass
        
        # Cannot correlate without event time
        if not event_time:
            return result
        
        # Define time windows for correlation (in seconds)
        time_windows = [
            (60, 0.9),     # Within 1 minute: 90% confidence
            (300, 0.7),    # Within 5 minutes: 70% confidence
            (900, 0.4),    # Within 15 minutes: 40% confidence
            (1800, 0.2)    # Within 30 minutes: 20% confidence
        ]
        
        # Check each indicator
        max_confidence = 0.0
        matched_indicators = []
        
        for indicator in indicators:
            if "generation_time" not in indicator:
                continue
                
            indicator_time = indicator["generation_time"]
            
            # Calculate time difference in seconds
            if isinstance(indicator_time, datetime):
                time_diff = abs((event_time - indicator_time).total_seconds())
                
                # Check time windows
                for window_seconds, window_confidence in time_windows:
                    if time_diff <= window_seconds:
                        matched_indicators.append(indicator["indicator_id"])
                        max_confidence = max(max_confidence, window_confidence)
                        break
        
        # Set result
        if matched_indicators:
            result["indicators"] = matched_indicators
            result["confidence"] = max_confidence
        
        return result
    
    def _correlate_by_action_type(
        self, 
        event: Dict[str, Any], 
        indicators: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Correlate event by action/technique type.
        
        Returns:
            Dictionary with correlation results.
        """
        result = {
            "confidence": 0.0,
            "indicators": []
        }
        
        # Extract event action/type information
        event_actions = set()
        for field in ["eventName", "event_name", "action", "actionType", "operation"]:
            if field in event and isinstance(event[field], str):
                event_actions.add(event[field].lower())
        
        # Extract event categories
        event_categories = set()
        for field in ["eventCategory", "eventType", "category", "type"]:
            if field in event and isinstance(event[field], str):
                event_categories.add(event[field].lower())
        
        # Check each indicator
        matched_by_technique = set()
        matched_by_category = set()
        
        for indicator in indicators:
            # Check technique ID
            technique_matched = False
            if "technique_id" in indicator:
                # Try to find technique ID references in event
                for field_value in event_actions:
                    if indicator["technique_id"].lower() in field_value:
                        matched_by_technique.add(indicator["indicator_id"])
                        technique_matched = True
                        break
            
            # Check indicator type
            if not technique_matched and "type" in indicator:
                indicator_type = indicator["type"].lower()
                
                # Check event actions
                for action in event_actions:
                    # Simple word matching
                    action_words = set(re.findall(r'\w+', action))
                    indicator_words = set(re.findall(r'\w+', indicator_type))
                    
                    if action_words.intersection(indicator_words):
                        matched_by_category.add(indicator["indicator_id"])
                        break
                
                # Check event categories
                for category in event_categories:
                    category_words = set(re.findall(r'\w+', category))
                    indicator_words = set(re.findall(r'\w+', indicator_type))
                    
                    if category_words.intersection(indicator_words):
                        matched_by_category.add(indicator["indicator_id"])
                        break
        
        # Combine results with different confidence levels
        if matched_by_technique:
            result["indicators"].extend(list(matched_by_technique))
            result["confidence"] = 0.7  # Higher confidence for technique matches
        
        if matched_by_category:
            result["indicators"].extend([i for i in matched_by_category 
                                       if i not in matched_by_technique])
            
            # If we already have technique matches, average the confidences
            if result["confidence"] > 0:
                result["confidence"] = (result["confidence"] + 0.4) / 2
            else:
                result["confidence"] = 0.4  # Lower confidence for category matches
        
        return result
    
    def _extract_all_values(self, obj: Any, keys: List[str]) -> List[Any]:
        """
        Recursively extract all values for the given keys from an object.
        
        Args:
            obj: Object to extract values from
            keys: List of keys to extract
            
        Returns:
            List of extracted values
        """
        values = []
        
        if isinstance(obj, dict):
            # Check if any of the keys exist in this dict
            for key in keys:
                if key in obj:
                    values.append(obj[key])
            
            # Recurse into all values
            for value in obj.values():
                values.extend(self._extract_all_values(value, keys))
        
        elif isinstance(obj, (list, tuple)):
            # Recurse into the list
            for item in obj:
                values.extend(self._extract_all_values(item, keys))
        
        return values
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if a string is a valid IP address (IPv4 or IPv6)."""
        # Simple IPv4 check
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, ip_str):
            # Verify each octet is 0-255
            return all(0 <= int(octet) <= 255 for octet in ip_str.split('.'))
        
        # Simple IPv6 check (not comprehensive)
        ipv6_pattern = r'^[0-9a-fA-F:]+$'
        if re.match(ipv6_pattern, ip_str) and ':' in ip_str:
            return True
        
        return False