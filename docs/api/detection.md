# Detection API Reference

This document provides a reference for the detection components of the MTTD Benchmarking Framework.

## DetectionMonitor

The `DetectionMonitor` class is responsible for monitoring security services for detection events related to simulated threats.

### Constructor

```python
def __init__(self, config: Dict[str, Any])
```

- **config**: Configuration for the detection monitor

### Methods

#### start_monitoring

```python
def start_monitoring(self, simulation_result: SimulationResult, scenario: ThreatScenario) -> None
```

Starts monitoring for detection events related to a simulation.

- **simulation_result**: The active simulation to monitor
- **scenario**: The scenario being executed

#### stop_monitoring

```python
def stop_monitoring(self, simulation_id: str) -> None
```

Stops monitoring for a specific simulation.

- **simulation_id**: ID of the simulation to stop monitoring

#### get_detection_events

```python
def get_detection_events(self, simulation_id: str, timeout: int = 0) -> List[DetectionEvent]
```

Gets detection events for a specific simulation.

- **simulation_id**: The ID of the simulation
- **timeout**: How long to wait for events in seconds (0 = no wait)
- **Returns**: List of detection events related to the simulation

### Internal Methods

- `_monitoring_worker(service_name)`: Worker thread that polls security services for events.
- `_process_events(raw_events, service_name, simulation_ids)`: Processes and correlates raw security events.
- `_extract_event_id(event)`: Extracts event ID from raw event.
- `_extract_detection_time(event)`: Extracts detection timestamp from raw event.
- `_extract_event_type(event)`: Extracts event type from raw event.
- `_extract_severity(event)`: Extracts severity from raw event.

## EventCorrelator

The `EventCorrelator` class correlates security events with simulated attack indicators using a multi-strategy approach.

### Constructor

```python
def __init__(self)
```

### Methods

#### correlate_event

```python
def correlate_event(self, raw_event: Dict[str, Any], simulation_result: SimulationResult, correlation_threshold: float = 0.6) -> Dict[str, Any]
```

Correlates a security event with a simulation result.

- **raw_event**: The raw event from a security service
- **simulation_result**: The simulation result to correlate with
- **correlation_threshold**: Minimum confidence for correlation
- **Returns**: Dictionary with correlation results

### Correlation Strategies

The correlator uses multiple strategies with weighted confidence scores:

1. **ID-based correlation** (weight: 0.3): Explicit ID references in events
2. **Resource-based correlation** (weight: 0.25): Resource identifiers matching
3. **IP-based correlation** (weight: 0.15): IP address matches
4. **User-based correlation** (weight: 0.15): User account matches
5. **Time-based correlation** (weight: 0.05): Temporal proximity
6. **Action-based correlation** (weight: 0.1): Matching action or technique types

The overall correlation confidence is the weighted sum of individual strategy confidences.

## SecurityClient Interface

Security clients provide a standardized interface for interacting with different security services.

### Required Methods

#### get_security_events

```python
def get_security_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]
```

Gets security events within a time range.

- **start_time**: Start time for events
- **end_time**: End time for events
- **Returns**: List of security events

#### create_sample_alert (Optional)

```python
def create_sample_alert(self, technique_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]
```

Creates a sample alert for testing purposes.

- **technique_id**: MITRE ATT&CK technique ID
- **parameters**: Alert parameters
- **Returns**: Dictionary with sample alert details

## Security Service Implementations

The framework includes implementations for various security services:

### AWS Security Services

- **GuardDuty**: AWS threat detection service
- **SecurityHub**: AWS security findings aggregator

### Azure Security Services

- **Sentinel**: Azure SIEM solution
- **Defender**: Microsoft Defender for Cloud

### GCP Security Services

- **Security Command Center**: GCP security and risk management platform

## Integration Architecture

The detection system uses a factory pattern to create security clients:

```python
security_client = get_security_client(
    service_name=service_name,
    provider=provider,
    config=config,
    region=region
)
```

This allows for flexible integration with different security services while maintaining a consistent interface.

## Detection Event Flow

The typical flow of detection events is:

1. Security service generates an alert
2. DetectionMonitor polls for new events
3. Events are processed and normalized
4. EventCorrelator matches events to simulation indicators
5. Correlated events are added to the simulation's event queue
6. MetricsCollector retrieves events and calculates metrics

## Example Usage

```python
from mttd_benchmarking.detection.monitor import DetectionMonitor
from mttd_benchmarking.scenario.manager import ScenarioManager

# Initialize components
manager = ScenarioManager(config)
monitor = DetectionMonitor(config.get("monitoring", {}))

# Execute scenario and start monitoring
scenario = manager.load_scenario("aws-privilege-escalation-001")
simulation_result = manager.simulation_engine.execute_scenario(scenario)
monitor.start_monitoring(simulation_result, scenario)

# Wait for detections
import time
time.sleep(300)  # Wait for 5 minutes

# Get detection events
events = monitor.get_detection_events(simulation_result.simulation_id)
print(f"Detected {len(events)} events")
```