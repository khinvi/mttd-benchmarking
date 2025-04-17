# Metrics API Reference

This document provides a reference for the metrics components of the MTTD Benchmarking Framework.

## MetricsCollector

The `MetricsCollector` class is responsible for collecting and analyzing metrics related to threat detection.

### Constructor

```python
def __init__(self, config: Dict[str, Any])
```

- **config**: Configuration for the metrics collector

### Methods

#### collect_metrics

```python
def collect_metrics(self, simulation_result: SimulationResult, detection_monitor: DetectionMonitor, wait_for_detections: bool = True) -> MetricsResult
```

Collects and analyzes metrics for a completed simulation.

- **simulation_result**: The completed simulation result
- **detection_monitor**: The detection monitor instance
- **wait_for_detections**: Whether to wait for detection events
- **Returns**: MetricsResult containing analyzed metrics

#### collect_metrics_for_benchmark

```python
def collect_metrics_for_benchmark(self, simulation_results: List[SimulationResult], detection_monitor: DetectionMonitor) -> Dict[str, Union[List[MetricsResult], Dict[str, Any]]]
```

Collects metrics for multiple simulations in a benchmark.

- **simulation_results**: List of simulation results
- **detection_monitor**: The detection monitor instance
- **Returns**: Dictionary with lists of metrics results and aggregated metrics

#### load_metrics_result

```python
def load_metrics_result(self, metrics_id: str, simulation_id: str) -> Optional[MetricsResult]
```

Loads metrics result from file.

- **metrics_id**: The metrics ID
- **simulation_id**: The simulation ID
- **Returns**: Loaded MetricsResult or None if not found

#### get_all_metrics_for_simulation

```python
def get_all_metrics_for_simulation(self, simulation_id: str) -> List[MetricsResult]
```

Gets all metrics results for a simulation.

- **simulation_id**: The simulation ID
- **Returns**: List of MetricsResult objects

### Internal Methods

- `_extract_service_name(simulation_result)`: Extracts service name from simulation result.
- `_save_metrics_result(metrics_result, simulation_id)`: Saves metrics result to file.

## MetricsAnalyzer

The `MetricsAnalyzer` class analyzes detection events to calculate MTTD and other key metrics.

### Constructor

```python
def __init__(self, config: Dict[str, Any] = None)
```

- **config**: Configuration for the analyzer

### Methods

#### analyze_detection_events

```python
def analyze_detection_events(self, simulation_result: SimulationResult, detection_events: List[DetectionEvent], service_name: str) -> MetricsResult
```

Analyzes detection events to calculate MTTD and other metrics.

- **simulation_result**: The simulation result to analyze
- **detection_events**: List of detection events to analyze
- **service_name**: Name of the security service
- **Returns**: MetricsResult containing the analysis results

#### calculate_aggregate_metrics

```python
def calculate_aggregate_metrics(self, metrics_results: List[MetricsResult]) -> Dict[str, Any]
```

Calculates aggregate metrics across multiple test runs.

- **metrics_results**: List of metrics results from different runs
- **Returns**: Dictionary with aggregate metrics

### Internal Methods

- `_process_indicators(indicators)`: Processes indicators from simulation result.
- `_match_indicators_with_events(indicators, events)`: Matches indicators with detection events.
- `_calculate_mttd(indicator_matches)`: Calculates Mean Time To Detect from indicator matches.
- `_calculate_detection_rate(indicators, indicator_matches)`: Calculates detection rate.
- `_identify_false_positives(events, indicator_matches)`: Identifies false positive detections.
- `_analyze_severity_distribution(events)`: Analyzes the distribution of events by severity.
- `_calculate_aggregate_fp_rate(metrics_results)`: Calculates aggregate false positive rate.
- `_aggregate_severity_distribution(metrics_results)`: Aggregates severity distributions.

## Key Metrics

### Mean Time to Detect (MTTD)

The average time between attack execution and detection. Calculated as:

```
MTTD = Σ(Detection Time - Indicator Time) / Number of Detected Indicators
```

### Detection Rate

The percentage of attack indicators that were detected:

```
Detection Rate = Number of Detected Indicators / Total Number of Indicators
```

### False Positive Rate

The proportion of alerts that didn't correspond to actual attacks:

```
False Positive Rate = Number of False Positives / (True Positives + False Positives)
```

## MetricsResult

The `MetricsResult` class contains the results of metrics analysis:

- **metrics_id**: Unique ID for the metrics result
- **simulation_id**: ID of the simulation
- **scenario_id**: ID of the scenario
- **service_name**: Name of the security service
- **calculation_time**: When the metrics were calculated
- **mttd**: Mean Time To Detect in seconds (-1 if no detection)
- **detection_rate**: Fraction of indicators detected (0.0-1.0)
- **false_positives**: Number of false positive detections
- **severity_distribution**: Distribution of alerts by severity
- **technique_detection_times**: Detection times by technique
- **indicator_detection_times**: Detection times by indicator
- **alerts_matched**: List of matched alert IDs
- **alerts_missed**: List of missed expected alerts

## BenchmarkReport

The `BenchmarkReport` class contains comparative benchmark results:

- **report_id**: Unique ID for the report
- **generation_time**: When the report was generated
- **service_comparison**: Metrics by service
- **scenario_results**: Results by scenario
- **service_details**: Details about services
- **raw_metrics**: Raw metrics data

## Example Usage

```python
from mttd_benchmarking.scenario.manager import ScenarioManager

# Initialize the manager
manager = ScenarioManager(config)

# Execute a benchmark
result = manager.execute_benchmark(
    scenario_ids=["aws-privilege-escalation-001", "aws-data-exfiltration-001"],
    services=["aws_guardduty", "aws_securityhub"]
)

# Access benchmark results
mttd_by_service = result["service_comparison"]["mttd"]
detection_rates = result["service_comparison"]["detection_rate"]
false_positive_rates = result["service_comparison"]["false_positive_rate"]

# Print MTTD comparison
for service, mttd in mttd_by_service.items():
    print(f"{service}: {mttd:.2f} seconds")
```