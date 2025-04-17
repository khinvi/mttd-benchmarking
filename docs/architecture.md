# MTTD Benchmarking Framework Architecture

This document provides an overview of the MTTD Benchmarking Framework architecture, explaining its key components and how they interact.

## System Architecture

The framework follows a modular architecture with clearly defined responsibilities for each component:

```
┌─────────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
│                     │      │                      │      │                     │
│  Threat Simulation  │─────▶│  Detection Monitoring│─────▶│  Metric Collection  │
│       Engine        │      │       System         │      │    & Analysis       │
│                     │      │                      │      │                     │
└─────────────────────┘      └──────────────────────┘      └─────────────────────┘
          ▲                             ▲                            │
          │                             │                            │
          │                             │                            ▼
┌─────────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
│                     │      │                      │      │                     │
│  Test Scenario      │◀────▶│  Service Integration │      │     Reporting &     │
│     Manager         │      │        Layer         │      │    Visualization    │
│                     │      │                      │      │                     │
└─────────────────────┘      └──────────────────────┘      └─────────────────────┘
```

### Core Components

#### 1. Scenario Manager

The Scenario Manager orchestrates the entire testing lifecycle:
- Loads and validates test scenarios
- Coordinates simulation execution
- Collects metrics and generates reports
- Provides a high-level API for the framework

#### 2. Threat Simulation Engine

The Simulation Engine executes attack scenarios:
- Creates necessary cloud resources
- Executes attack techniques based on MITRE ATT&CK
- Generates attack indicators
- Cleans up resources after testing

#### 3. Detection Monitoring System

The Detection Monitor tracks security events:
- Polls security services for alerts
- Correlates events with simulated attacks
- Provides normalized events for metric calculation

#### 4. Metrics Collection & Analysis

The Metrics components calculate and analyze security metrics:
- Calculates MTTD, detection rates, and false positive rates
- Analyzes security event distribution
- Aggregates metrics across services and scenarios

#### 5. Service Integration Layer

The Service Integration Layer provides adapters for cloud services:
- Platform clients for resource management
- Security clients for alert monitoring
- Factory pattern for service instantiation

#### 6. Reporting & Visualization

The Reporting components generate comprehensive reports:
- Comparative benchmark reports
- Detailed service analysis
- Visualization charts and graphs

## Data Flow

The typical data flow through the system is:

1. **Scenario Definition** → The process starts with a JSON scenario file defining attack steps and expected alerts.

2. **Resource Provisioning** → The Simulation Engine creates necessary cloud resources.

3. **Attack Execution** → Attack techniques are executed sequentially, generating indicators.

4. **Alert Detection** → The Detection Monitor polls security services for alerts.

5. **Event Correlation** → Alerts are correlated with attack indicators.

6. **Metrics Calculation** → MTTD and other metrics are calculated from correlated events.

7. **Report Generation** → Benchmark reports are generated for service comparison.

8. **Resource Cleanup** → All created resources are cleaned up.

## Design Patterns

The framework uses several design patterns:

### Factory Pattern

Used in the Service Integration Layer to create appropriate client instances based on parameters:

```python
def get_platform_client(provider, config, region):
    # Create appropriate client based on provider
    ...

def get_security_client(service_name, provider, config, region):
    # Create appropriate client based on service_name
    ...
```

### Strategy Pattern

Used in the Event Correlation component to apply multiple correlation strategies:

```python
class EventCorrelator:
    def __init__(self):
        self.correlation_strategies = [
            self._correlate_by_id,
            self._correlate_by_resource,
            self._correlate_by_ip_address,
            # ...
        ]
```

### Observer Pattern

Used to monitor detection events in a non-blocking manner:

```python
class DetectionMonitor:
    def start_monitoring(self, simulation_result, scenario):
        # Start monitoring thread
        threading.Thread(target=self._monitoring_worker).start()
```

### Command Pattern

Used to encapsulate attack steps as executable commands:

```python
def execute_technique(self, technique_id, parameters, context):
    # Map technique IDs to implementation methods
    technique_methods = {
        "T1078": self._execute_valid_accounts,
        "T1136": self._execute_create_account,
        # ...
    }
```

## Component Dependencies

The framework components have the following dependencies:

- **Scenario Manager** depends on Simulation Engine, Detection Monitor, and Metrics Collector
- **Simulation Engine** depends on Service Integration Layer (Platform Clients)
- **Detection Monitor** depends on Service Integration Layer (Security Clients)
- **Metrics Collector** depends on Detection Monitor
- **Service Integration Layer** depends on external cloud provider SDKs

## Extensibility Points

The framework is designed to be extensible in several ways:

### Adding New Cloud Providers

To add a new cloud provider:

1. Implement a new Platform Client in the Service Integration Layer
2. Implement Security Clients for the provider's security services
3. Register the new clients in the service factory

### Adding New Attack Techniques

To add a new attack technique:

1. Implement the technique in the appropriate platform client
2. Map the technique ID to the implementation in the `execute_technique` method
3. Update scenario files to use the new technique

### Adding New Security Services

To add a new security service:

1. Implement a Security Client for the service
2. Register the client in the service factory
3. Update service configuration in the framework config file

## Cloud Provider Integration

The framework integrates with cloud providers through the following abstractions:

### Platform Clients

Platform clients handle resource management and attack execution:

```python
class PlatformClient:
    def create_resource(self, resource_type, resource_name, parameters)
    def delete_resource(self, resource_type, resource_id)
    def execute_technique(self, technique_id, parameters, context)
```

### Security Clients

Security clients handle security event monitoring:

```python
class SecurityClient:
    def get_security_events(self, start_time, end_time)
    def create_sample_alert(self, technique_id, parameters)
```

## Cross-Platform Compatibility

The framework supports cross-platform benchmarking through:

1. **Standardized Interfaces** - Common interfaces for all providers
2. **Normalized Metrics** - Consistent metric calculation across services
3. **Abstracted Attack Techniques** - Techniques mapped to provider-specific implementations
4. **Common Reporting Format** - Unified reporting structure for all providers

## Performance Considerations

The framework addresses performance considerations in several ways:

1. **Asynchronous Monitoring** - Detection monitoring runs in separate threads
2. **Configurable Timeouts** - Detection timeouts can be configured based on needs
3. **Efficient Correlation** - Multi-strategy correlation with confidence scoring
4. **Resource Cleanup** - Automatic cleanup of all created resources

## Security Considerations

The framework includes several security features:

1. **Isolated Environments** - Tests run in isolated cloud environments
2. **Safe Attack Simulations** - Non-destructive attack techniques
3. **Credential Management** - Secure handling of cloud credentials
4. **Automatic Cleanup** - Resources are cleaned up even on failures
5. **Audit Logging** - Comprehensive logging of all operations