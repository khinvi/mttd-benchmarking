# Simulation API Reference

This document provides a reference for the simulation components of the MTTD Benchmarking Framework.

## ThreatSimulationEngine

The `ThreatSimulationEngine` class is responsible for executing attack simulations across different cloud environments.

### Constructor

```python
def __init__(self, config: Dict[str, Any])
```

- **config**: Configuration parameters for the simulation engine

### Methods

#### execute_scenario

```python
def execute_scenario(self, scenario: ThreatScenario) -> SimulationResult
```

Executes a specific threat scenario.

- **scenario**: The threat scenario to execute
- **Returns**: SimulationResult containing execution details and timestamps

### Internal Methods

- `_prepare_environment(scenario, platform_client, result)`: Prepares the cloud environment for simulation.
- `_execute_step(step, platform_client, scenario)`: Executes a single attack step.
- `_enrich_step_parameters(parameters, resources)`: Enriches step parameters with actual resource information.
- `_generate_indicators(step, step_result)`: Generates detection indicators for a step.
- `_cleanup_environment(scenario, platform_client, result)`: Cleans up resources after simulation.

## Attack Techniques

The framework implements various attack techniques based on the MITRE ATT&CK framework:

### AWS Techniques

- `T1078`: Valid Accounts - Simulates using valid credentials for initial access
- `T1136`: Create Account - Creates a new IAM user or role
- `T1087`: Account Discovery - Enumerates users and roles
- `T1098`: Account Manipulation - Modifies permissions or attaches policies
- `T1048`: Exfiltration Over Alternative Protocol - Simulates data exfiltration
- `T1530`: Data from Cloud Storage - Accesses and downloads data from S3
- `T1537`: Transfer to Cloud Account - Transfers data to a different account

### Azure Techniques

- `T1078`: Valid Accounts - Simulates using valid credentials for initial access
- `T1136`: Create Account - Creates a new user account
- `T1087`: Account Discovery - Enumerates users and roles
- `T1098`: Account Manipulation - Modifies permissions or assigns roles
- `T1528`: Steal Application Access Token - Simulates stealing application tokens
- `T1537`: Transfer to Cloud Account - Transfers data to an external storage

### GCP Techniques

- `T1078`: Valid Accounts - Simulates using valid credentials for initial access
- `T1136`: Create Account - Creates a new service account
- `T1087`: Account Discovery - Enumerates service accounts and roles
- `T1098`: Account Manipulation - Modifies IAM policies
- `T1525`: Implant Container Image - Simulates implanting a container image
- `T1496`: Resource Hijacking - Deploys resource-intensive workloads
- `T1537`: Transfer to Cloud Account - Transfers data to external storage

## Integration with Cloud Platforms

The simulation engine integrates with different cloud platforms through the `PlatformClient` interface. Each platform implementation provides:

1. Resource creation and management
2. Attack technique execution
3. Resource cleanup

The factory pattern is used to create appropriate platform clients based on the scenario configuration:

```python
platform_client = get_platform_client(
    provider=scenario.platform.provider,
    config=scenario.platform.config,
    region=scenario.platform.region
)
```

## Simulation Flow

The typical flow of a simulation is:

1. Load and validate the scenario
2. Prepare the environment (create necessary resources)
3. Execute each attack step in sequence
4. Generate indicators for detection
5. Clean up resources
6. Return the simulation result

## Example Usage

```python
from mttd_benchmarking.scenario.manager import ScenarioManager

# Initialize the manager
manager = ScenarioManager(config)

# Execute a scenario
result = manager.execute_scenario("aws-privilege-escalation-001")

# Access simulation results
simulation_id = result["simulation"]["id"]
status = result["simulation"]["status"]
mttd = result["metrics"]["mttd"]
```