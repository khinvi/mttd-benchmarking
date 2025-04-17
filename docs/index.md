# MTTD Benchmarking Framework

Welcome to the MTTD Benchmarking Framework documentation!

## Overview

The MTTD (Mean Time to Detect) Benchmarking Framework is a standardized methodology for measuring and comparing Mean Time to Detect across different commercial cloud security services. This framework addresses the lack of consistent evaluation methods in the industry, enabling organizations to make more informed security decisions.

## Key Features

- **Standardized Testing**: Consistent methodology for comparing security services
- **Multi-Cloud Support**: Works with AWS, Azure, and GCP security services
- **MITRE ATT&CK Integration**: Attack scenarios based on the MITRE ATT&CK framework
- **Comprehensive Metrics**: Measures MTTD, detection rates, false positives, and more
- **Advanced Visualization**: Interactive charts and reports for easy analysis
- **Extensible Architecture**: Easy to add new security services and attack techniques

## Quick Start

### Installation

```bash
pip install mttd-benchmarking
```

For detailed installation instructions, see the [Installation Guide](installation.md).

### Basic Usage

1. **List available scenarios**:
   ```bash
   mttd-benchmark list
   ```

2. **Execute a specific scenario**:
   ```bash
   mttd-benchmark execute --scenario-id aws-privilege-escalation-001
   ```

3. **Run a benchmark across multiple services**:
   ```bash
   mttd-benchmark benchmark --scenarios aws-privilege-escalation-001,aws-data-exfiltration-001 --services aws_guardduty,aws_securityhub
   ```

4. **Generate a report from benchmark results**:
   ```bash
   mttd-benchmark report --report-id 123e4567-e89b-12d3-a456-426614174000 --format html
   ```

## Documentation Sections

- [Installation Guide](installation.md) - How to install and configure the framework
- [Architecture](architecture.md) - Overview of the framework architecture
- [Attack Scenarios](scenarios.md) - Working with attack scenarios
- [Cloud Security Services](services.md) - Supported security services
- [API Documentation](api/simulation.md) - Detailed API reference

## Core Concepts

### Mean Time to Detect (MTTD)

MTTD measures how quickly a security service detects a simulated attack. It is calculated as the time difference between when an attack indicator was generated and when the security service detected it.

### Detection Rate

Detection rate represents the percentage of attack indicators that were successfully detected by the security service. A higher detection rate indicates more comprehensive coverage.

### False Positive Rate

False positive rate measures the proportion of alerts that don't correspond to actual attacks. A lower false positive rate indicates more accurate detections.

### Benchmark Reports

Benchmark reports provide comparative analysis across different security services, helping organizations understand the strengths and weaknesses of each service.

## Workflow

The typical workflow for using the MTTD Benchmarking Framework is:

1. **Configure Environment**: Set up cloud credentials and framework configuration
2. **Select Scenarios**: Choose or create attack scenarios to test
3. **Execute Benchmarks**: Run benchmarks across multiple security services
4. **Analyze Results**: Review metrics and visualizations to understand performance
5. **Make Decisions**: Use insights to inform security service selection and configuration

## Running a Benchmark

To run a comprehensive benchmark across multiple services:

```bash
mttd-benchmark benchmark \
  --scenarios aws-privilege-escalation-001,aws-data-exfiltration-001,azure-lateral-movement-001 \
  --services aws_guardduty,aws_securityhub,azure_sentinel
```

This will:
1. Execute each scenario against each service
2. Collect detection events
3. Calculate metrics
4. Generate a benchmark report

## Analyzing Results

Benchmark results include:

- **MTTD Comparison**: How quickly each service detects attacks
- **Detection Rate Comparison**: How comprehensive each service's coverage is
- **False Positive Comparison**: How accurate each service's detections are
- **Scenario-specific Analysis**: How services perform on different attack scenarios

Example output:

```
Benchmark Results:
  Report ID: 123e4567-e89b-12d3-a456-426614174000

  Service Comparison:
    Mean Time To Detect (MTTD):
    - aws_guardduty: 85.7 seconds
    - aws_securityhub: 142.3 seconds
    - azure_sentinel: 103.5 seconds

    Detection Rate:
    - aws_guardduty: 87.5%
    - aws_securityhub: 75.0%
    - azure_sentinel: 81.2%

    False Positive Rate:
    - aws_guardduty: 8.3%
    - aws_securityhub: 5.6%
    - azure_sentinel: 12.5%
```

## Visualizations

The framework provides several visualizations:

- **Bar Charts**: Compare metrics across services
- **Radar Charts**: Multi-dimensional comparison
- **Timeline Charts**: Track detection performance over time

![Example MTTD Chart](mttd_chart_example.png)

## Use Cases

The MTTD Benchmarking Framework is useful for:

- **Security Vendor Selection**: Objective comparison of security services
- **Security Posture Assessment**: Measuring detection capabilities
- **Detection Tuning**: Identifying and addressing detection gaps
- **Cost-Benefit Analysis**: Understanding the value of security investments
- **Research and Publication**: Generating empirical data on security effectiveness

## Contributing

We welcome contributions to the MTTD Benchmarking Framework! Some ways to contribute:

- Add new attack scenarios
- Implement support for additional security services
- Improve existing detection correlation algorithms
- Enhance visualization and reporting capabilities
- Share benchmark results and insights

For contribution guidelines, see the project's GitHub repository.

## FAQ

### Q: How accurate are the simulated attacks?

A: The framework uses real cloud APIs to simulate attacks, making them as realistic as possible without causing actual harm. Attack techniques are based on the MITRE ATT&CK framework to ensure relevance to real-world threats.

### Q: Can I use this for penetration testing?

A: While the framework simulates attacks, it is designed for benchmarking security services, not penetration testing. All simulated attacks are non-destructive and use isolated resources.

### Q: How much does it cost to run benchmarks?

A: The cost depends on the cloud resources created during benchmarks. Most scenarios use minimal resources and clean them up afterward, but you should review the resource requirements before running benchmarks in production environments.

### Q: Can I benchmark third-party security solutions?

A: Yes, the framework can be extended to support any security service that provides an API for retrieving security events. See the documentation on [Adding Custom Security Services](services.md#adding-custom-security-services).

### Q: How long does a benchmark take to run?

A: Benchmark duration depends on the number of scenarios and services being tested, as well as the detection timeout configuration. A typical benchmark might take 1-2 hours to complete.

## Next Steps

Now that you understand the basics, you can:

1. [Install the framework](installation.md)
2. [Explore the included scenarios](scenarios.md)
3. [Learn about supported security services](services.md)
4. [Understand the architecture](architecture.md)
5. [Read the API documentation](api/simulation.md)