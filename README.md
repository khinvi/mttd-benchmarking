# MTTD Benchmarking Framework 🔍

*A research-oriented framework for standardized measurement and comparison of Mean Time to Detect (MTTD) across commercial cloud security services.* ☁️

## Overview

The **MTTD Benchmarking Framework** addresses a critical gap in cloud security: the **lack of standardized methods** to objectively evaluate and compare detection capabilities across security services. When organizations migrate to the cloud, they need empirical data to make informed security decisions, but consistent benchmarking methodologies have been missing—until now.

Our framework provides:

- A standardized approach for measuring MTTD across AWS, Azure, and GCP security services
- Realistic attack simulations based on the MITRE ATT&CK framework
- Comprehensive metrics including detection rates and false positive rates
- Platform-agnostic evaluation that enables direct comparison of service performance

This repository contains our implementation, documentation, and research findings as we continue to develop and refine this methodology. We'll update it as our research progresses! 🚀

The MTTD Benchmarking Framework employs a modular architecture to systematically evaluate security service detection capabilities:

- **Threat Simulation Engine**: Executes controlled attack scenarios across platforms
- **Detection Monitoring System**: Collects security events from various services
- **Metric Collection & Analysis**: Processes event data to calculate MTTD and other metrics
- **Reporting & Visualization**: Generates comparative reports and visualizations
- **Test Scenario Manager**: Orchestrates test execution and manages environments
- **Service Integration Layer**: Provides standardized interfaces to various security services

Our meta-level analysis framework combines these components to provide objective comparisons while adapting to the unique characteristics of each security service.

## Read More

For a deeper understanding of the research motivations and methodology behind this implementation:

📄 **Research Paper Proposal:** [Beyond Vendor Claims: Empirical MTTD Benchmarking for Cloud Security Services](https://github.com/khinvi/mttd-benchmarking/blob/main/Research_Paper_Proposal__MTTD_Benchmarking_Framework.pdf)

📄 **Documentation:** [MTTD Benchmarking Framework Documentation](https://github.com/khinvi/mttd-benchmarking/docs/index.md)

This structure shows the progression from your initial research proposal to the implementation documentation, providing readers with both the theoretical foundation and practical details of your work.

## Research Applications

This framework enables several important cybersecurity research directions:

1. Establishing empirical baselines for MTTD across different providers
2. Identifying detection blind spots in cloud security services
3. Analyzing the relationship between alert volume and accuracy
4. Measuring how MTTD varies across different attack techniques
5. Evaluating the impact of security service configuration on detection capabilities

## Key Features

- **Standardized Testing**: Consistent methodology for comparing security services 📊
- **Realistic Attack Simulation**: Based on MITRE ATT&CK framework and real-world patterns 🛡️
- **Multi-Cloud Support**: Works with AWS, Azure, and GCP security services ☁️
- **Comprehensive Metrics**: Measures MTTD, detection rates, false positives, and more 📈
- **Advanced Visualization**: Interactive charts and reports for easy analysis 📉
- **Extensible Architecture**: Easy to add new security services and attack techniques 🧩
- **Objective Comparison**: Framework for evidence-based security decisions 🔬

## Installation

### Prerequisites

- Python 3.9 or higher
- Access to cloud platform accounts (AWS, Azure, and/or GCP)
- Cloud security services to test (GuardDuty, Security Hub, Sentinel, etc.)
- Appropriate permissions to create and manage cloud resources

### Setup

```bash
# Install from PyPI
pip install mttd-benchmarking

# Or install from source
git clone https://github.com/yourusername/mttd-benchmarking.git
cd mttd-benchmarking
pip install -e .
```

For detailed installation instructions, see the [Installation Guide](https://github.com/yourusername/mttd-benchmarking/docs/installation.md).

## Usage

### Command Line Interface

```bash
# List available scenarios
mttd-benchmark list

# Execute a specific scenario
mttd-benchmark execute --scenario-id aws-privilege-escalation-001

# Run a benchmark across multiple services
mttd-benchmark benchmark --scenarios aws-privilege-escalation-001,aws-data-exfiltration-001 --services aws_guardduty,aws_securityhub

# Generate a report from benchmark results
mttd-benchmark report --report-id 123e4567-e89b-12d3-a456-426614174000 --format html
```

### Web Interface

The framework also provides a web-based UI for easier interaction:

```bash
# Start the web interface
python -m mttd_benchmarking.web.app
```

Then access it at http://localhost:5000

## Attack Scenarios

The framework includes several pre-defined scenarios:

- **AWS Privilege Escalation**: Simulates an attacker gaining initial access and escalating privileges
- **AWS Data Exfiltration**: Simulates access and exfiltration of sensitive data from S3 buckets
- **Azure Lateral Movement**: Simulates gaining initial access and moving laterally through Azure resources
- **GCP Cryptomining**: Simulates compromising GCP resources to deploy cryptomining workloads

These scenarios are designed to test real-world attack patterns while remaining non-destructive and controlled.

## Project Structure

```
mttd-benchmarking/
├── cli/                  # Command line interface
├── config/               # Configuration files and scenario definitions
├── core/                 # Core types and utilities
├── detection/            # Detection monitoring and correlation
├── docs/                 # Documentation
├── metrics/              # Metric collection and analysis
├── reporting/            # Report generation and visualizations
├── scenario/             # Scenario management
├── services/             # Service integration layer
│   ├── aws/              # AWS service clients
│   ├── azure/            # Azure service clients
│   └── gcp/              # GCP service clients
├── simulation/           # Simulation engine and techniques
│   └── techniques/       # Attack technique implementations
├── tests/                # Unit and integration tests
└── web/                  # Web UI
```

## Extending the Framework

The framework is designed to be extensible in several ways:

1. **Add New Attack Techniques**: Implement new MITRE ATT&CK techniques in the appropriate platform modules
2. **Support New Security Services**: Create new security service clients in the services directory
3. **Develop Custom Scenarios**: Create new JSON scenario files to test specific attack patterns
4. **Enhance Visualization**: Add new visualization types in the reporting module
5. **Expand Cloud Support**: Extend the framework to additional cloud providers

## Security Considerations

This framework simulates attack techniques for benchmarking purposes only. Always:

- Use dedicated test environments, never production
- Obtain proper authorization before testing
- Follow responsible disclosure processes if vulnerabilities are discovered
- Ensure all testing complies with applicable laws and regulations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Citation

If you use this work in your research, please cite:

```
@article{khinvasara2025multiexpert,
  title={Multi-Expert AI System for Sneaker Bot Detection},
  author={Khinvasara, Arnav},
  journal={arXiv preprint},
  year={2025}
}
```

## Acknowledgments

* University of California, San Diego
* MITRE ATT&CK® framework
* Cloud security service providers
* Security researchers who have developed similar methodologies
