# Installation Guide

This guide explains how to install and configure the MTTD Benchmarking Framework.

## Prerequisites

Before installing the framework, ensure you have the following prerequisites:

- Python 3.9 or higher
- pip (Python package installer)
- Access to cloud accounts for testing (AWS, Azure, and/or GCP)
- Appropriate permissions to create and manage cloud resources
- Basic knowledge of cloud security services

## Installation Methods

### Method 1: Install from PyPI

The simplest way to install the framework is through PyPI:

```bash
pip install mttd-benchmarking
```

### Method 2: Install from Source

To install from source:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/mttd-benchmarking.git
   cd mttd-benchmarking
   ```

2. Install the package in development mode:
   ```bash
   pip install -e .
   ```

## Dependencies

The framework depends on several Python packages:

### Core Dependencies
- python-dateutil>=2.8.2
- pyyaml>=6.0
- requests>=2.28.0
- jsonschema>=4.16.0

### Cloud SDKs
- boto3>=1.26.0 (for AWS)
- azure-identity>=1.12.0 (for Azure)
- google-cloud-compute>=1.6.0 (for GCP)

These dependencies will be installed automatically when installing the package.

## Cloud Provider Configuration

### AWS Configuration

1. Configure AWS credentials using one of the following methods:
   - AWS CLI: `aws configure`
   - Environment variables:
     ```bash
     export AWS_ACCESS_KEY_ID=your_access_key
     export AWS_SECRET_ACCESS_KEY=your_secret_key
     export AWS_DEFAULT_REGION=us-west-2
     ```
   - Configuration file: `~/.aws/credentials`

2. Ensure the IAM user or role has the following permissions:
   - IAM: CreateUser, DeleteUser, AttachUserPolicy, DetachUserPolicy
   - EC2: RunInstances, TerminateInstances
   - S3: CreateBucket, DeleteBucket, PutObject, GetObject
   - GuardDuty/SecurityHub: GetFindings, ListDetectors

### Azure Configuration

1. Configure Azure credentials using one of the following methods:
   - Azure CLI: `az login`
   - Environment variables:
     ```bash
     export AZURE_TENANT_ID=your_tenant_id
     export AZURE_CLIENT_ID=your_client_id
     export AZURE_CLIENT_SECRET=your_client_secret
     ```
   - Service principal configuration in the framework config file

2. Ensure the service principal or user has the following roles:
   - Contributor
   - Security Admin
   - Log Analytics Contributor

### GCP Configuration

1. Configure GCP credentials using one of the following methods:
   - GCloud CLI: `gcloud auth application-default login`
   - Environment variable:
     ```bash
     export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
     ```
   - Service account key configuration in the framework config file

2. Ensure the service account has the following roles:
   - Compute Admin
   - Storage Admin
   - IAM Admin
   - Security Center Admin

## Framework Configuration

Create a configuration file at `config/config.json`:

```json
{
  "simulation": {
    "platforms": {
      "aws": {
        "region_name": "us-west-2",
        "profile_name": "mttd-benchmark"
      },
      "azure": {
        "subscription_id": "00000000-0000-0000-0000-000000000000",
        "resource_group": "mttd-benchmark"
      },
      "gcp": {
        "project_id": "mttd-benchmark-project",
        "region": "us-central1"
      }
    }
  },
  "monitoring": {
    "polling_interval": 30,
    "services": {
      "aws_guardduty": {
        "region_name": "us-west-2",
        "profile_name": "mttd-benchmark"
      },
      "azure_sentinel": {
        "subscription_id": "00000000-0000-0000-0000-000000000000",
        "resource_group": "mttd-benchmark",
        "workspace_id": "00000000-0000-0000-0000-000000000000"
      },
      "gcp_security_command": {
        "project_id": "mttd-benchmark-project"
      }
    }
  },
  "metrics": {
    "detection_timeout": 3600
  },
  "reporting": {
    "output_dir": "reports"
  }
}
```

Customize the configuration according to your cloud environments and needs.

## Verifying Installation

To verify the installation:

1. Run the CLI help command:
   ```bash
   mttd-benchmark --help
   ```

2. List available scenarios:
   ```bash
   mttd-benchmark list
   ```

## Troubleshooting

### Common Issues

1. **Missing Cloud SDK Dependencies**
   
   If you encounter errors about missing cloud SDK dependencies, install them separately:
   ```bash
   pip install boto3  # For AWS
   pip install azure-identity azure-mgmt-security  # For Azure
   pip install google-cloud-compute google-cloud-securitycenter  # For GCP
   ```

2. **Authentication Errors**
   
   Ensure your cloud credentials are properly configured and have the necessary permissions.

3. **Region or Resource Constraints**
   
   Some cloud regions may have resource constraints. If you encounter quota issues, try a different region or request quota increases.

## Optional Components

### Visualization Dependencies

For full visualization capabilities, install matplotlib:

```bash
pip install matplotlib
```

### Web UI Dependencies

To use the web interface, install the web dependencies:

```bash
pip install flask flask-cors
```

Start the web interface with:

```bash
python -m mttd_benchmarking.web.app
```

Then access it at http://localhost:5000

## Next Steps

After installation, proceed to:

1. [Configure your first scenario](scenarios.md)
2. [Run a benchmark](index.md#running-a-benchmark)
3. [Analyze the results](index.md#analyzing-results)