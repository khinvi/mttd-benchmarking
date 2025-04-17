# Cloud Security Services

This document provides information about the cloud security services supported by the MTTD Benchmarking Framework.

## Supported Services

The framework supports benchmarking the following security services:

### AWS Services

| Service | Description | Key Features |
|---------|-------------|--------------|
| **AWS GuardDuty** | Threat detection service that continuously monitors for malicious activity and unauthorized behavior | - Anomaly detection<br>- ML-based threat detection<br>- Integration with CloudTrail, VPC Flow Logs, and DNS logs |
| **AWS Security Hub** | Security findings aggregator that performs security checks against best practices and standards | - Compliance checks<br>- Findings aggregation<br>- Integration with third-party tools |

### Azure Services

| Service | Description | Key Features |
|---------|-------------|--------------|
| **Azure Sentinel** | Cloud-native SIEM and SOAR solution | - AI-based threat detection<br>- Security orchestration and automation<br>- Integration with Microsoft and third-party products |
| **Microsoft Defender for Cloud** | Cloud security posture management (CSPM) and cloud workload protection platform (CWPP) | - Security posture management<br>- Vulnerability assessment<br>- Threat protection |

### GCP Services

| Service | Description | Key Features |
|---------|-------------|--------------|
| **Security Command Center** | Security and risk management platform | - Threat detection<br>- Security posture management<br>- Vulnerability scanning<br>- Integration with Google Cloud services |

## Service Integration

The framework integrates with cloud security services through standardized interfaces:

### Security Client Interface

All security service clients implement the following interface:

```python
def get_security_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]
```

This method retrieves security events/alerts that occurred within the specified time range.

### Factory Pattern

The framework uses a factory pattern to create appropriate security clients:

```python
client = get_security_client(
    service_name="aws_guardduty",
    provider=CloudProvider.AWS,
    config=config
)
```

## AWS Security Services

### AWS GuardDuty

**Service Name:** `aws_guardduty`

AWS GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior in AWS accounts and workloads.

#### Configuration

```json
"aws_guardduty": {
  "region_name": "us-west-2",
  "profile_name": "mttd-benchmark"
}
```

#### Supported Finding Types

- `UnauthorizedAccess:IAMUser/MaliciousIPCaller`
- `Discovery:IAMUser/AnomalousBehavior`
- `Persistence:IAMUser/UserPermissions`
- `PrivilegeEscalation:IAMUser/AdministrativePermissions`
- `Exfiltration:S3/MaliciousIPCaller`
- `Discovery:S3/BucketEnumeration`
- `Exfiltration:S3/ObjectRead`
- `DefenseEvasion:CloudTrail/LogsDeleted`

### AWS Security Hub

**Service Name:** `aws_securityhub`

AWS Security Hub is a cloud security posture management (CSPM) service that performs security best practice checks and aggregates alerts.

#### Configuration

```json
"aws_securityhub": {
  "region_name": "us-west-2",
  "profile_name": "mttd-benchmark"
}
```

#### Supported Finding Types

- `TTPs/Initial.Access/UnauthorizedAccess`
- `TTPs/Discovery/Account.Discovery`
- `TTPs/Persistence/Account.Creation`
- `TTPs/Persistence/Account.Manipulation`
- `TTPs/Exfiltration/Transfer.to.Cloud.Account`
- `TTPs/Exfiltration/Exfiltration.Over.Alternative.Protocol`
- `TTPs/Collection/Data.from.Cloud.Storage`
- `TTPs/DefenseEvasion/Indicator.Removal.On.Host`

## Azure Security Services

### Azure Sentinel

**Service Name:** `azure_sentinel`

Azure Sentinel is a cloud-native SIEM and SOAR solution that provides intelligent security analytics across the enterprise.

#### Configuration

```json
"azure_sentinel": {
  "subscription_id": "00000000-0000-0000-0000-000000000000",
  "resource_group": "mttd-benchmark",
  "workspace_id": "00000000-0000-0000-0000-000000000000",
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "client_secret": "your-client-secret"
}
```

#### Supported Alert Types

- `Suspicious sign-in activity`
- `User enumeration activity`
- `New user creation`
- `Privileged role assignment`
- `Application token theft`
- `Data exfiltration to storage account`

### Microsoft Defender for Cloud

**Service Name:** `azure_defender`

Microsoft Defender for Cloud (formerly Azure Security Center) is a unified security management system that strengthens the security posture of your cloud resources.

#### Configuration

```json
"azure_defender": {
  "subscription_id": "00000000-0000-0000-0000-000000000000",
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "client_secret": "your-client-secret"
}
```

#### Supported Alert Types

- `Suspicious sign-in activity detected`
- `Addition of account with privileged role detected`
- `Account enumeration activity detected`
- `Account manipulation activity detected`
- `Suspicious application consent detected`
- `Data exfiltration to storage detected`

## GCP Security Services

### Security Command Center

**Service Name:** `gcp_security_command`

Security Command Center is a risk management platform that helps organizations identify and remediate security vulnerabilities and threats.

#### Configuration

```json
"gcp_security_command": {
  "project_id": "mttd-project-id",
  "organization_id": "000000000000",
  "credentials_file": "/path/to/credentials.json"
}
```

#### Supported Finding Types

- `IAM_ABNORMAL_GRANT`
- `IAM_ANOMALOUS_ACCOUNT_CREATION`
- `IAM_ANOMALOUS_ACCOUNT_ENUMERATION`
- `IAM_PRIVILEGED_ACCESS_GRANT`
- `CONTAINER_SUSPICIOUS_IMAGE_PUSH`
- `ANOMALOUS_COMPUTE_USAGE`
- `STORAGE_EXFILTRATION`

## Service Detection Capabilities

The following table provides an overview of detection capabilities by service and attack technique:

| Technique ID | Technique Name | AWS GuardDuty | AWS Security Hub | Azure Sentinel | Azure Defender | GCP Security Command |
|--------------|----------------|--------------:|----------------:|--------------:|--------------:|---------------------:|
| T1078 | Valid Accounts | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1136 | Create Account | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1087 | Account Discovery | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1098 | Account Manipulation | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1528 | Steal Application Access Token | ✗ | ✗ | ✓ | ✓ | ✗ |
| T1530 | Data from Cloud Storage | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1048 | Exfiltration Over Alternative Protocol | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1537 | Transfer to Cloud Account | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1525 | Implant Container Image | ✗ | ✗ | ✗ | ✗ | ✓ |
| T1496 | Resource Hijacking | ✓ | ✓ | ✓ | ✓ | ✓ |
| T1070.004 | File Deletion | ✓ | ✓ | ✓ | ✓ | ✓ |

## Adding Custom Security Services

To add a custom security service:

1. Create a new Python module in the appropriate service directory:
   ```
   mttd_benchmarking/services/provider/your_service.py
   ```

2. Implement the SecurityClient class with the required interface:
   ```python
   class SecurityClient:
       def __init__(self, config: Dict[str, Any]):
           # Initialize client
           
       def get_security_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
           # Retrieve security events
           
       def create_sample_alert(self, technique_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
           # Create a sample alert for testing
   ```

3. Register the service in the service factory:
   ```python
   # In mttd_benchmarking/services/factory.py
   service_modules = {
       # Add your service
       "your_service_name": "mttd_benchmarking.services.provider.your_service"
   }
   ```

4. Update the configuration to include your service:
   ```json
   "monitoring": {
     "services": {
       "your_service_name": {
         "parameter1": "value1",
         "parameter2": "value2"
       }
     }
   }
   ```

## Service Authentication

### AWS Authentication

AWS services support the following authentication methods:

1. **Profile-based authentication**:
   ```json
   "profile_name": "mttd-benchmark"
   ```

2. **Access key authentication**:
   ```json
   "aws_access_key_id": "your-access-key",
   "aws_secret_access_key": "your-secret-key"
   ```

3. **Environment variable authentication** (no config needed):
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_DEFAULT_REGION=us-west-2
   ```

### Azure Authentication

Azure services support the following authentication methods:

1. **Service principal authentication**:
   ```json
   "tenant_id": "00000000-0000-0000-0000-000000000000",
   "client_id": "00000000-0000-0000-0000-000000000000",
   "client_secret": "your-client-secret"
   ```

2. **Default credential authentication** (no credentials in config):
   Uses environment variables or managed identities

### GCP Authentication

GCP services support the following authentication methods:

1. **Service account key file**:
   ```json
   "credentials_file": "/path/to/credentials.json"
   ```

2. **Application default credentials** (no credentials in config):
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
   ```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   
   Check that your cloud credentials are valid and have the necessary permissions.

2. **Service API Limitations**
   
   Some services have API rate limits that can affect polling. Adjust the polling interval if needed:
   ```json
   "monitoring": {
     "polling_interval": 60
   }
   ```

3. **Missing Detections**
   
   Verify that the security service is properly configured and enabled. Some services require specific features to be enabled.

4. **Network Connectivity Issues**
   
   Ensure that your machine has network connectivity to the cloud provider APIs.

### Fallback Mechanisms

If a specific service client fails to initialize or operate, the framework can fall back to:

1. **Provider-specific generic client**:
   A simplified client for the same cloud provider

2. **Fully generic client**:
   A mock implementation that can be used for testing

This ensures that the framework can continue to function even if some service integrations are not available.