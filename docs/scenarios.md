# Attack Scenarios

This guide explains how to work with attack scenarios in the MTTD Benchmarking Framework.

## Scenario Overview

Attack scenarios define the sequence of attack techniques to execute during a simulation. Scenarios are defined in JSON format and include:

- Basic information (ID, name, description)
- Platform configuration
- Resources to create
- Attack steps to execute
- Expected alerts

## Included Scenarios

The framework includes several pre-defined scenarios:

### AWS Privilege Escalation

**File:** `aws-privilege-escalation-001.json`

This scenario simulates an attacker gaining initial access and escalating privileges through IAM manipulation:

1. Initial access using valid credentials
2. Account discovery to identify targets
3. Creation of a new IAM user
4. Attaching administrator policy to the new user
5. Creating access keys for the new user
6. Accessing S3 data with escalated privileges
7. Exfiltrating data to an external account

### AWS Data Exfiltration

**File:** `aws-data-exfiltration-001.json`

This scenario simulates an attacker accessing and exfiltrating sensitive data from S3 buckets:

1. Initial access using valid credentials
2. Account and S3 bucket discovery
3. S3 object enumeration
4. Data access and download
5. Exfiltration via alternative protocol (DNS)
6. Attempt to delete CloudTrail logs

### Azure Lateral Movement

**File:** `azure-lateral-movement-001.json`

This scenario simulates an attacker gaining initial access and moving laterally through Azure resources:

1. Initial access using valid credentials
2. Account discovery
3. Creation of a new user account
4. Privilege escalation through role assignment
5. Stealing application access tokens
6. Data exfiltration to external storage

### GCP Cryptomining

**File:** `gcp-cryptomining-001.json`

This scenario simulates an attacker compromising GCP resources to deploy cryptomining workloads:

1. Initial access using valid credentials
2. Account discovery
3. Creation of a new service account
4. Privilege escalation through role assignment
5. Uploading a container image with mining software
6. Deploying compute-intensive workloads
7. Exfiltrating mining profits

## Scenario Structure

Scenarios are defined in JSON format with the following structure:

```json
{
  "id": "unique-scenario-id",
  "name": "Human-readable Scenario Name",
  "description": "Detailed description of the scenario",
  "platform": {
    "name": "aws|azure|gcp",
    "service_name": "aws_guardduty|azure_sentinel|gcp_security_command",
    "region": "us-west-2"
  },
  "environment_config": {
    "resources": {
      "resource_type_1": [
        {
          "parameter1": "value1",
          "parameter2": "value2"
        }
      ],
      "resource_type_2": [
        {
          "parameter1": "value1",
          "parameter2": "value2"
        }
      ]
    }
  },
  "steps": [
    {
      "name": "Step Name",
      "technique_id": "T1078",
      "description": "Step description",
      "parameters": {
        "param1": "value1",
        "param2": "value2"
      },
      "expected_indicators": [
        "indicator-type-1",
        "indicator-type-2"
      ]
    }
  ],
  "expected_alerts": [
    {
      "service": "aws_guardduty",
      "finding_type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
      "severity": "MEDIUM",
      "time_to_detect_range": [60, 300]
    }
  ]
}
```

## Creating Custom Scenarios

To create a custom scenario:

1. Create a new JSON file in the `config/scenarios` directory
2. Define the scenario structure as shown above
3. Validate the scenario using the CLI:
   ```bash
   mttd-benchmark validate --file config/scenarios/your-scenario.json
   ```

### Platform Configuration

Define which cloud platform and security service to test:

```json
"platform": {
  "name": "aws",
  "service_name": "aws_guardduty",
  "region": "us-west-2"
}
```

Supported platforms:
- AWS (`aws`)
- Azure (`azure`)
- GCP (`gcp`)

### Resource Configuration

Define the resources to create for the simulation:

```json
"environment_config": {
  "resources": {
    "ec2_instance": [
      {
        "image_id": "ami-0c55b159cbfafe1f0",
        "instance_type": "t2.micro"
      }
    ],
    "s3_bucket": [
      {
        "public_access": false
      }
    ]
  }
}
```

Supported resource types vary by platform:

**AWS:**
- `ec2_instance`
- `s3_bucket`
- `iam_user`
- `iam_role`
- `lambda_function`
- `cloudtrail`
- `cloudwatch_alarm`

**Azure:**
- `virtual_machine`
- `storage_account`
- `managed_identity`
- `app_service`
- `logic_app`

**GCP:**
- `compute_instance`
- `storage_bucket`
- `iam_service_account`
- `cloud_function`

### Attack Steps

Define the sequence of attack techniques to execute:

```json
"steps": [
  {
    "name": "Initial Access",
    "technique_id": "T1078",
    "description": "Initial access using valid credentials",
    "parameters": {
      "user_name": "legitimate-user",
      "source_ip": "198.51.100.1"
    },
    "expected_indicators": [
      "aws-api-call",
      "unusual-api-call-location"
    ]
  }
]
```

Each step includes:
- `name`: Human-readable name
- `technique_id`: MITRE ATT&CK technique ID
- `description`: Step description
- `parameters`: Technique-specific parameters
- `expected_indicators`: Indicator types this step should generate

### Supported Techniques

The framework supports the following MITRE ATT&CK techniques:

**Initial Access:**
- `T1078`: Valid Accounts

**Persistence:**
- `T1136`: Create Account
- `T1098`: Account Manipulation

**Discovery:**
- `T1087`: Account Discovery
- `T1083`: File and Directory Discovery

**Privilege Escalation:**
- `T1098`: Account Manipulation

**Credential Access:**
- `T1528`: Steal Application Access Token (Azure)

**Collection:**
- `T1530`: Data from Cloud Storage

**Exfiltration:**
- `T1048`: Exfiltration Over Alternative Protocol
- `T1537`: Transfer to Cloud Account

**Impact:**
- `T1496`: Resource Hijacking (GCP)

**Defense Evasion:**
- `T1070.004`: File Deletion
- `T1525`: Implant Container Image (GCP)

### Expected Alerts

Define the alerts that security services should generate:

```json
"expected_alerts": [
  {
    "service": "aws_guardduty",
    "finding_type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "severity": "MEDIUM",
    "time_to_detect_range": [60, 300]
  }
]
```

Each expected alert includes:
- `service`: Security service name
- `finding_type`: Type of finding/alert expected
- `severity`: Expected severity level
- `time_to_detect_range`: Range of acceptable detection times in seconds [min, max]

## Executing Scenarios

Execute a scenario using the CLI:

```bash
mttd-benchmark execute --scenario-id aws-privilege-escalation-001
```

Or override the security service:

```bash
mttd-benchmark execute --scenario-id aws-privilege-escalation-001 --service aws_securityhub
```

## Tips for Effective Scenarios

1. **Start Simple**: Begin with a few attack steps and gradually add complexity
2. **Use Realistic Parameters**: Set realistic parameters that reflect actual attacks
3. **Define Clear Indicators**: Clearly define expected indicators for each step
4. **Set Reasonable Time Ranges**: Set realistic detection time expectations
5. **Test Incrementally**: Test each step individually before running the full scenario
6. **Document Assumptions**: Document any assumptions about the environment
7. **Consider Service Limitations**: Be aware of the limitations of different security services

## Troubleshooting

### Common Issues

1. **Resource Creation Failures**
   
   Check that your cloud credentials have the necessary permissions to create resources.

2. **Technique Execution Failures**
   
   Ensure technique parameters are valid and check logs for specific error messages.

3. **Missing Detections**
   
   Verify that the security service is properly configured and check for any filtering that might prevent detection.

### Debug Mode

Run scenarios in debug mode for more detailed logging:

```bash
mttd-benchmark execute --scenario-id your-scenario-id --log-level DEBUG
```

## Advanced Features

### Resource References

Reference resources created during simulation within step parameters:

```json
"parameters": {
  "bucket_name": "$resource:s3_bucket_1"
}
```

### Conditional Steps

Execute steps conditionally based on previous results:

```json
"condition": {
  "step_id": "previous_step_id",
  "status": "completed"
}
```

### Automatic Value Generation

Use special placeholders for automatic value generation:

```json
"parameters": {
  "user_name": "mttd-user-${random_hex:8}"
}
```