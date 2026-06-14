# Project 12: Cloud Security Investigation (AWS/Azure)
**Platform:** AWS Free Tier + Azure Free Trial + Cloud Security Tools | **Duration:** 3 weeks | **Difficulty:** Advanced

---

## Project Overview

Conduct real-world **cloud security investigations** across AWS and Azure — analyzing CloudTrail forensics, triaging GuardDuty alerts, detecting S3 misconfigurations, investigating IAM privilege escalation in AWS, and performing Sentinel incident investigation, Entra ID attack detection, and PIM abuse scenarios in Azure.

**This project proves you can:**
- Investigate cloud-native security incidents across multi-cloud environments
- Analyze cloud audit trails (CloudTrail, Azure Activity Logs) for attack evidence
- Detect and respond to identity-based cloud attacks (IAM escalation, PIM abuse)
- Identify and remediate cloud misconfigurations (the #1 cloud breach cause)
- Think strategically about shared responsibility and cloud security architecture

**The Impact:** Detect 100% of simulated cloud attacks, reduce cloud misconfiguration exposure by 90%, and build multi-cloud investigation capability.

---

## Learning Objectives

- Master AWS CloudTrail log analysis for forensic investigation
- Triage and investigate AWS GuardDuty findings
- Detect S3 bucket misconfigurations and data exposure risks
- Investigate IAM privilege escalation attack chains in AWS
- Conduct Azure Sentinel incident investigation and KQL querying
- Detect Entra ID (Azure AD) attacks: password spray, MFA bypass, consent phishing
- Identify PIM (Privileged Identity Management) abuse scenarios
- Build cloud-specific detection rules and response playbooks

---

## Tools & Technologies

### AWS Stack
| Tool | Role | Function |
|------|------|----------|
| **AWS CloudTrail** | Audit logging | API call history for forensics |
| **AWS GuardDuty** | Threat detection | ML-based threat finding service |
| **AWS IAM Access Analyzer** | Misconfiguration | Identify overprivileged roles/policies |
| **AWS Config** | Compliance | Track resource configuration changes |
| **AWS S3** | Storage investigation | Bucket policy analysis, access logging |
| **Prowler** | Security scanner | Open-source AWS/Azure security assessment |
| **Pacu** | Attack simulation | AWS exploitation framework (ethical) |

### Azure Stack
| Tool | Role | Function |
|------|------|----------|
| **Microsoft Sentinel** | Cloud SIEM | Log analytics, incident investigation |
| **Entra ID (Azure AD)** | Identity | Authentication logs, risk detections |
| **Azure PIM** | Privileged access | JIT role elevation, audit logs |
| **Azure Activity Log** | Audit trail | Resource management operations |
| **Microsoft Defender for Cloud** | CSPM | Security posture scoring, recommendations |
| **AzureHound** | Attack paths | BloodHound for Azure AD |

---

## Step-by-Step Execution Plan

### **Week 1: AWS Security Investigation**

#### Day 1-2: AWS Environment Setup & CloudTrail Configuration

**Step 1: Create AWS Free Tier Account**

```bash
# After account creation, enable CloudTrail
aws cloudtrail create-trail \
  --name soc-investigation-trail \
  --s3-bucket-name soc-cloudtrail-logs-$(date +%s) \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name soc-investigation-trail

# Enable GuardDuty
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES
```

**Step 2: Create Vulnerable Resources for Investigation**

```bash
# Create S3 bucket with intentional misconfigurations
aws s3 mb s3://soc-test-misconfigured-bucket

# Misconfiguration 1: Public read access (DON'T do in production!)
aws s3api put-bucket-acl --bucket soc-test-misconfigured-bucket --acl public-read

# Misconfiguration 2: No encryption
aws s3api put-bucket-encryption --bucket soc-test-misconfigured-bucket \
  --server-side-encryption-configuration '{"Rules":[]}'

# Create overprivileged IAM user
aws iam create-user --user-name test-overprivileged
aws iam attach-user-policy --user-name test-overprivileged \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access keys (for investigation later)
aws iam create-access-key --user-name test-overprivileged
```

**Step 3: Generate Sample CloudTrail Events**

```python
# generate_aws_events.py
import boto3
import time

session = boto3.Session(profile_name='soc-lab')

# Simulate suspicious IAM enumeration
iam = session.client('iam')
sts = session.client('sts')

# Action 1: Enumerate all users (reconnaissance)
users = iam.list_users()
print(f"Enumerated {len(users['Users'])} IAM users")

# Action 2: Enumerate all roles
roles = iam.list_roles()
print(f"Enumerated {len(roles['Roles'])} IAM roles")

# Action 3: Enumerate all policies
policies = iam.list_policies(Scope='Local')
print(f"Enumerated {len(policies['Policies'])} policies")

# Action 4: Attempt to create admin user (privilege escalation)
try:
    iam.create_user(UserName='backdoor-admin')
    iam.attach_user_policy(
        UserName='backdoor-admin',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    print("Created backdoor admin user")
except Exception as e:
    print(f"Privilege escalation blocked: {e}")

# Action 5: Access S3 data
s3 = session.client('s3')
buckets = s3.list_buckets()
for bucket in buckets['Buckets']:
    print(f"Accessing bucket: {bucket['Name']}")
    try:
        objects = s3.list_objects_v2(Bucket=bucket['Name'])
        print(f"  Objects: {objects.get('KeyCount', 0)}")
    except Exception as e:
        print(f"  Access denied: {e}")
```

---

#### Day 3-5: CloudTrail Forensic Investigation

**Objective:** Investigate the simulated attack using CloudTrail logs.

**Step 1: Query CloudTrail with Athena**

```sql
-- Create Athena table for CloudTrail logs
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIPAddress STRING,
    userAgent STRING,
    userIdentity STRUCT<
        type: STRING,
        arn: STRING,
        accountId: STRING,
        userName: STRING
    >,
    requestParameters STRING,
    responseElements STRING,
    errorCode STRING,
    errorMessage STRING
)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
LOCATION 's3://soc-cloudtrail-logs/AWSLogs/';

-- Investigation Query 1: IAM Enumeration Detection
SELECT eventTime, eventName, userIdentity.userName, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('ListUsers', 'ListRoles', 'ListPolicies', 'GetUser', 'GetRole')
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime;

-- Investigation Query 2: Privilege Escalation Attempts
SELECT eventTime, eventName, userIdentity.userName, sourceIPAddress,
       requestParameters, errorCode
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreateUser', 'AttachUserPolicy', 'CreateAccessKey',
                     'PutUserPolicy', 'CreateRole', 'AttachRolePolicy')
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime;

-- Investigation Query 3: S3 Data Access from Unusual Sources
SELECT eventTime, eventName, userIdentity.userName, sourceIPAddress,
       requestParameters
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('GetObject', 'ListBucket', 'PutBucketAcl', 'PutBucketPolicy')
  AND sourceIPAddress NOT IN ('known-office-ip-1', 'known-vpn-ip-2')
ORDER BY eventTime;

-- Investigation Query 4: Console Logins from Unusual Locations
SELECT eventTime, userIdentity.userName, sourceIPAddress,
       responseElements
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND eventTime > date_add('day', -30, now())
ORDER BY eventTime;
```

**Step 2: GuardDuty Alert Triage**

```python
# guardduty_triage.py
import boto3
import json

guardduty = boto3.client('guardduty')

# Get detector ID
detectors = guardduty.list_detectors()
detector_id = detectors['DetectorIds'][0]

# List all findings
findings = guardduty.list_findings(
    DetectorId=detector_id,
    FindingCriteria={
        'Criterion': {
            'severity': {'Gte': 4}  # Medium and above
        }
    }
)

# Get finding details
if findings['FindingIds']:
    details = guardduty.get_findings(
        DetectorId=detector_id,
        FindingIds=findings['FindingIds']
    )

    for finding in details['Findings']:
        print(f"\n{'='*60}")
        print(f"Type: {finding['Type']}")
        print(f"Severity: {finding['Severity']}")
        print(f"Title: {finding['Title']}")
        print(f"Description: {finding['Description']}")
        print(f"Resource: {json.dumps(finding['Resource'], indent=2)}")
        print(f"Action: {json.dumps(finding.get('Service', {}).get('Action', {}), indent=2)}")

        # Triage decision
        if finding['Severity'] >= 7:
            print(">>> TRIAGE: CRITICAL — Immediate investigation required")
        elif finding['Severity'] >= 4:
            print(">>> TRIAGE: MEDIUM — Investigate within 4 hours")
        else:
            print(">>> TRIAGE: LOW — Review in daily queue")
```

**Step 3: S3 Misconfiguration Detection**

```bash
# Use Prowler for comprehensive S3 audit
pip install prowler
prowler aws --service s3 --output-formats json csv html

# Key checks Prowler performs:
# - S3 buckets with public access
# - S3 buckets without encryption
# - S3 buckets without versioning
# - S3 buckets without logging
# - S3 bucket policy analysis
```

---

#### Day 6-7: AWS IAM Privilege Escalation Investigation

**Simulate & Investigate IAM Escalation Paths:**

```python
# iam_escalation_detector.py
import boto3
import json

iam = boto3.client('iam')

def check_privilege_escalation_paths():
    """Identify IAM users/roles with privilege escalation potential."""
    
    escalation_paths = []
    
    # Get all users
    users = iam.list_users()['Users']
    
    for user in users:
        username = user['UserName']
        
        # Get attached policies
        attached = iam.list_attached_user_policies(UserName=username)
        inline = iam.list_user_policies(UserName=username)
        
        for policy in attached['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            
            # Get policy document
            version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            doc = iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version
            )['PolicyVersion']['Document']
            
            # Check for dangerous permissions
            for statement in doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    dangerous_actions = [
                        'iam:CreateUser', 'iam:AttachUserPolicy',
                        'iam:PutUserPolicy', 'iam:CreateAccessKey',
                        'iam:PassRole', 'iam:CreateRole',
                        'iam:AttachRolePolicy', 'sts:AssumeRole',
                        'iam:*', '*'
                    ]
                    
                    for action in actions:
                        if action in dangerous_actions or action == '*':
                            escalation_paths.append({
                                'user': username,
                                'policy': policy_arn,
                                'dangerous_action': action,
                                'resource': statement.get('Resource', '*'),
                                'risk': 'CRITICAL' if action in ['iam:*', '*'] else 'HIGH'
                            })
    
    return escalation_paths

paths = check_privilege_escalation_paths()
print(f"\n=== IAM PRIVILEGE ESCALATION PATHS: {len(paths)} FOUND ===\n")
for path in paths:
    print(f"User: {path['user']}")
    print(f"  Policy: {path['policy']}")
    print(f"  Action: {path['dangerous_action']}")
    print(f"  Risk: {path['risk']}")
    print()
```

---

### **Week 2: Azure Security Investigation**

#### Day 8-10: Azure Sentinel Setup & Entra ID Investigation

**Step 1: Azure Environment Setup**

```bash
# Create resource group
az group create --name soc-investigation-rg --location eastus

# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group soc-investigation-rg \
  --workspace-name soc-sentinel-workspace

# Enable Microsoft Sentinel
az sentinel onboarding-state create \
  --resource-group soc-investigation-rg \
  --workspace-name soc-sentinel-workspace
```

**Step 2: Connect Entra ID Data Sources**

In Azure Portal:
1. **Sentinel** → Data connectors → **Microsoft Entra ID**
2. Enable: Sign-in logs, Audit logs, Provisioning logs
3. **Sentinel** → Data connectors → **Microsoft Defender for Cloud**
4. Enable: Security alerts, Recommendations

**Step 3: Entra ID Attack Detection with KQL**

```kql
// Investigation 1: Password Spray Detection
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "50126"  // Invalid username or password
| summarize FailedAttempts=count(), TargetAccounts=dcount(UserPrincipalName),
            IPAddresses=make_set(IPAddress) by bin(TimeGenerated, 10m)
| where TargetAccounts > 10 and FailedAttempts > 50
| project TimeGenerated, FailedAttempts, TargetAccounts, IPAddresses

// Investigation 2: MFA Fatigue / Push Bombing
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "500121"  // MFA denied
| summarize MFADenials=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where MFADenials > 5
| project TimeGenerated, UserPrincipalName, IPAddress, MFADenials

// Investigation 3: Suspicious OAuth Consent Grants (Consent Phishing)
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppName = TargetResources[0].displayName
| extend UserWhoConsented = InitiatedBy.user.userPrincipalName
| extend Permissions = AdditionalDetails
| project TimeGenerated, UserWhoConsented, AppName, Permissions
| where AppName !in ("Microsoft Teams", "SharePoint Online", "Outlook")

// Investigation 4: Impossible Travel Detection
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0  // Successful logins only
| extend City = LocationDetails.city, Country = LocationDetails.countryOrRegion
| summarize Locations=make_set(Country), LocationCount=dcount(Country)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where LocationCount > 1

// Investigation 5: Privileged Role Assignment Outside PIM
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "Add member to role"
| extend RoleName = TargetResources[0].displayName
| extend AssignedUser = TargetResources[0].userPrincipalName
| extend AssignedBy = InitiatedBy.user.userPrincipalName
| where RoleName in ("Global Administrator", "Privileged Role Administrator",
                       "Security Administrator")
| project TimeGenerated, AssignedBy, AssignedUser, RoleName
```

---

#### Day 11-12: PIM Abuse Scenarios

**Scenario 1: Unauthorized PIM Elevation**

```kql
// Detect PIM role activations outside business hours
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add member to role in PIM completed (permanent)"
   or OperationName == "Add eligible member to role in PIM completed"
| extend ActivatedBy = InitiatedBy.user.userPrincipalName
| extend RoleName = TargetResources[0].displayName
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay < 7 or HourOfDay > 19  // Outside business hours
| project TimeGenerated, ActivatedBy, RoleName, HourOfDay

// Detect PIM activations without justification
AuditLogs
| where OperationName has "PIM"
| extend Justification = AdditionalDetails[0].value
| where isempty(Justification) or Justification == "N/A"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, OperationName
```

**Scenario 2: PIM Policy Weakening**

```kql
// Detect changes to PIM role settings (extending duration, removing MFA)
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "Update role setting in PIM"
| extend ChangedBy = InitiatedBy.user.userPrincipalName
| extend Setting = TargetResources[0].displayName
| project TimeGenerated, ChangedBy, Setting, OperationName
```

---

#### Day 13-14: Azure Security Posture Assessment

```bash
# Run Prowler against Azure
prowler azure --service iam storage network --output-formats json csv html

# Key Azure checks:
# - Storage accounts with public blob access
# - Network Security Groups with overly permissive rules
# - Entra ID users without MFA
# - Subscription-level RBAC over-permissions
# - Key Vault access policy audit
```

---

### **Week 3: Multi-Cloud Detection Rules & Portfolio**

#### Day 15-17: Cloud-Specific Sigma/Detection Rules

**AWS CloudTrail Detection Rules:**

```yaml
# sigma_rules/aws_iam_enumeration.yml
title: AWS IAM Enumeration Activity
id: cloud-hunt-01-aws-enum
status: experimental
description: Detects rapid IAM enumeration indicating reconnaissance
author: SOC Lab
tags:
  - attack.discovery
  - attack.t1087.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - ListUsers
      - ListRoles
      - ListPolicies
      - ListGroups
      - GetAccountAuthorizationDetails
  timeframe: 10m
  condition: selection | count() > 5
level: high
```

```yaml
# sigma_rules/aws_privilege_escalation.yml
title: AWS IAM Privilege Escalation Attempt
id: cloud-hunt-02-aws-privesc
status: experimental
description: Detects IAM actions that could lead to privilege escalation
author: SOC Lab
tags:
  - attack.privilege_escalation
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName:
      - CreateUser
      - AttachUserPolicy
      - PutUserPolicy
      - CreateAccessKey
      - CreateLoginProfile
      - UpdateLoginProfile
  condition: selection
level: critical
```

#### Day 18-21: Portfolio Documentation

**Create multi-cloud investigation report with:**
- AWS CloudTrail forensic timeline
- GuardDuty triage results
- S3 misconfiguration findings
- IAM privilege escalation paths
- Azure Sentinel KQL queries
- Entra ID attack detection results
- PIM abuse scenario documentation
- Cloud-specific Sigma rules
- Multi-cloud detection coverage matrix

---

## Evidence to Capture

- [ ] AWS CloudTrail forensic investigation queries and results
- [ ] GuardDuty finding triage documentation
- [ ] S3 misconfiguration scan report (Prowler)
- [ ] IAM privilege escalation path analysis
- [ ] Azure Sentinel incident investigation screenshots
- [ ] KQL queries for Entra ID attack detection (5+ queries)
- [ ] PIM abuse detection evidence
- [ ] Cloud-specific Sigma detection rules (5+)
- [ ] Multi-cloud detection coverage matrix
- [ ] Prowler security assessment report (AWS + Azure)

---

## Resume Bullets

### Version 1: Multi-Cloud Security Operations (CISO-Path)
> **Multi-Cloud Security Investigation & Detection Engineering**  
> - Led cloud security investigations across AWS and Azure environments, analyzing CloudTrail forensics, triaging GuardDuty findings, and conducting Sentinel incident investigations that detected 100% of simulated cloud attacks including IAM privilege escalation and Entra ID compromise  
> - Identified and remediated 15+ cloud misconfigurations using Prowler and IAM Access Analyzer, reducing cloud attack surface by 90% and establishing automated posture assessment pipeline for continuous compliance monitoring  
> - Developed 10+ cloud-native detection rules covering AWS IAM enumeration, S3 data exfiltration, Azure PIM abuse, and Entra ID password spray attacks, creating reusable detection library adopted across multi-cloud SOC operations

### Version 2: Cloud Identity Security (CISO-Path)
> **Cloud Identity Threat Detection & Response Program**  
> - Built cloud ITDR capability detecting Entra ID password spray, MFA fatigue, consent phishing, and PIM abuse attacks using KQL analytics in Microsoft Sentinel, achieving <10 minute detection time for identity-based cloud threats  
> - Investigated IAM privilege escalation chains in AWS, identifying 8 critical paths from low-privilege user to administrative access and implementing least-privilege policies reducing overprivileged accounts by 95%  
> - Designed cloud security investigation playbooks covering AWS CloudTrail forensics and Azure Sentinel workflows, enabling SOC team to conduct cloud investigations 60% faster with standardized evidence collection

### Version 3: Strategic Cloud Security (CISO-Path)
> **Enterprise Cloud Security Posture & Governance**  
> - Established multi-cloud security monitoring program spanning AWS and Azure, providing unified visibility into 500+ cloud resources and enabling board-level reporting on cloud risk posture with quantified misconfiguration metrics  
> - Translated cloud shared responsibility model into operational security controls, implementing automated S3 public access detection, IAM drift monitoring, and PIM policy compliance checks that prevented 3 potential data exposure incidents  
> - Demonstrated CISO-level cloud security expertise by bridging technical investigation with business risk communication, presenting cloud security findings with cost-of-breach analysis that secured $200K budget for cloud security tooling

---

## Interview Talking Points

### Question: "How do you investigate a security incident in the cloud?"

**STAR Answer:**

**Situation:**  
"Cloud incidents require different investigation techniques than on-premises — there are no disk images to capture, no physical access. Everything is API calls, logs, and configuration state."

**Task:**  
"I built a multi-cloud investigation lab to develop expertise in AWS CloudTrail forensics, GuardDuty triage, and Azure Sentinel investigations."

**Action:**  
"For AWS, my investigation workflow starts with CloudTrail — querying for the suspicious user's API calls chronologically. I use Athena to run SQL queries across CloudTrail logs, looking for IAM enumeration (ListUsers, ListRoles), privilege escalation attempts (AttachUserPolicy, CreateAccessKey), and data access patterns (S3 GetObject from unusual IPs).

For Azure, I use Sentinel KQL queries against SigninLogs and AuditLogs. I look for password spray patterns (many failed logins to different accounts), impossible travel (logins from two countries in one hour), and suspicious OAuth consent grants.

The critical difference from on-prem: in cloud, I must also investigate the configuration state — was an S3 bucket made public? Was a security group opened? Was a PIM policy weakened? These configuration changes are attacks in the cloud context."

**Result:**  
"I detected 100% of simulated attacks across both clouds, built 10+ cloud-specific detection rules, and created standardized investigation playbooks. The key insight: cloud security is identity security — 80% of cloud breaches start with compromised or overprivileged credentials."

---

## Skills Developed Checklist

**Technical Skills:**
- [ ] AWS CloudTrail forensic analysis
- [ ] AWS GuardDuty alert triage
- [ ] AWS IAM security assessment
- [ ] S3 security configuration auditing
- [ ] Azure Sentinel (KQL query development)
- [ ] Entra ID attack detection
- [ ] Azure PIM administration and abuse detection
- [ ] Prowler multi-cloud security scanning
- [ ] Cloud-native Sigma rule authoring

**Frameworks:**
- [ ] AWS Shared Responsibility Model
- [ ] Azure Security Benchmark
- [ ] CIS AWS/Azure Benchmarks
- [ ] MITRE ATT&CK Cloud Matrix
- [ ] Cloud Security Alliance (CSA) framework

**Soft Skills:**
- [ ] Multi-cloud security strategy
- [ ] Cloud risk communication to leadership
- [ ] Cross-platform investigation methodology
- [ ] Cloud security budget justification

---

## Common Mistakes to Avoid

1. **Not enabling CloudTrail first:** Without logs, there's nothing to investigate
2. **Ignoring IAM over-permissions:** The #1 cloud vulnerability — audit regularly
3. **Using root account:** Create IAM users with least privilege for all operations
4. **Forgetting to clean up:** Delete test resources to avoid unexpected AWS/Azure charges
5. **Treating cloud like on-prem:** Cloud investigation is API-centric, not disk-centric
6. **Skipping Azure PIM:** PIM abuse is a top Entra ID attack vector — don't overlook it

---

**Total Time Investment:** 40-50 hours over 3 weeks  
**Portfolio Artifacts:** CloudTrail forensics, Sentinel queries, Prowler reports, detection rules, investigation playbooks  
**Job Market Value:** Multi-cloud security is the #1 hiring requirement for senior security roles in 2026

---

**Cloud is the new perimeter. Identity is the new firewall. Master both, and you're CISO-ready.** ☁️🔒🚀
