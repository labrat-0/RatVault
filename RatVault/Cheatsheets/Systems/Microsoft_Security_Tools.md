---
tags: [cheatsheet, microsoft, security, defender, sentinel, m365]
aliases: [Microsoft Security Stack, Microsoft Security Ecosystem]
created: {{date}}
updated: {{date}}
---

# 🔐 Microsoft Security Tools Ecosystem

> [!info] About Microsoft Security
> Microsoft offers a comprehensive suite of security tools that span from endpoint protection to cloud security. This cheatsheet provides an overview of these tools, their key features, and how to integrate them into security operations.

## 📋 Table of Contents

- [Microsoft Defender for Endpoint](#microsoft-defender-for-endpoint)
- [Microsoft Sentinel](#microsoft-sentinel)
- [Microsoft Defender for Cloud](#microsoft-defender-for-cloud)
- [Microsoft Defender for Identity](#microsoft-defender-for-identity)
- [Microsoft Defender for Office 365](#microsoft-defender-for-office-365)
- [Microsoft Purview](#microsoft-purview)
- [Microsoft Intune](#microsoft-intune)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Microsoft Security Score](#microsoft-security-score)
- [Integration and Cross-Platform Analysis](#integration-and-cross-platform-analysis)

## Microsoft Defender for Endpoint

A unified endpoint security platform that helps protect against advanced threats.

### Key Components

- **Endpoint Detection and Response (EDR)**: Real-time detection, investigation, and response capabilities.
- **Threat & Vulnerability Management**: Discover, prioritize, and remediate vulnerabilities.
- **Attack Surface Reduction (ASR)**: Harden endpoints against common attack vectors.
- **Next-Generation Protection**: Antivirus and anti-malware capabilities.
- **Advanced Hunting**: Custom query-based threat hunting.

### Important Features

```powershell
# Enable EDR in block mode via PowerShell
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -SubmitSamplesConsent Always
Set-MpPreference -MAPSReporting Advanced

# Enable Attack Surface Reduction rules
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule_id> -AttackSurfaceReductionRules_Actions Enabled
```

### MDE Advanced Hunting Examples

```kusto
// Find suspicious PowerShell executions
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any("Invoke-Expression", "IEX", "-encodedcommand", "FromBase64String")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName

// Detect credential dumping
DeviceProcessEvents
| where FileName =~ "rundll32.exe" 
| where ProcessCommandLine has "comsvcs.dll"
    and ProcessCommandLine has "full"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Identify files created in the system32 directory
DeviceFileEvents
| where FolderPath contains "Windows\\System32"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Common Response Actions

- **Isolate device**: Disconnect compromised endpoints while maintaining security management.
- **Collect investigation package**: Gather forensic data for deeper analysis.
- **Run antivirus scan**: Trigger on-demand scans.
- **Restrict app execution**: Block specific applications.
- **Offboard machines**: Remove endpoints from MDE management.

## Microsoft Sentinel

A cloud-native Security Information and Event Management (SIEM) and Security Orchestration, Automation and Response (SOAR) solution.

### Key Components

- **Data Connectors**: Integrate with Microsoft and non-Microsoft sources.
- **Workbooks**: Interactive dashboards for visualization and analysis.
- **Analytics Rules**: Detect threats with built-in and custom detection rules.
- **Incidents**: Combine related alerts into actionable cases.
- **Hunting Queries**: Proactively search for threats.
- **Playbooks**: Automate response with Logic Apps.

### Analytics Rules Examples

```kusto
// Suspicious service installation
SecurityEvent
| where EventID == 7045 and ServiceFileName has_any("cmd.exe", "powershell.exe", "regsvr32.exe")
| extend Service = tostring(split(ServiceName, ",")[0])
| project TimeGenerated, Computer, Service, ServiceFileName, ServiceAccount

// Multiple failed logins followed by success
let failedLogons = SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress;
let successfulLogons = SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, Computer, IpAddress;
failedLogons
| summarize FailedCount = count() by Account, Computer, bin(TimeGenerated, 10m)
| where FailedCount > 5
| join kind=inner (
    successfulLogons
) on Account, Computer
| where TimeGenerated > TimeGenerated1
| project TimeGenerated, Account, Computer, IpAddress, FailedCount
```

### Playbook Integration

```
Trigger: When an alert is created
Action 1: Get alert details
Action 2: Enrich with threat intelligence
Action 3: Check if IP is internal or external
Action 4: If external, add IP to block list
Action 5: If critical severity, isolate device
Action 6: Create incident ticket in service management tool
Action 7: Send notification to security team
```

### Cost Optimization Tips

- Use Basic Logs for high-volume, low-value data
- Implement data retention policies
- Create analytics rules with appropriate frequency
- Use watchlists for common reference data
- Implement table-level RBAC to control access

## Microsoft Defender for Cloud

Cloud security posture management and workload protection for multi-cloud environments.

### Key Components

- **Secure Score**: Assess and improve security posture.
- **Resource Security Hygiene**: Identify and remediate security misconfigurations.
- **Cloud Workload Protection**: Defend servers, containers, and storage.
- **Regulatory Compliance**: Track compliance with standards like NIST, PCI-DSS, and ISO.
- **Multi-cloud Security**: Protect Azure, AWS, and GCP resources.

### Secure Score Improvement Actions

1. **Implement MFA**: Enable multi-factor authentication for privileged accounts.
2. **Apply Just-in-Time VM access**: Reduce attack surface with temporary access.
3. **Enable encrypted storage**: Ensure data is encrypted at rest.
4. **Implement network segmentation**: Apply NSGs and deny traffic by default.
5. **Enforce adaptive application controls**: Limit which applications can run.

### Security Alerts Examples

```
Alert: "Network communication with a malicious server detected"
Description: "A virtual machine in your workspace has been observed communicating with a known malicious IP address."
Remediation: Investigate the communication, isolate the VM, analyze logs for additional indicators.

Alert: "Suspicious resource deployment detected"
Description: "An unusual resource deployment was detected in your subscription."
Remediation: Verify deployment legitimacy, review permissions, implement Azure RBAC restrictions.
```

## Microsoft Defender for Identity

Cloud-based security solution that identifies, detects, and helps investigate advanced threats, compromised identities, and malicious insider actions.

### Key Components

- **Security Alerts**: Detection of suspicious activities and advanced attacks.
- **Entity Behaviors**: Profiling user behavior and detecting anomalies.
- **Lateral Movement Paths**: Visualization of potential attack paths through the network.
- **Domain Controller Monitoring**: Monitoring of authentication and authorization traffic.
- **User Investigation**: Detailed user activity timeline for analysis.

### Detection Capabilities

- **Reconnaissance techniques**: Directory enumeration, user enumeration
- **Compromised credentials**: Pass-the-hash, pass-the-ticket, brute force
- **Lateral movement**: Remote execution, credential theft
- **Privilege escalation**: Directory service exploitation
- **Domain dominance**: DCSync, Golden Ticket, Silver Ticket

### Alert Investigation Process

1. **Review the alert details**: Understand the attack technique and affected entities.
2. **Check user profile**: Review the user's privileges, group memberships, and normal behaviors.
3. **Investigate activity timeline**: Look for unusual activities before and after the alert.
4. **Examine lateral movement paths**: Identify potential attack paths to sensitive accounts.
5. **Correlate with other alerts**: Check for related suspicious activities across the environment.

## Microsoft Defender for Office 365

Protection against advanced threats like phishing and malware in email and collaboration tools.

### Key Components

- **Safe Attachments**: Protection against malicious attachments.
- **Safe Links**: Protection against malicious URLs.
- **Anti-phishing Policies**: Defense against phishing attempts.
- **Threat Explorer**: Investigation and hunting of email threats.
- **Attack Simulator**: Simulation of attacks for user awareness.

### Configuration Best Practices

```powershell
# Enable Safe Attachments (using PowerShell)
New-SafeAttachmentPolicy -Name "Block Malicious Attachments" -Action Block
New-SafeAttachmentRule -Name "Apply to All Users" -SafeAttachmentPolicy "Block Malicious Attachments" -RecipientDomainIs yourdomain.com

# Enable Safe Links
New-SafeLinksPolicy -Name "Track and Block Malicious URLs" -TrackClicks $true -IsEnabled $true
New-SafeLinksRule -Name "Apply to All Users" -SafeLinksPolicy "Track and Block Malicious URLs" -RecipientDomainIs yourdomain.com
```

### Threat Hunting with Explorer

```
# Search for phishing campaigns
- Filter by Subject contains "password reset" or "account verification"
- Filter by URL domains not in approved list
- Group by Sender to identify campaigns

# Identify malware campaigns
- Filter by Attachment file types (e.g., .exe, .js, .vbs)
- Filter by Detection Technology = "AV engines"
- View timeline for campaign patterns
```

## Microsoft Purview

A unified data governance service that helps manage and govern on-premises, multi-cloud, and SaaS data.

### Key Components

- **Data Map**: Discover and classify data across the organization.
- **Data Catalog**: Glossary and search for data assets.
- **Information Protection**: Sensitivity labels and protection policies.
- **Data Loss Prevention (DLP)**: Prevent sharing of sensitive information.
- **Insider Risk Management**: Detect risky user activities.
- **Communication Compliance**: Monitor communications for inappropriate content.

### Sensitivity Labels

```powershell
# Create a new sensitivity label
New-Label -Name "Confidential" -DisplayName "Confidential" -Tooltip "Contains confidential information"

# Configure label to encrypt content
Set-Label -Identity "Confidential" -EncryptionEnabled $true -EncryptionProtectionType "Template" -EncryptionTemplateId "<template-id>"

# Apply label policy
New-LabelPolicy -Name "Company Confidential Policy" -Labels "Confidential" -ExchangeLocation All
```

### DLP Policy Examples

```
# Financial data protection policy
- Condition: Content contains SSN, credit card numbers, or banking information
- Action: Block sharing outside organization, notify user, send incident report

# Source code protection policy
- Condition: Content contains code signatures or file extensions (.java, .py, .cs)
- Action: Block sharing with external domains except approved partners
```

## Microsoft Intune

Cloud-based mobile device management and mobile application management service.

### Key Components

- **Device Compliance**: Set rules for device access to resources.
- **Configuration Profiles**: Manage settings across devices.
- **App Protection Policies**: Protect data within applications.
- **Conditional Access Integration**: Control resource access based on device state.
- **Remote Actions**: Manage devices remotely (wipe, lock, restart).

### Security Configuration Examples

```powershell
# Require encryption on Windows devices
$params = @{
    displayName = "Windows 10 Encryption Policy"
    description = "Requires BitLocker encryption"
    platformType = "Windows10"
    settingsDelta = @(
        @{
            "@odata.type" = "#microsoft.graph.deviceManagementBooleanSettingInstance"
            definitionId = "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerSystemDrivePolicy_encryptionMethod"
            valueJson = '"xtsAes256"'
        }
    )
}
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Body $params | ConvertTo-Json
```

### Compliance Policy Best Practices

1. **Require device encryption**: Ensure data is encrypted at rest.
2. **Set minimum OS versions**: Maintain current security patches.
3. **Require screen lock and complexity**: Prevent unauthorized physical access.
4. **Block jailbroken/rooted devices**: Reduce compromised device risk.
5. **Require Microsoft Defender**: Ensure endpoints have antimalware protection.

## Microsoft Entra ID (formerly Azure AD)

Cloud-based identity and access management service.

### Key Components

- **Multi-Factor Authentication**: Additional verification beyond passwords.
- **Conditional Access**: Context-based security controls.
- **Identity Protection**: Risk-based policies and vulnerability detection.
- **Privileged Identity Management (PIM)**: Just-in-time privileged access.
- **Identity Governance**: Lifecycle management and access reviews.

### Security Best Practices

```powershell
# Block legacy authentication
New-AzureADMSConditionalAccessPolicy -Name "Block Legacy Authentication" -State "enabled" -Conditions @{
    ClientAppTypes = @("exchangeActiveSync", "other")
} -GrantControls @{
    BuiltInControls = @("block")
}

# Require MFA for all users
New-AzureADMSConditionalAccessPolicy -Name "Require MFA for All Users" -State "enabled" -Conditions @{
    Users = @{IncludeUsers = @("all")}
    Applications = @{IncludeApplications = @("all")}
} -GrantControls @{
    BuiltInControls = @("mfa")
}
```

### Identity Protection Alert Response

1. **User Risk**: Force password change and MFA for compromised accounts.
2. **Sign-in Risk**: Block sign-ins from unfamiliar locations until verified.
3. **Leaked Credentials**: Reset passwords and review account activity.
4. **Impossible Travel**: Investigate and verify legitimate activity.
5. **Unfamiliar Sign-in Properties**: Review sign-in logs and user activity.

## Microsoft Security Score

A measurement of an organization's security posture based on security controls and behaviors.

### Key Areas

- **Identity**: MFA, privileged accounts, password policies
- **Devices**: Endpoint protection, encryption, update compliance
- **Apps**: Email protection, cloud app security
- **Infrastructure**: Azure, AWS, GCP security configurations
- **Data**: Information protection, DLP

### Improvement Action Examples

```
# Identity Improvements
- Enable MFA for all users: +25 points
- Remove inactive user accounts: +10 points
- Disable legacy authentication: +20 points

# Device Improvements
- Deploy EDR solution: +30 points
- Enable disk encryption: +15 points
- Manage vulnerable OS versions: +15 points

# Data Improvements
- Classify and label sensitive information: +20 points
- Set up DLP policies: +15 points
- Enable client-side encryption: +10 points
```

## Integration and Cross-Platform Analysis

### Microsoft Graph Security API

```powershell
# Get alerts across Microsoft security products
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/alerts" -Headers @{Authorization = "Bearer $token"}

# Update alert status
$body = @{
    status = "resolved"
    assignedTo = "analyst@example.com"
    comments = "False positive confirmed"
} | ConvertTo-Json
Invoke-RestMethod -Method PATCH -Uri "https://graph.microsoft.com/v1.0/security/alerts/{alert-id}" -Body $body -Headers @{Authorization = "Bearer $token"}
```

### Cross-Platform KQL Queries

```kusto
// Find risky users with suspicious activities across platforms
let riskyUsers = IdentityRiskEvents
| where TimeGenerated > ago(7d)
| where RiskLevel in ("high", "medium")
| distinct UserPrincipalName;
let deviceEvents = DeviceEvents
| where TimeGenerated > ago(7d)
| where AccountName in (riskyUsers)
| project TimeGenerated, AccountName, ActionType, DeviceName;
let emailEvents = EmailEvents
| where TimeGenerated > ago(7d)
| where RecipientEmailAddress in (riskyUsers)
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject;
deviceEvents
| union emailEvents
| sort by TimeGenerated
```

### Automation Examples

```powershell
# Logic App trigger on Microsoft Defender for Endpoint alert
When a Microsoft Defender for Endpoint alert is created
-> Get alert details
-> Check user risk level in Microsoft Entra ID
-> Query email activity for the user
-> If suspicious patterns found, isolate device and disable user account
-> Create incident ticket with correlation details
-> Send notification to SOC team
```

## 📎 Related Items

- [[Cheatsheets/Query_Languages/KQL_Cheatsheet|KQL Cheatsheet]]
- [[Tool_Guides/Endpoint_Analysis/Sysinternals_Guide|Sysinternals Guide]]
- [[Cheatsheets/Scripting/PowerShell_Cheatsheet|PowerShell Cheatsheet]]
- [[Cheatsheets/Systems/Windows_Event_Logs|Windows Event Logs]]

---

> [!tip] Microsoft Security Best Practices
> 1. Implement a Zero Trust approach across identity, devices, and data
> 2. Enable MFA for all users, especially for privileged accounts
> 3. Use Conditional Access to enforce context-aware security
> 4. Deploy EDR capabilities to all endpoints
> 5. Integrate security tools for unified visibility and response
> 6. Regular review of Security Score improvement actions
> 7. Implement least privilege access through PIM and JIT access 