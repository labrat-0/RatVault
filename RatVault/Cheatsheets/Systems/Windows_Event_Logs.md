---
tags: [cheatsheet, windows, event-logs, security, forensics]
date: {{date}}
author: 
version: 1.0
---

# 🪟 Windows Event Logs for Security Analysis

> [!info] About Windows Event Logs
> Windows Event Logs are a crucial source of forensic evidence and security telemetry. This cheatsheet covers important event IDs, log locations, analysis techniques, and tools for security analysts.

## 📋 Table of Contents

- [Log Locations](#log-locations)
- [Event Viewer Usage](#event-viewer-usage)
- [Critical Security Event IDs](#critical-security-event-ids)
- [Authentication Events](#authentication-events)
- [Account Management](#account-management)
- [Privilege Use](#privilege-use)
- [Process Execution](#process-execution)
- [Object Access](#object-access)
- [PowerShell Events](#powershell-events)
- [Command Line Logging](#command-line-logging)
- [Advanced Log Analysis](#advanced-log-analysis)
- [PowerShell For Log Analysis](#powershell-for-log-analysis)
- [Common Attack Patterns](#common-attack-patterns)

## Log Locations

Windows event logs are stored in the following locations:

```
# Main event log files (.evtx)
%SystemRoot%\System32\Winevt\Logs\

# Security log
%SystemRoot%\System32\Winevt\Logs\Security.evtx

# System log
%SystemRoot%\System32\Winevt\Logs\System.evtx

# Application log
%SystemRoot%\System32\Winevt\Logs\Application.evtx

# PowerShell operational log
%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx

# Sysmon log (if installed)
%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```

## Event Viewer Usage

Event Viewer (`eventvwr.msc`) is the built-in GUI tool for viewing Windows event logs:

| Action | Steps |
|--------|-------|
| Open specific log | Event Viewer → Windows Logs → Security/System/Application |
| Filter by Event ID | Right-click log → Filter Current Log → Event ID: 4624,4625 |
| Filter by time | Right-click log → Filter Current Log → Time range |
| Create custom view | Right-click Custom Views → Create Custom View |
| Export logs | Right-click log → Save Filtered Log File As... |
| Clear log | Right-click log → Clear Log |

> [!warning] Clearing logs requires administrator privileges and may destroy evidence. In forensic investigations, always preserve original logs.

## Critical Security Event IDs

| Event ID | Description | Log | Potential Threat Indicators |
|----------|-------------|-----|----------------------------|
| 4624 | Successful logon | Security | Unusual accounts, workstations, or times |
| 4625 | Failed logon | Security | Brute force attempts |
| 4720 | Account created | Security | Unauthorized account creation |
| 4732 | User added to security-enabled group | Security | Privilege escalation |
| 4688 | Process creation | Security | Suspicious process execution |
| 4698/4699 | Scheduled task created/deleted | Security | Persistence mechanism |
| 4657 | Registry value modified | Security | Configuration changes |
| 4670 | Permissions on object changed | Security | Permission modification |
| 4672 | Special privileges assigned | Security | Privilege escalation |
| 4648 | Explicit logon (RunAs) | Security | Lateral movement |
| 4776 | Credential validation | Security | Pass-the-Hash attacks |
| 7045 | Service installed | System | Malicious service installation |
| 104 | Log cleared | System | Evidence destruction |
| 1102 | Audit log cleared | Security | Evidence destruction |
| 4697 | Service installation | Security | Persistence via service |
| 400/800 | PowerShell execution | PowerShell | Malicious script execution |

## Authentication Events

### Logon Types (Event ID 4624, 4625)

| Logon Type | Description | Security Relevance |
|------------|-------------|-------------------|
| 2 | Interactive (local) | Console logon |
| 3 | Network | Remote logon (file shares, named pipes) |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Credentials sent in cleartext |
| 9 | NewCredentials | RunAs or similar |
| 10 | RemoteInteractive | RDP session |
| 11 | CachedInteractive | Cached domain credentials used |

### Logon Failure Reasons (Event ID 4625)

| Status/Sub Status | Description | Potential Attack |
|-------------------|-------------|-----------------|
| 0xC000006A | Invalid username or password | Brute force |
| 0xC000006D | Logon failure | Brute force |
| 0xC000006F | Outside authorized hours | Time restriction bypass |
| 0xC0000070 | Workstation restriction | Unauthorized access point |
| 0xC0000071 | Expired password | Account takeover |
| 0xC0000072 | Disabled account | Attempt to use disabled account |
| 0xC0000193 | Account expiration | Attempt to use expired account |
| 0xC0000234 | Account locked | Brute force aftermath |
| 0xC0000413 | Authentication firewall | Security policy violation |

## Account Management

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4720 | User account created | New backdoor account |
| 4722 | User account enabled | Dormant account activation |
| 4723 | User password change | Unauthorized credential change |
| 4724 | Password reset attempt | Account takeover |
| 4725 | User account disabled | Potential DoS |
| 4726 | User account deleted | Covering tracks |
| 4728/4732/4756 | User added to security group | Privilege escalation |
| 4729/4733/4757 | User removed from security group | Account modification |
| 4738 | User account changed | Reconnaissance and modification |
| 4781 | Account name changed | Evasion technique |

## Privilege Use

| Event ID | Description | Potential Threat |
|----------|-------------|------------------|
| 4672 | Special privileges assigned to new logon | Elevated access |
| 4673 | Privileged service called | Access to sensitive operations |
| 4674 | Privileged object operation | Sensitive object access |
| 4648 | Explicit credentials used (RunAs) | Account pivoting |

## Process Execution

| Event ID | Description | Notes |
|----------|-------------|-------|
| 4688 | Process creation | Requires audit policy configuration |
| 4689 | Process termination | Not enabled by default |
| 592/593 | Legacy process tracking | Older Windows versions |

### Important Fields in Process Creation (4688)

- **NewProcessName**: Path to the executable
- **CommandLine**: Full command line (requires additional auditing)
- **ParentProcessId**: PID of the parent process
- **SubjectUserName**: User context
- **TokenElevationType**: Elevation status (UAC)

## Object Access

| Event ID | Description | Security Relevance |
|----------|-------------|-------------------|
| 4656 | Object access requested | File, registry, or other object access attempts |
| 4658 | Handle to object closed | End of object access |
| 4660 | Object deleted | Evidence removal |
| 4663 | Object access attempt | Monitor sensitive files/registry |
| 4657 | Registry value modified | Configuration changes |
| 5140 | Network share accessed | Lateral movement and data access |
| 5145 | Network share object checked | Reconnaissance |

## PowerShell Events

| Event ID | Log | Description | Threat Detection |
|----------|-----|-------------|-----------------|
| 400 | PowerShell | Engine lifecycle | Script execution start |
| 403 | PowerShell | Engine stopped | Script execution end |
| 4103 | PowerShell | Module logging | Command execution |
| 4104 | PowerShell | Script block logging | Script content (fileless malware) |
| 4105/4106 | PowerShell | Script start/stop | Script boundaries |
| 600 | PowerShell | Provider lifecycle | PowerShell provider usage |

### Important PowerShell Logs

- **Microsoft-Windows-PowerShell/Operational**: Basic execution tracking
- **Microsoft-Windows-PowerShell/Admin**: High-level PowerShell events
- **Microsoft-Windows-PowerShell/Analytic**: Detailed tracing (when enabled)
- **Microsoft-Windows-PowerShell/Transcription**: Detailed command recordings (when enabled)

## Command Line Logging

To enable command line logging in process creation events (4688):

1. **Group Policy**: Computer Configuration → Administrative Templates → System → Audit Process Creation → "Include command line in process creation events" → Enable
2. **Registry**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` = 1

## Advanced Log Analysis

### Sysmon Event IDs

| Event ID | Description | Threat Detection Value |
|----------|-------------|------------------------|
| 1 | Process creation | Malicious process execution |
| 2 | File creation time changed | Timestamp tampering |
| 3 | Network connection | C2, lateral movement, exfiltration |
| 4 | Sysmon service state change | Service tampering |
| 5 | Process terminated | Execution lifecycle |
| 6 | Driver loaded | Rootkit, kernel manipulation |
| 7 | Image loaded | DLL hijacking, malicious modules |
| 8 | Remote thread created | Process injection |
| 9 | Raw disk access | Rootkit, direct disk manipulation |
| 10 | Process access | Process injection, credential theft |
| 11 | File created | Malicious file creation, staging |
| 12/13/14 | Registry operation | Persistence, configuration changes |
| 15 | File stream created | ADS usage for hiding data |
| 16 | Sysmon configuration change | Evasion |
| 17/18 | Pipe created/connected | Process communication |
| 19/20/21 | WMI events | Fileless persistence |
| 22 | DNS query | C2, data exfiltration |
| 23 | File deletion | Anti-forensics |
| 24 | Clipboard change | Data theft |
| 25 | Process tampering | Process hollowing, protection bypasses |
| 26 | File delete archived | Anti-forensics detection |

## PowerShell For Log Analysis

### Query Security Logons
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)]]" -MaxEvents 10 | 
    Format-Table TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}
```

### Find Failed Logon Attempts
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
    Select-Object TimeCreated, @{Name='Username';Expression={$_.Properties[5].Value}}, 
                  @{Name='Source';Expression={$_.Properties[19].Value}}
```

### Detect Account Lockouts
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} | 
    Select-Object TimeCreated, @{Name='Username';Expression={$_.Properties[0].Value}}
```

### Check for Privilege Escalation
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} | 
    Select-Object TimeCreated, @{Name='Username';Expression={$_.Properties[1].Value}}
```

### Search for Process Creation
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
    Select-Object TimeCreated, @{Name='Process';Expression={$_.Properties[5].Value}},
                  @{Name='User';Expression={$_.Properties[1].Value}}
```

### Convert EVTX to CSV
```powershell
Get-WinEvent -Path C:\Path\to\log.evtx | Export-Csv -Path output.csv -NoTypeInformation
```

### Combine Multiple Event IDs
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634} -MaxEvents 100
```

## Common Attack Patterns

### Pass-the-Hash Detection
Look for:
- Event ID 4624 (Logon) with Logon Type 3 or 9
- Where Authentication Package is NTLM rather than Kerberos
- Multiple logons from admin accounts across systems

### Brute Force Attacks
Look for:
- Multiple Event ID 4625 (Failed Logon) for same username
- Failed logons from same source IP/computer
- Pattern of attempts across multiple accounts

### Lateral Movement
Look for:
- Event ID 4624 (Logon) with Logon Type 3 (Network) or 10 (RDP)
- Event ID 4688 with process names like psexec.exe, wmic.exe, sc.exe, schtasks.exe
- Event ID 5140 (Network Share Access) to admin shares (C$, ADMIN$)

### Privilege Escalation
Look for:
- Event ID 4672 (Special privileges assigned)
- Event ID 4732 (User added to privileged group)
- Event ID 4688 with UAC bypass techniques (eventvwr.exe then abnormal child)
- PowerShell events with suspicious scripts

### Persistence Mechanisms
Look for:
- Event ID 4698 (Scheduled Task creation)
- Event ID 4697 (Service installation)
- Event ID 4657 (Registry modifications) to Run keys, Services, WMI subscriptions

### Credential Theft
Look for:
- Event ID 4688 with process names like mimikatz.exe, procdump.exe
- Event ID 4663 (Object access) to LSASS process
- Events showing access to SAM, SECURITY registry hives

### Log Tampering
Look for:
- Event ID 1102 (Security log cleared)
- Event ID 104 (Log cleared)
- Missing time periods in logs
- Disabled audit policies (Event ID 4719)

## 📎 Related Items

- [[Cheatsheets/Scripting/PowerShell_Cheatsheet]]
- [[Tool_Guides/Endpoint_Analysis/Sysmon_Configuration]]
- [[Templates/Incident_Response/IR_Report_Template]]

---

> [!tip] Event Log Analysis Best Practices
> 1. Establish baseline behavior before hunting for anomalies
> 2. Correlate events across multiple logs for complete attack chain visibility
> 3. Focus on account, time, and system patterns across events
> 4. Configure proper audit policies to ensure you capture relevant events
> 5. Consider centralized logging with SIEM for larger environments 