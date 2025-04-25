---
tags: [cheatsheet, query-language, kql, azure, sentinel, m365, defender]
aliases: [Kusto Query Language Reference, Azure Sentinel Queries]
created: {{date}}
updated: {{date}}
---

# 📊 KQL (Kusto Query Language) Cheatsheet

> [!info] About KQL
> Kusto Query Language (KQL) is a powerful query language used for log analytics in Azure services including Azure Sentinel, Azure Monitor, and Microsoft Defender for Endpoint. This cheatsheet covers common syntax and examples for security analysis.

## 📋 Table of Contents

- [Basic Syntax](#basic-syntax)
- [Time Operators](#time-operators)
- [String Operations](#string-operations)
- [Filtering and Where Clauses](#filtering-and-where-clauses)
- [Aggregations and Summarization](#aggregations-and-summarization)
- [Joins](#joins)
- [Functions and Let Statements](#functions-and-let-statements)
- [JSON and Dynamic Data](#json-and-dynamic-data)
- [Common Security Queries](#common-security-queries)
- [Azure Sentinel Queries](#azure-sentinel-queries)
- [Microsoft Defender Queries](#microsoft-defender-queries)
- [Performance Optimization](#performance-optimization)

## Basic Syntax

```kusto
// Basic table query
TableName

// Selecting specific columns
TableName
| project TimeGenerated, Computer, EventID

// Limiting results
TableName
| take 100

// Ordering results
TableName
| order by TimeGenerated desc
| take 100

// Distinct values
TableName
| distinct Computer

// Count results
TableName
| count

// Counting distinct values
TableName
| summarize dcount(Computer)
```

## Time Operators

```kusto
// Filter by time range (last 24 hours)
TableName
| where TimeGenerated > ago(24h)

// Filter by time range (specific dates)
TableName
| where TimeGenerated between (datetime(2023-01-01) .. datetime(2023-01-31))

// Time bucketing (hourly)
TableName
| where TimeGenerated > ago(24h)
| summarize count() by bin(TimeGenerated, 1h)

// Time bucketing (daily)
TableName
| where TimeGenerated > ago(7d)
| summarize count() by bin(TimeGenerated, 1d)

// Time bucketing with other fields
TableName
| where TimeGenerated > ago(7d)
| summarize count() by bin(TimeGenerated, 1d), Computer
```

## String Operations

```kusto
// String contains
TableName
| where EventData contains "error"

// Case-insensitive search
TableName
| where EventData contains_cs "Error"

// String matching with regular expressions
TableName
| where EventData matches regex "fail\\w+"

// String extraction with regular expressions
TableName
| extend ExtractedValue = extract("id=([\\w-]+)", 1, EventData)

// String replacement
TableName
| extend CleanString = replace_string(Message, "CONFIDENTIAL", "[REDACTED]")

// String parsing (split)
TableName
| extend Parts = split(Message, ",")
| extend FirstPart = tostring(Parts[0])

// Formatting strings
TableName
| extend FormattedMessage = strcat("Computer: ", Computer, " Event: ", tostring(EventID))
```

## Filtering and Where Clauses

```kusto
// Basic filtering
TableName
| where EventID == 4625

// Multiple conditions (AND)
TableName
| where EventID == 4625 and Computer startswith "SRV"

// Multiple conditions (OR)
TableName
| where EventID == 4625 or EventID == 4624

// Multiple values (IN)
TableName
| where EventID in (4624, 4625, 4634)

// Negative conditions (NOT)
TableName
| where EventID != 4624
| where Computer !startswith "TEST-"
| where !(EventID in (4624, 4625))

// Complex filtering
TableName
| where (EventID == 4625 and AccountType == "User")
    or (EventID == 4740 and AccountType == "Machine")

// Working with nulls and empty values
TableName
| where isnotempty(IPAddress)
| where isempty(SourcePort)
```

## Aggregations and Summarization

```kusto
// Simple count by dimension
TableName
| summarize count() by Computer

// Multiple aggregations
TableName
| summarize 
    count(),
    dcount(IpAddress),
    min(TimeGenerated),
    max(TimeGenerated)
    by Computer

// Multiple dimensions
TableName
| summarize count() by Computer, EventID

// Aggregate with time buckets
TableName
| where TimeGenerated > ago(7d)
| summarize count() by bin(TimeGenerated, 1d), Computer

// Running calculations
TableName
| summarize SuccessCount = countif(ResultCode == "Success"),
            FailureCount = countif(ResultCode == "Failure")
            by Computer

// Percentiles
TableName
| summarize
    count(),
    p50 = percentile(ResponseTime, 50),
    p95 = percentile(ResponseTime, 95),
    p99 = percentile(ResponseTime, 99)
    by Computer

// Top N by measure
TableName
| summarize count() by IPAddress
| top 10 by count_
```

## Joins

```kusto
// Inner join
TableName1
| join (TableName2) on Computer

// Left outer join
TableName1
| join kind=leftouter (TableName2) on Computer

// Right outer join
TableName1
| join kind=rightouter (TableName2) on Computer

// Full outer join
TableName1
| join kind=fullouter (TableName2) on Computer

// Anti join (not in)
TableName1
| join kind=anti (TableName2) on Computer

// Join with multiple columns
TableName1
| join (TableName2) on Computer, IPAddress

// Join with time window
TableName1
| join kind=inner (
    TableName2
) on $left.Computer == $right.Computer, $left.TimeGenerated == $right.TimeGenerated
| where $left.TimeGenerated between ($right.TimeGenerated-5m .. $right.TimeGenerated+5m)

// Join uneven columns
TableName1
| join kind=inner (
    TableName2
) on $left.Computer == $right.DeviceName
```

## Functions and Let Statements

```kusto
// Basic let statement (variable)
let timeFrame = 24h;
TableName
| where TimeGenerated > ago(timeFrame)

// Let statement with tabular data
let SuspiciousIPs = datatable(IP:string)
[
    "10.10.10.10",
    "192.168.1.100",
    "172.16.5.5"
];
TableName
| where SourceIP in (SuspiciousIPs)

// Function with parameters
let GetEvents = (eventId:int, timeAgo:timespan) 
{
    TableName
    | where EventID == eventId and TimeGenerated > ago(timeAgo)
};
GetEvents(4625, 12h)

// Function returning tabular data
let TopComputers = (n:int) 
{
    TableName
    | summarize count() by Computer
    | top n by count_
};
TopComputers(10)
| join (TableName) on Computer
```

## JSON and Dynamic Data

```kusto
// Parse JSON 
TableName
| extend parsedData = parse_json(RawData)

// Access JSON properties
TableName
| extend parsedData = parse_json(RawData)
| extend userId = parsedData.user.id
| extend userName = parsedData.user.name

// Array access
TableName
| extend parsedData = parse_json(RawData)
| extend firstItem = parsedData.items[0]

// Expand array items
TableName
| extend parsedData = parse_json(RawData)
| mv-expand item = parsedData.items

// Parse JSON array directly
TableName
| mv-expand parsedData = parse_json(RawData)

// Check if property exists
TableName
| extend parsedData = parse_json(RawData)
| where parsedData.errorCode != ""

// Get array length
TableName
| extend parsedData = parse_json(RawData)
| extend arrayLength = array_length(parsedData.items)
```

## Common Security Queries

### Failed Authentication Detection

```kusto
// Find failed logons
SecurityEvent
| where EventID == 4625
| summarize count() by TargetAccount, TargetUserName, IpAddress, Computer
| sort by count_ desc 

// Detect potential brute force (multiple failed logins followed by success)
let failedLogons = SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account = tolower(Account), Computer, IpAddress, LogonType;
let successfulLogons = SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account = tolower(Account), Computer, IpAddress, LogonType;
failedLogons
| where TimeGenerated > ago(1h)
| summarize FailedCount = count() by Account, Computer, bin(TimeGenerated, 10m)
| where FailedCount > 5
| join kind=inner (
    successfulLogons
    | where TimeGenerated > ago(1h)
) on Account, Computer
| where TimeGenerated > bin_at(TimeGenerated1, 10m, now())
```

### Unusual Process Creation

```kusto
// Unusual processes running from temp directories
DeviceProcessEvents
| where InitiatingProcessFolderPath contains @"temp"
    or FolderPath contains @"temp"
| where not(InitiatingProcessFolderPath contains @"Teams")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, 
          FileName, ProcessCommandLine, InitiatingProcessCommandLine
          
// Suspicious process ancestry
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| where FileName in~ ("netsh.exe", "bitsadmin.exe", "certutil.exe", "mshta.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, 
          FileName, ProcessCommandLine
```

### Network Anomalies

```kusto
// Detect outbound connections to unusual ports
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 53, 22, 123)
| summarize count() by DeviceName, RemoteIP, RemotePort
| order by count_ desc

// New external IPs contacted
let knownIPs = DeviceNetworkEvents
| where TimeGenerated between(ago(30d)..ago(1d))
| where RemoteIPType == "Public"
| distinct RemoteIP;
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemoteIPType == "Public"
| where RemoteIP !in (knownIPs)
| summarize FirstSeen = min(TimeGenerated), 
            DeviceNames = make_set(DeviceName, 100),
            ProcessNames = make_set(InitiatingProcessFileName, 100)
            by RemoteIP, RemotePort
```

### Registry Modifications

```kusto
// Detect modifications to Run keys
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"Microsoft\Windows\CurrentVersion\Run"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, 
          RegistryKey, RegistryValueName, RegistryValueData

// Detect modifications to service configurations
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
| where RegistryValueName in~ ("ImagePath", "FailureCommand", "ServiceDll")
| project TimeGenerated, DeviceName, RegistryKey, 
          RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

## Azure Sentinel Queries

### Identity-based Threats

```kusto
// Multiple authentications from impossible travel
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
| order by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend prev_time = prev(TimeGenerated), prev_ip = prev(IPAddress), prev_location = prev(Location)
| extend prev_user = prev(UserPrincipalName)
| where UserPrincipalName == prev_user
| extend timediff = TimeGenerated - prev_time
| where timediff between (0min .. 2h)
| extend distance = geo_distance_2points(
    todouble(parse_json(Location).geoCoordinates.longitude), 
    todouble(parse_json(Location).geoCoordinates.latitude), 
    todouble(parse_json(prev_location).geoCoordinates.longitude), 
    todouble(parse_json(prev_location).geoCoordinates.latitude)
)
| where distance > 500
| project TimeGenerated, UserPrincipalName, IPAddress, prev_ip, Location, prev_location, 
          timediff, distance, AppDisplayName

// New admin accounts
AuditLogs
| where OperationName has_any ("Add member to role", "Add user", "Add group member")
| where Result == "success"
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Group = tostring(TargetResources[0].displayName)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Group has_any ("Admin", "Administrators", "Global Administrator")
| project TimeGenerated, Actor, Target, Group, OperationName
```

### Resource-based Threats

```kusto
// Azure Key Vault access failures 
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "VaultGet" or OperationName == "KeyGet" or OperationName == "SecretGet"
| where ResultSignature == "Unauthorized"
| summarize count() by CallerIPAddress, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g
| order by count_ desc

// Network Security Group changes
AzureActivity
| where OperationNameValue contains "NETWORKSECURITYGROUPS" 
    and OperationNameValue contains "WRITE"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, Resource
```

## Microsoft Defender Queries

### Advanced Hunting Queries

```kusto
// Suspicious PowerShell commands
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any (
    "FromBase64String", 
    "Invoke-Expression", 
    "IEX", 
    "Invoke-WebRequest", 
    "Invoke-Mimikatz", 
    "Net.WebClient", 
    "Start-Process"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

// Living off the land binaries (LOLBins)
DeviceProcessEvents
| where FileName in~ (
    "regsvr32.exe", 
    "certutil.exe", 
    "bitsadmin.exe", 
    "mshta.exe", 
    "wmic.exe", 
    "msbuild.exe", 
    "installutil.exe"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| summarize ProcessCount = count(), 
            ProcessCommands = make_set(ProcessCommandLine, 5) 
            by DeviceName, FileName

// USB drive activity
DeviceEvents
| where ActionType == "UsbDriveMount"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| extend DriveLetter = tostring(parse_json(AdditionalFields).DriveLetter)
| extend SerialNumber = tostring(parse_json(AdditionalFields).SerialNumber)
| project Timestamp, DeviceName, AccountName, DriveLetter, SerialNumber
```

### Endpoint Detection

```kusto
// Fileless malware signs
DeviceProcessEvents
| where InitiatingProcessCommandLine has "rundll32"
    and InitiatingProcessCommandLine has "javascript"
| project Timestamp, DeviceName, InitiatingProcessCommandLine

// Suspicious script execution
DeviceEvents
| where ActionType == "ScriptExecuted"
| extend ParsedFields = parse_json(AdditionalFields)
| where tostring(ParsedFields.ScriptType) in~ ("PowerShell", "VBScript", "JavaScript")
| project Timestamp, DeviceName, AccountName, 
          ScriptType = tostring(ParsedFields.ScriptType),
          FileName = tostring(ParsedFields.FileName),
          SHA256 = tostring(ParsedFields.SHA256)
```

## Performance Optimization

```kusto
// Use time restrictions first
TableName
| where TimeGenerated > ago(1h)  // Time filter first
| where Computer == "Server01"   // Then other filters

// Limit fields early
TableName
| where TimeGenerated > ago(1h)
| project TimeGenerated, Computer, IPAddress, EventID  // Only needed fields
| where EventID == 4625

// Pre-aggregate large datasets
TableName
| where TimeGenerated > ago(1d)
| summarize count() by Computer, bin(TimeGenerated, 1h)
| where count_ > 100

// Use let for repeated operations
let TimeFilter = ago(1d);
let CommonEvents = 
    TableName
    | where TimeGenerated > TimeFilter
    | where EventID in (4624, 4625);
CommonEvents
| where Computer startswith "SRV"
| summarize count() by Computer;
CommonEvents
| where SourceIP != "127.0.0.1"
| summarize count() by SourceIP
```

## 🔗 Related Resources

- [[Cheatsheets/Systems/Windows_Event_Logs|Windows Event Logs Reference]]
- [[Cheatsheets/Query_Languages/YARA_Rules_Guide|YARA Rules Guide]]
- [[Tool_Guides/Endpoint_Analysis/Microsoft_Defender_Guide|Microsoft Defender Guide]]
- [[Cheatsheets/Scripting/PowerShell_Cheatsheet|PowerShell Cheatsheet]]

---

> [!tip] KQL Best Practices
> 1. Always filter by time first to improve performance
> 2. Use functions and let statements for complex code reuse
> 3. Pre-aggregate data when possible for improved performance
> 4. Use appropriate join types to avoid unintended data loss
> 5. Test complex queries on smaller time ranges before expanding 