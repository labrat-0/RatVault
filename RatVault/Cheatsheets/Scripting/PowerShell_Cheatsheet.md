---
tags: [cheatsheet, scripting, powershell, windows, security]
date: {{date}}
author: 
version: 1.0
aliases: [PowerShell Reference, Windows Scripting]
created: {{date}}
updated: {{date}}
---

# 🔷 PowerShell Scripting Cheatsheet

> [!info] About PowerShell
> PowerShell is a powerful task automation and configuration management framework from Microsoft that consists of a command-line shell and associated scripting language. This cheatsheet focuses on PowerShell commands and techniques useful for security analysts.

> [!tip] Quick Start
> ```powershell
> # Your first PowerShell script
> Write-Host "Hello, Security World!" -ForegroundColor Green
> 
> # Save as script.ps1 and run with:
> # powershell.exe -ExecutionPolicy Bypass -File script.ps1
> ```

## 📋 Table of Contents

- [Basic Syntax](#basic-syntax)
- [String Operations](#string-operations)
- [Arrays and Collections](#arrays-and-collections)
- [Functions](#functions)
- [Command Line Arguments](#command-line-arguments)
- [File Operations](#file-operations)
- [Security-Focused Examples](#security-focused-examples)
- [Debugging](#debugging)
- [Logging and Auditing](#logging-and-auditing)
- [Advanced Security Techniques](#advanced-security-techniques)
- [PowerShell Modules for Security](#powershell-modules-for-security)
- [Event Log Analysis](#event-log-analysis)
- [Remote PowerShell](#remote-powershell)
- [PowerShell + Active Directory](#powershell--active-directory)

## 📋 Basic Syntax

### Script Structure
```powershell
# PowerShell script (.ps1)
# No shebang needed in PowerShell

# Strict mode (highly recommended)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Comments start with #
# Your code here
```

### Variables
```powershell
# Declaring variables (no type declaration needed)
$name = "RatVault"
$number = 42

# Strongly typed variables (optional)
[string]$name = "RatVault"
[int]$number = 42

# Using variables
Write-Host "The name is $name"
Write-Host "The name is ${name}" # For complex cases

# Constants
Set-Variable -Name API_KEY -Value "secret" -Option Constant

# Special variables
$PSCommandPath    # Current script path
$PSScriptRoot     # Current script directory
$args[0]          # First argument
$args.Count       # Number of arguments
$LASTEXITCODE     # Exit code of last command
$?                # Success/failure of last command
$null             # Null value
$true, $false     # Boolean values
```

### Conditionals
```powershell
# If-else statement
if ($count -eq 100) {
    Write-Host "Count is 100"
} elseif ($count -gt 100) {
    Write-Host "Count is greater than 100"
} else {
    Write-Host "Count is less than 100"
}

# Comparison operators
# -eq (equal), -ne (not equal), -gt (greater than), -lt (less than)
# -ge (greater or equal), -le (less or equal)
# -like (wildcard), -notlike, -match (regex), -notmatch

# String comparison (case-insensitive by default)
if ($string -like "*substring*") {
    Write-Host "String contains substring"
}

# Case-sensitive comparison
if ($string -clike "*Substring*") {
    Write-Host "Case-sensitive match"
}

# File tests
if (Test-Path $file) { Write-Host "File exists" }
if (Test-Path $dir -PathType Container) { Write-Host "Directory exists" }
```

### Loops
```powershell
# ForEach loop
foreach ($item in $collection) {
    Write-Host "Item: $item"
}

# For loop
for ($i = 0; $i -lt 10; $i++) {
    Write-Host "Index: $i"
}

# While loop
while ($count -lt 10) {
    Write-Host "Count: $count"
    $count++
}

# Do-While loop
do {
    Write-Host "Count: $count"
    $count++
} while ($count -lt 10)

# Do-Until loop
do {
    Write-Host "Count: $count"
    $count++
} until ($count -ge 10)

# Loop through files
foreach ($file in Get-ChildItem -Path "C:\Logs" -Filter "*.log") {
    Write-Host "Processing $($file.FullName)"
}
```

## 🔍 String Operations

```powershell
# String length
$string = "Security"
Write-Host "Length: $($string.Length)"

# Substring
Write-Host "First 3 chars: $($string.Substring(0, 3))"

# String replacement
Write-Host "Replace: $($string.Replace('curity', 'cond'))"

# Split string
$parts = "a,b,c".Split(',')
Write-Host "First part: $($parts[0])"

# Join array to string
$joined = $parts -join ":"
Write-Host "Joined: $joined"

# String interpolation
$message = "The value is ${number}"

# Multiline strings (here-string)
$multiline = @"
Line 1
Line 2
Variables like $name work here
"@

# Case transformation
Write-Host "Uppercase: $($string.ToUpper())"
Write-Host "Lowercase: $($string.ToLower())"

# Check if string contains value
if ($string.Contains("cur")) {
    Write-Host "Contains 'cur'"
}

# Regex match
if ($string -match "Sec.*ty") {
    Write-Host "Regex match found: $($matches[0])"
}
```

## 🔢 Arrays and Collections

```powershell
# Declare array
$tools = @("nmap", "wireshark", "tcpdump")

# Access element
Write-Host "First tool: $($tools[0])"

# All elements
Write-Host "All tools: $tools"

# Array length
Write-Host "Number of tools: $($tools.Count)"

# Add element
$tools += "metasploit"

# Remove element
$tools = $tools | Where-Object { $_ -ne "wireshark" }

# Iterate over array
foreach ($tool in $tools) {
    Write-Host "Tool: $tool"
}

# Filter array
$filtered = $tools | Where-Object { $_ -like "*map*" }

# Sort array
$sorted = $tools | Sort-Object

# Hashtable (dictionary)
$ports = @{
    "http" = 80
    "https" = 443
    "ssh" = 22
}
Write-Host "HTTP port: $($ports['http'])"

# Add key-value pair
$ports["ftp"] = 21

# Check if key exists
if ($ports.ContainsKey("ssh")) {
    Write-Host "SSH port defined"
}

# Iterate over hashtable
foreach ($key in $ports.Keys) {
    Write-Host "$key : $($ports[$key])"
}
```

## 📝 Functions

```powershell
# Defining a function
function Greet {
    param(
        [string]$name
    )
    Write-Host "Hello, $name!"
    return "Greeting sent"
}

# Function with mandatory parameters
function Check-Status {
    param(
        [Parameter(Mandatory=$true)]
        [int]$status
    )
    
    if ($status -eq 0) {
        Write-Host "Success"
        return $true
    } else {
        Write-Host "Failed"
        return $false
    }
}

# Function with named parameters
function Process-File {
    param(
        [Parameter(Mandatory=$true)]
        [string]$path,
        
        [Parameter(Mandatory=$false)]
        [switch]$backup = $false
    )
    
    if ($backup) {
        Copy-Item -Path $path -Destination "$path.bak"
    }
    # Process file...
}

# Calling functions
Greet -name "Analyst"
$result = Check-Status -status 0
Process-File -path "C:\data.txt" -backup
```

## 🔧 Command Line Arguments

```powershell
# Simple parameter parsing
param(
    [string]$file,
    [switch]$verbose
)

if ($verbose) {
    Write-Host "Verbose mode enabled"
}

# Advanced parameter parsing with validation
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateScript({Test-Path $_})]
    [string]$logFile,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Error", "Warning", "Info")]
    [string]$logLevel = "Info",
    
    [Parameter(Mandatory=$false)]
    [switch]$archive
)
```

## 📂 File Operations

```powershell
# Read file content
$content = Get-Content -Path "input.txt"

# Read file line by line
foreach ($line in Get-Content -Path "input.txt") {
    Write-Host "Line: $line"
}

# Write to file
"Log entry: $(Get-Date)" | Out-File -FilePath "logs.txt" -Append

# Check if file exists before reading
if (Test-Path $file) {
    $content = Get-Content -Path $file
}

# Create directory if it doesn't exist
if (-not (Test-Path "C:\Logs")) {
    New-Item -Path "C:\Logs" -ItemType Directory
}

# Copy, move, rename files
Copy-Item -Path "source.txt" -Destination "dest.txt"
Move-Item -Path "old.txt" -Destination "new.txt"
Rename-Item -Path "file.txt" -NewName "file.bak"

# Delete files
Remove-Item -Path "temp.txt"
Remove-Item -Path "C:\Temp\*" -Recurse -Force
```

## 🛡️ Security-Focused Examples

### System Information
```powershell
# Get running processes
Get-Process | Select-Object Name, Id, Path | Format-Table

# Get services
Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table

# Get installed software
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor

# Get system info
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
```

### Network Analysis
```powershell
# Check network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State

# Check listening ports
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
    Select-Object LocalAddress, LocalPort, State

# Get IP configuration
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
```

### Security Audit
```powershell
# Check local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# Check local administrators
Get-LocalGroupMember -Group "Administrators" | Format-Table

# Check firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True" -and $_.Direction -eq "Inbound"} | 
    Select-Object DisplayName, Direction, Action, Profile | Format-Table

# Get event logs (failed logons)
Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 | Format-Table TimeGenerated, Message

# Create baseline of running processes (for later comparison)
Get-Process | Select-Object Name, Id, Path | Export-Csv -Path "baseline.csv"
```

## 🐞 Debugging

```powershell
# Set debug mode
$DebugPreference = "Continue"
Write-Debug "This is a debug message"

# Verbose output
$VerbosePreference = "Continue"
Write-Verbose "This is verbose output"

# Error handling
try {
    # Risky code
    $result = 1 / 0
} catch {
    Write-Host "An error occurred: $_"
} finally {
    # Cleanup code that always runs
    Write-Host "Cleanup"
}

# Specific error type handling
try {
    # Risky code
    $data = Get-Content "missing.txt"
} catch [System.IO.FileNotFoundException] {
    Write-Host "File not found"
} catch {
    Write-Host "Other error: $_"
}

# Throw custom error
if ($value -lt 0) {
    throw "Value cannot be negative"
}
```

## 🕵️ Logging and Auditing

```powershell
# Start transcript (logs everything in the console)
Start-Transcript -Path "C:\Logs\transcript.log" -Append

# Do your work...
Write-Host "This will be captured in the transcript"

# Stop transcript
Stop-Transcript

# Create custom logging function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "C:\Logs\script.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogFile -Append
}

# Use the logging function
Write-Log -Message "Script started" -Level "INFO"
Write-Log -Message "An error occurred" -Level "ERROR"
```

## 🔒 Advanced Security Techniques

### Secure String Handling
```powershell
# Create a secure string
$securePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force

# Convert secure string to encrypted string (can only be decrypted by same user on same computer)
$encryptedString = ConvertFrom-SecureString $securePassword

# Store encrypted credentials to file
$encryptedString | Out-File "C:\Secure\credentials.txt"

# Read encrypted credentials from file
$securePassword = Get-Content "C:\Secure\credentials.txt" | ConvertTo-SecureString

# Create credential object
$username = "administrator"
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

# Use credential object
Invoke-Command -ComputerName "server01" -Credential $credential -ScriptBlock { Get-Process }
```

### Certificate Operations
```powershell
# List certificates
Get-ChildItem -Path Cert:\CurrentUser\My

# Find certificate by thumbprint
$cert = Get-ChildItem -Path Cert:\CurrentUser\My\1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T

# Check certificate details
$cert | Format-List Subject, Issuer, NotBefore, NotAfter, Thumbprint

# Export certificate
Export-Certificate -Cert $cert -FilePath "C:\Certs\exported_cert.cer"

# Import certificate
Import-Certificate -FilePath "C:\Certs\cert.cer" -CertStoreLocation Cert:\CurrentUser\My

# Create self-signed certificate
New-SelfSignedCertificate -DnsName "example.com" -CertStoreLocation "Cert:\CurrentUser\My"
```

### Script Signing
```powershell
# Sign a script using a code signing certificate
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath "C:\Scripts\secure_script.ps1" -Certificate $cert

# Check script signature
Get-AuthenticodeSignature -FilePath "C:\Scripts\secure_script.ps1"

# Set execution policy to require signed scripts
Set-ExecutionPolicy -ExecutionPolicy AllSigned
```

### DPAPI Usage
```powershell
# Import the necessary assembly
Add-Type -AssemblyName System.Security

# Encrypt data using DPAPI (Data Protection API)
function Protect-Data {
    param([string]$data)
    $dataBytes = [System.Text.Encoding]::Unicode.GetBytes($data)
    $entropy = New-Object byte[] 16
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($entropy)
    $encryptedData = [System.Security.Cryptography.ProtectedData]::Protect(
        $dataBytes, 
        $entropy, 
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return @{
        EncryptedData = $encryptedData
        Entropy = $entropy
    }
}

# Decrypt data using DPAPI
function Unprotect-Data {
    param(
        [byte[]]$encryptedData,
        [byte[]]$entropy
    )
    $decryptedData = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedData, 
        $entropy, 
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [System.Text.Encoding]::Unicode.GetString($decryptedData)
}

# Example usage
$sensitive = "Secret API Key"
$protected = Protect-Data $sensitive
$decrypted = Unprotect-Data $protected.EncryptedData $protected.Entropy
```

## 📚 PowerShell Modules for Security

### PowerSploit
```powershell
# Import PowerSploit module (Pen-testing framework)
Import-Module PowerSploit

# PowerView (AD reconnaissance)
Get-NetDomain
Get-NetUser -Username "administrator"
Find-LocalAdminAccess

# PowerUp (Privilege escalation)
Invoke-AllChecks

# Others
Get-Keystrokes  # Keylogger
Get-TimedScreenshot  # Screenshots
Get-VaultCredential  # Extract credentials from Windows Vault
```

### PSReflect
```powershell
# Load PSReflect for easy access to Windows API
$Code = Get-Content "PSReflect.ps1" -Raw
Invoke-Expression $Code

# Define Windows API functions
$FunctionDefinitions = @(
    (New-Function kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (New-Function kernel32 ReadProcessMemory ([Bool]) @([IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError)
)

$Types = New-Type @{}

$Kernel32 = Add-Module kernel32 $FunctionDefinitions $Types

# Use the functions
$ProcessHandle = $Kernel32::OpenProcess(0x10, $false, 1234)
```

### DSInternals
```powershell
# Install DSInternals module (AD security)
Install-Module -Name DSInternals

# Import module
Import-Module DSInternals

# Get AD database passwords
Get-ADDBAccount -SamAccountName Administrator -DBPath 'C:\Windows\NTDS\ntds.dit'

# Convert NTLM hash
ConvertTo-NTHash -Password 'Password123'

# Test password quality
Test-PasswordQuality -WeakPasswordHashes (Get-Content 'hashes.txt') -WeakPasswordsFile 'dictionary.txt'
```

### PSAT (PowerShell Security Assessment Tool)
```powershell
# Import PSAT module
Import-Module PSAT

# Run security assessment
Invoke-PSAudit

# Check for weak PowerShell configurations
Get-PSConfiguration

# Get auditing settings
Get-PSAuditSettings

# Create security report
New-PSAuditReport -OutputPath "C:\Reports\security_report.html"
```

## 📊 Event Log Analysis

### Common Event Queries
```powershell
# Get failed logins (4625)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
} -MaxEvents 100 | Format-Table TimeCreated, @{
    Name = 'Username'
    Expression = {$_.Properties[5].Value}
}, @{
    Name = 'Source'
    Expression = {$_.Properties[19].Value}
}

# Get successful logins (4624)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
} -MaxEvents 100 | Format-Table TimeCreated, @{
    Name = 'Username'
    Expression = {$_.Properties[5].Value}
}, @{
    Name = 'LogonType'
    Expression = {$_.Properties[8].Value}
}

# Get account lockouts (4740)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4740
} | Format-Table TimeCreated, @{
    Name = 'LockedAccount'
    Expression = {$_.Properties[0].Value}
}

# Get PowerShell script block logging (4104)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} -MaxEvents 10 | Format-List
```

### Custom Log Parsers
```powershell
# Parse Windows firewall logs
function Parse-FirewallLog {
    param(
        [string]$LogPath = "C:\Windows\system32\LogFiles\Firewall\pfirewall.log"
    )
    
    $log = Get-Content -Path $LogPath | Where-Object { $_ -notmatch '^#' }
    $entries = @()
    
    foreach ($line in $log) {
        $fields = $line -split ' '
        if ($fields.Count -ge 7) {
            $entry = [PSCustomObject]@{
                Date = $fields[0]
                Time = $fields[1]
                Action = $fields[2]
                Protocol = $fields[3]
                SourceIP = $fields[4]
                DestinationIP = $fields[5]
                SourcePort = $fields[6]
                DestinationPort = $fields[7]
            }
            $entries += $entry
        }
    }
    
    return $entries
}

# Use the parser
$firewallEntries = Parse-FirewallLog
$firewallEntries | Where-Object { $_.Action -eq 'DROP' } | Format-Table
```

### Timeline Creation
```powershell
function Create-EventTimeline {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [string[]]$EventIds = @('4624', '4625', '4634', '4647', '4688')
    )
    
    $events = @()
    
    foreach ($computer in $ComputerName) {
        $events += Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $EventIds
            StartTime = $StartTime
            EndTime = $EndTime
        } -ComputerName $computer -ErrorAction SilentlyContinue
    }
    
    $timeline = $events | ForEach-Object {
        $eventId = $_.Id
        $desc = switch ($eventId) {
            4624 { "Logon" }
            4625 { "Failed Logon" }
            4634 { "Logoff" }
            4647 { "User Initiated Logoff" }
            4688 { "Process Started" }
            default { "Other Event" }
        }
        
        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventID = $eventId
            Description = $desc
            Computer = $_.MachineName
            Username = if ($eventId -in @('4624', '4625', '4634', '4647')) { $_.Properties[5].Value } else { "N/A" }
            Details = if ($eventId -eq '4688') { "Process: $($_.Properties[5].Value)" } else { "N/A" }
        }
    }
    
    return $timeline | Sort-Object Time
}

# Create a timeline for today
$today = Get-Date
$startOfDay = $today.Date
$timeline = Create-EventTimeline -StartTime $startOfDay -EndTime $today
$timeline | Format-Table -AutoSize
```

## 🔄 Remote PowerShell

### PowerShell Remoting
```powershell
# Enable PowerShell remoting (run as admin)
Enable-PSRemoting -Force

# Test connection
Test-WSMan -ComputerName server01

# Execute command on remote computer
Invoke-Command -ComputerName server01 -ScriptBlock { Get-Process }

# Execute command on multiple computers
Invoke-Command -ComputerName server01, server02, server03 -ScriptBlock {
    Get-Service | Where-Object { $_.Status -eq 'Running' }
}

# Execute script on remote computer
Invoke-Command -ComputerName server01 -FilePath C:\Scripts\Get-SystemInfo.ps1

# Create persistent session
$session = New-PSSession -ComputerName server01

# Use the session
Invoke-Command -Session $session -ScriptBlock { Get-EventLog -LogName Security -Newest 10 }

# Copy file to remote computer
Copy-Item -Path C:\Scripts\script.ps1 -Destination C:\Scripts\ -ToSession $session

# Copy file from remote computer
Copy-Item -Path C:\Logs\app.log -Destination C:\Logs\ -FromSession $session

# Enter interactive session
Enter-PSSession -ComputerName server01

# Remove session
Remove-PSSession $session
```

### Just Enough Administration (JEA)
```powershell
# Create a JEA session configuration file
New-PSSessionConfigurationFile -Path "C:\JEA\SecurityAudit.pssc" -SessionType RestrictedRemoteServer -LanguageMode NoLanguage

# Register the JEA endpoint
Register-PSSessionConfiguration -Path "C:\JEA\SecurityAudit.pssc" -Name "SecurityAudit" -Force

# Connect to a JEA endpoint
Enter-PSSession -ComputerName server01 -ConfigurationName "SecurityAudit"

# Create a role capability file
New-PSRoleCapabilityFile -Path "C:\JEA\SecurityAuditor.psrc"

# Edit the role capability file to allow specific cmdlets
# SecurityAuditor.psrc content example:
# VisibleCmdlets = 'Get-Process', 'Get-Service', 'Get-EventLog'
# VisibleFunctions = 'Get-SystemInfo'
```

## 🔍 PowerShell + Active Directory

### User Management
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Get all users
Get-ADUser -Filter * -Properties * | 
    Select-Object SamAccountName, GivenName, Surname, Enabled, LastLogonDate

# Get disabled users
Get-ADUser -Filter {Enabled -eq $false} -Properties LastLogonDate | 
    Select-Object SamAccountName, LastLogonDate

# Get users with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true} | 
    Select-Object SamAccountName

# Get user's group membership
Get-ADPrincipalGroupMembership -Identity "username" | 
    Select-Object Name

# Create new user
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" `
    -SamAccountName "jdoe" -UserPrincipalName "jdoe@domain.com" `
    -Path "OU=Users,DC=domain,DC=com" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) `
    -Enabled $true

# Disable user
Disable-ADAccount -Identity "username"

# Reset password
Set-ADAccountPassword -Identity "username" -Reset `
    -NewPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)
```

### Group Management
```powershell
# Get all groups
Get-ADGroup -Filter * | Select-Object Name, GroupCategory

# Get group members
Get-ADGroupMember -Identity "Domain Admins" | 
    Select-Object Name, SamAccountName

# Create new group
New-ADGroup -Name "Security Team" -GroupScope Global -Path "OU=Groups,DC=domain,DC=com"

# Add user to group
Add-ADGroupMember -Identity "Security Team" -Members "username"

# Remove user from group
Remove-ADGroupMember -Identity "Security Team" -Members "username" -Confirm:$false
```

### Security Checks
```powershell
# Find users with non-expiring passwords
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | 
    Select-Object SamAccountName, Name

# Find inactive users (not logged in for 90 days)
$90DaysAgo = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $90DaysAgo -and Enabled -eq $true} -Properties LastLogonDate | 
    Select-Object SamAccountName, LastLogonDate

# Find users with old passwords
$90DaysAgo = (Get-Date).AddDays(-90)
Get-ADUser -Filter {PasswordLastSet -lt $90DaysAgo -and Enabled -eq $true} -Properties PasswordLastSet | 
    Select-Object SamAccountName, PasswordLastSet

# Find Domain Admins
Get-ADGroupMember "Domain Admins" -Recursive | 
    Get-ADUser -Properties * | 
    Select-Object SamAccountName, Enabled, LastLogonDate

# Find empty groups
Get-ADGroup -Filter * | Where-Object {-not (Get-ADGroupMember $_)} | 
    Select-Object Name
```

## 🔗 Related Resources

- [[Cheatsheets/Scripting/Bash_Cheatsheet|Bash Cheatsheet]]
- [[Tool_Guides/Windows_Commands|Windows Commands Guide]]
- [[Cheatsheets/Systems/Windows_Hardening|Windows Hardening]]
- [[Cheatsheets/Query_Languages/KQL_Cheatsheet|KQL Cheatsheet]]
- [[Tool_Guides/Endpoint_Analysis/Sysinternals_Guide|Sysinternals Guide]]

---

> [!warning] Security Note
> - Always use script signing for production scripts
> - Set execution policy appropriately (`Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`)
> - Avoid using `Invoke-Expression` with user input
> - Be cautious with `Start-Process` and command execution
> - Store credentials securely using `SecureString` or Windows Credential Manager
> - Use `-NoProfile` when running scripts to prevent environment contamination 