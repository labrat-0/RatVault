---
tags: [tool-guide, windows, sysinternals, forensics, endpoint-analysis]
date: {{date}}
author: 
version: 1.0
---

# 🛠️ Sysinternals Tools for Security Analysis

> [!info] About Sysinternals
> Sysinternals is a suite of advanced system utilities and technical information created by Mark Russinovich and Bryce Cogswell. Now owned by Microsoft, these tools provide essential capabilities for system troubleshooting and security analysis.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Process Analysis Tools](#process-analysis-tools)
- [System Information Tools](#system-information-tools)
- [Disk and File System Tools](#disk-and-file-system-tools)
- [Network Tools](#network-tools)
- [Security Tools](#security-tools)
- [Automation and Response](#automation-and-response)
- [Live Forensics](#live-forensics)
- [Common Analysis Scenarios](#common-analysis-scenarios)

## Getting Started

### Installation and Access

```powershell
# Download full suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\Tools\SysinternalsSuite.zip"
Expand-Archive -Path "C:\Tools\SysinternalsSuite.zip" -DestinationPath "C:\Tools\Sysinternals"

# Add to PATH
$env:Path += ";C:\Tools\Sysinternals"

# Use directly from web (live.sysinternals.com)
\\live.sysinternals.com\tools\procmon.exe

# Configure tools to auto-accept EULA (avoid popup)
REG ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
```

### Sysinternals Suite Overview

| Category | Key Tools |
|----------|-----------|
| Process Tools | Process Explorer, Process Monitor, ProcDump, Handle, ListDLLs |
| System Tools | Autoruns, PsTools, RegJump, Sysmon |
| Disk Tools | Disk2vhd, Diskmon, DiskView |
| Network Tools | TCPView, PsPing |
| Security Tools | AccessChk, Autoruns, LogonSessions, SigCheck |
| File Tools | Streams, Strings, SDelete |

## Process Analysis Tools

### Process Explorer (procexp.exe)

Advanced task manager replacement that shows detailed process information.

```powershell
# Run Process Explorer
procexp.exe

# Run as administrator (recommended)
Start-Process procexp.exe -Verb RunAs
```

Key Features:
- Color-coding processes by type (services, new processes)
- View process properties, DLLs, and handles
- Verify image signatures
- Check VirusTotal integration
- View process tree and child processes

Security Analysis Tips:
- **Find suspicious processes**: Sort by "Company Name" and investigate unknown entries
- **Identify malicious processes**: Right-click a process → "Check VirusTotal"
- **Investigate handles**: Double-click a process → "Handles" tab to see open files/registry keys
- **Examine command lines**: View → Select Columns → Process Image → Command Line
- **Find hidden processes**: Options → Verify Image Signatures

### Process Monitor (procmon.exe)

Real-time file system, registry, and process/thread activity monitoring.

```powershell
# Run Process Monitor
procmon.exe

# Save logs to file
procmon.exe /BackingFile C:\Logs\system_activity.pml
```

Key Features:
- Real-time monitoring of file system, registry, network, process, and thread activity
- Advanced filtering system
- Boot time logging capabilities
- Stack traces for each operation

Security Analysis Tips:
- **Create baseline filters**: Filter → Filter (Ctrl+L) → Add standard exclusions
- **Detect malware activity**: Filter for suspicious paths (`%TEMP%`, `%APPDATA%`)
- **Identify persistence**: Filter for registry operations on startup locations (Run keys)
- **Track process creation chains**: Tools → Process Tree
- **Find file manipulations**: Filter for file operations on sensitive locations

### ProcDump (procdump.exe)

Command-line utility for monitoring processes and creating process dumps.

```powershell
# Create memory dump of a process by PID
procdump -ma 1234 C:\Logs\process_dump.dmp

# Create memory dump when CPU exceeds threshold
procdump -ma -c 80 notepad.exe C:\Logs\notepad_dump.dmp

# Create memory dump when specific exception occurs
procdump -ma -e 1 -f "OutOfMemoryException" w3wp.exe C:\Logs\w3wp_exception.dmp

# Create mini dump of all instances of a process
procdump -ma -x C:\dump_folder iexplore.exe
```

Security Analysis Tips:
- Capture process memory during suspicious activity for offline analysis
- Trigger dumps on specific behaviors (high CPU, exception, memory usage)
- Extract evidence of malware in memory
- Analyze memory dumps with tools like WinDbg or Volatility

### Handle (handle.exe)

View open file handles by process or display handles for a specific file.

```powershell
# Show all handles
handle.exe

# Show handles for specific process
handle.exe -p notepad.exe

# Show handles for specific file or path
handle.exe C:\Windows\System32

# Find processes with handles to a deleted file
handle.exe -a
```

Security Analysis Tips:
- Identify what processes are accessing sensitive files
- Find processes preventing file deletion
- Track malware attempting to access critical system files
- Detect unauthorized DLL loading

## System Information Tools

### Autoruns (autoruns.exe)

Comprehensive tool for viewing and managing Windows auto-start configurations.

```powershell
# Run Autoruns
autoruns.exe

# Run Autoruns for specific user
autorunsc.exe -u username

# Generate CSV report
autorunsc.exe -a * -c > autoruns_report.csv

# Hide Microsoft/Windows entries
autoruns.exe /h
```

Key Features:
- Shows all auto-start locations (registry, startup folder, scheduled tasks, services)
- Color codes for missing files and unsigned code
- VirusTotal integration
- Compare feature for baseline analysis

Security Analysis Tips:
- **Hide Microsoft/Windows entries**: Options → Hide Microsoft Entries
- **Find unsigned code**: Options → Scan Options → Verify Code Signatures
- **Check VirusTotal**: Options → Scan Options → Check VirusTotal.com
- **Compare to baseline**: File → Compare → Browse to previous autoruns file
- **Look for unusual autostart entries**: Sort by "Publisher" column and review unsigned/unknown entries

### Sysmon (sysmon.exe)

System monitoring service that logs detailed system activity to the Windows event log.

```powershell
# Install Sysmon with default configuration
sysmon.exe -i

# Install Sysmon with custom configuration file
sysmon.exe -i sysmon_config.xml

# Update Sysmon configuration
sysmon.exe -c sysmon_config.xml

# Uninstall Sysmon
sysmon.exe -u
```

Key Configuration Areas:
- Process creation/termination
- File creation time changes
- Network connections
- Driver/image loading
- Registry modifications
- WMI activity
- DNS queries

Recommended Configuration:
```xml
<Sysmon schemaversion="4.50">
  <HashAlgorithms>SHA1,MD5,SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Process Creation -->
    <ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</Image>
    </ProcessCreate>
    
    <!-- Network Connections -->
    <NetworkConnect onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <Image condition="contains">cmd.exe</Image>
      <Image condition="contains">rundll32.exe</Image>
    </NetworkConnect>
    
    <!-- Other configurations omitted for brevity -->
  </EventFiltering>
</Sysmon>
```

Security Analysis Tips:
- Use a robust configuration file like [SwiftOnSecurity's template](https://github.com/SwiftOnSecurity/sysmon-config)
- Forward Sysmon events to a SIEM for analysis
- Create alerts for suspicious process ancestry chains
- Monitor for abnormal network connections from unusual processes

### PsTools Suite

Collection of command-line tools for system administration and forensics.

**PsList (pslist.exe)**
```powershell
# List running processes
pslist.exe

# Show process threads and memory details
pslist.exe -m -d
```

**PsExec (psexec.exe)**
```powershell
# Run command on remote system
psexec.exe \\remotesystem -u username -p password cmd.exe

# Run command with SYSTEM privileges
psexec.exe -s cmd.exe
```

**PsLoggedOn (psloggedon.exe)**
```powershell
# Show all users logged on locally
psloggedon.exe

# Check specific computer
psloggedon.exe \\computername
```

**PsService (psservice.exe)**
```powershell
# List all services
psservice.exe

# View specific service
psservice.exe query servicename

# Start/stop a service
psservice.exe start/stop servicename
```

Security Analysis Tips:
- Use PsExec with caution (common tool for lateral movement)
- Check for unauthorized user sessions with PsLoggedOn
- Identify suspicious services with PsService
- Audit PsExec usage in your environment

## Disk and File System Tools

### Disk2vhd (disk2vhd.exe)

Creates VHD/VHDX virtual hard disk images of physical disks.

```powershell
# Create VHD of all volumes
disk2vhd.exe C:\Evidence\system_image.vhdx

# Create VHD of specific volumes
disk2vhd.exe -r C: D: C:\Evidence\system_image.vhdx
```

Security Analysis Tips:
- Capture forensic images of live systems
- Maintain disk snapshots for later analysis
- Convert physical machines to virtual for sandboxed malware analysis
- Preserve evidence before remediation

### Streams (streams.exe)

Reveals NTFS alternate data streams.

```powershell
# Check for alternate data streams
streams.exe filename.exe

# Check entire directory
streams.exe -s C:\Users\Username\Downloads

# Delete all streams
streams.exe -d filename.exe
```

Security Analysis Tips:
- Identify hidden data in NTFS alternate data streams
- Detect Zone.Identifier streams that mark files downloaded from the internet
- Find malware hiding code in alternate streams
- Discover potential data exfiltration techniques

### SDelete (sdelete.exe)

Securely deletes files and wipes free space.

```powershell
# Securely delete a file
sdelete.exe -p 3 filename.txt

# Clean free space
sdelete.exe -p 3 -c C:

# Zero free space (faster)
sdelete.exe -z C:
```

Security Analysis Tips:
- Securely remove sensitive data during incident response
- Prepare systems for decommissioning
- Prevent forensic recovery of sensitive information
- Clean temporary files after working with sensitive data

## Network Tools

### TCPView (tcpview.exe)

GUI tool for displaying detailed listings of all TCP and UDP connections.

```powershell
# Run TCPView
tcpview.exe
```

Key Features:
- Real-time view of all TCP/UDP connections
- Process-to-connection mapping
- Highlighting of newly created/terminated connections

Security Analysis Tips:
- **Identify suspicious connections**: Look for unusual destination IPs/ports
- **Detect beaconing**: Watch for recurring connections
- **Find backdoors**: Review listening ports and associated processes
- **Track connection history**: Use "Options" → "History Depth" to increase visibility
- **Export data**: Use "File" → "Save As" to save connection data for offline analysis

### PsPing (psping.exe)

Ping, latency, and bandwidth measurement tool.

```powershell
# Basic ping
psping.exe 8.8.8.8

# TCP ping
psping.exe -t 8.8.8.8:80

# Latency test
psping.exe -l 500 -n 100 8.8.8.8:80

# Bandwidth test (server)
psping.exe -s 8.8.8.8:80

# Bandwidth test (client)
psping.exe -b -l 8k -n 100 8.8.8.8:80
```

Security Analysis Tips:
- Test connectivity to suspicious IPs without using standard ping
- Measure network latency during security incidents
- Test if specific services/ports are accessible
- Conduct bandwidth tests to identify potential DDoS attacks

## Security Tools

### AccessChk (accesschk.exe)

Reports on security descriptors for files, registry keys, services, processes.

```powershell
# Check file permissions
accesschk.exe -c file.txt

# Check directory permissions recursively
accesschk.exe -s -d C:\Sensitive

# Check user's access to all services
accesschk.exe -c username *

# Find writable directories in Program Files
accesschk.exe -d -w "Everyone" "C:\Program Files"

# Find world-writable registry keys
accesschk.exe -k -w HKLM\Software
```

Security Analysis Tips:
- Identify privilege escalation paths via weak permissions
- Discover writable service executables
- Find exposed sensitive registry keys
- Audit file system permissions for security controls
- Check effective permissions for specific users

### SigCheck (sigcheck.exe)

Advanced file integrity checking and signature verification.

```powershell
# Check if file is signed
sigcheck.exe -a -h file.exe

# Check all EXEs in a directory
sigcheck.exe -e -h C:\Windows\System32

# Check and report to VirusTotal
sigcheck.exe -vt file.exe

# Check all files matching a pattern and output to CSV
sigcheck.exe -e -h -c -s -v C:\Windows\*.exe
```

Security Analysis Tips:
- Verify digital signatures of executables
- Identify unsigned binaries in sensitive directories
- Scan suspicious files against VirusTotal
- Compare file attributes against known-good baselines
- Check for certificate issues or revoked certificates

### LogonSessions (logonsessions.exe)

Lists all active logon sessions and maps them to running processes.

```powershell
# List logon sessions
logonsessions.exe -p
```

Security Analysis Tips:
- Identify unauthorized logon sessions
- Map processes to user sessions
- Detect credential theft and session hijacking
- Understand "who is running what" during security incidents

## Automation and Response

### PsExec (psexec.exe) for Remote Response

```powershell
# Run Process Explorer on remote system
psexec.exe \\remotesystem -c procexp.exe

# Execute command with SYSTEM privileges and capture output
psexec.exe \\remotesystem -s cmd.exe /c "netstat -ano > C:\evidence\connections.txt"

# Launch remote PowerShell
psexec.exe \\remotesystem -s powershell.exe -ExecutionPolicy Bypass -Command "Get-Process | Export-Csv C:\evidence\processes.csv"
```

### Scripting with Sysinternals

```powershell
# Create script to collect evidence
$script = @"
# Timestamp for collection
`$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
`$evidenceDir = "C:\Evidence_`$timestamp"
New-Item -ItemType Directory -Path `$evidenceDir -Force

# Run autoruns and save report
Start-Process -FilePath "autorunsc.exe" -ArgumentList "-a * -c" -NoNewWindow -RedirectStandardOutput "`$evidenceDir\autoruns.csv"

# Capture network connections
Start-Process -FilePath "tcpvcon.exe" -ArgumentList "-a -c" -NoNewWindow -RedirectStandardOutput "`$evidenceDir\networkconnections.csv"

# Take process memory dumps of suspicious processes
Start-Process -FilePath "procdump.exe" -ArgumentList "-ma explorer.exe `$evidenceDir\explorer.dmp" -NoNewWindow

# Collect process list with full details
Start-Process -FilePath "pslist.exe" -ArgumentList "-x" -NoNewWindow -RedirectStandardOutput "`$evidenceDir\processes.txt"

# Compress the evidence folder
Compress-Archive -Path `$evidenceDir -DestinationPath "`$evidenceDir.zip"
"@

# Save the script
$script | Out-File -FilePath "C:\Tools\collect_evidence.ps1"

# Execute the script remotely
psexec.exe \\remotesystem -s powershell.exe -ExecutionPolicy Bypass -File "C:\Tools\collect_evidence.ps1"
```

### Building a Response Jump Bag

Create a portable drive with essential Sysinternals tools:

1. **Core Tools**:
   - Process Explorer
   - Process Monitor
   - Autoruns
   - TCPView
   - ProcDump
   - PsExec
   - Handle
   - SigCheck

2. **Analysis Scripts**:
   - Collection scripts
   - Parsing scripts
   - Report templates

3. **Documentation**:
   - Tool usage guides
   - Analysis checklists
   - IR procedures

## Live Forensics

### Memory Acquisition

```powershell
# Capture full memory dump of specific process
procdump.exe -ma <PID> C:\Evidence\process_memory.dmp

# Capture full memory dump of system
procdump.exe -ma -r lsass.exe C:\Evidence\memory_full.dmp

# Create mini dumps of all instances of a process
procdump.exe -mm -x C:\Evidence chrome.exe
```

### Extracting Evidence

```powershell
# Extract strings from binary
strings.exe -s file.exe > strings_output.txt

# Extract alternate data streams
streams.exe -s C:\Users\Username\Downloads > ads_output.txt

# Find files with specific string
findstr.exe /s /i "password" C:\Users\*.txt > passwords_found.txt
```

### Creating Forensic Timeline

```powershell
# Configure Sysmon for forensic logging
sysmon.exe -i sysmon_config.xml

# Use Process Monitor with filter for forensic analysis
procmon.exe /BackingFile C:\Evidence\timeline.pml /Quiet /Minimized

# Create scheduled task to capture procmon logs
schtasks.exe /Create /TN "ForensicCapture" /TR "procmon.exe /BackingFile C:\Evidence\timeline_%date:~-4,4%%date:~-7,2%%date:~-10,2%.pml /Quiet /Minimized" /SC DAILY /ST 00:00
```

## Common Analysis Scenarios

### Malware Analysis

1. **Initial Triage**:
   - Run suspected file through SigCheck with VirusTotal integration
   - Use Strings to extract embedded text
   - Check for alternate data streams with Streams

2. **Behavioral Analysis**:
   - Set up Process Monitor with filters for the suspicious process
   - Run Process Explorer with VirusTotal integration
   - Use Autoruns to check for persistence mechanisms

3. **Network Activity**:
   - Monitor with TCPView for external connections
   - Use PsPing to test connectivity to suspicious IPs
   - Capture detailed network events with Sysmon

4. **Memory Analysis**:
   - Create process dump with ProcDump
   - Extract strings and analyze with Strings
   - Look for injected code or encrypted content

### Incident Response

1. **Initial Assessment**:
   - Run Autoruns to identify persistence mechanisms
   - Use Process Explorer to identify suspicious processes
   - Check LogonSessions for unauthorized access

2. **Evidence Collection**:
   - Capture memory dumps with ProcDump
   - Create disk image with Disk2vhd
   - Document network connections with TCPView
   - Run SigCheck against suspicious files

3. **Containment**:
   - Use PsKill to terminate malicious processes
   - Use PsSuspend to suspend suspicious processes
   - Remove persistence with Autoruns
   - Isolate system using PsShutdown for emergency shutdown

4. **Recovery**:
   - Use SDelete to securely remove malicious files
   - Verify system integrity with SigCheck
   - Validate permissions with AccessChk
   - Monitor for reinfection with Sysmon and ProcMon

### Privilege Escalation Investigation

1. **Permission Checks**:
   - Use AccessChk to find writable service executables
   - Check for weak directory permissions in sensitive locations
   - Identify misconfigured registry keys

2. **Service Analysis**:
   - Examine service configurations with PsService
   - Check service executable permissions with AccessChk
   - Look for unquoted service paths with Autoruns

3. **Process Analysis**:
   - Use Process Explorer to examine process tokens and privileges
   - Check for SYSTEM-level processes with Handle
   - Monitor privilege use with Sysmon

## 📎 Related Items

- [[Cheatsheets/Systems/Windows_Forensics]]
- [[Tool_Guides/Endpoint_Analysis/Windows_Live_Response]]
- [[Cheatsheets/Scripting/PowerShell_Cheatsheet]]
- [[Templates/Incident_Response/IR_Report_Template]]

---

> [!tip] Sysinternals Best Practices
> 1. Always run tools with administrator privileges for complete visibility
> 2. Create baselines of normal system behavior for comparison
> 3. Combine multiple tools for comprehensive analysis (e.g., Process Explorer + Process Monitor)
> 4. Use filters effectively to reduce noise, especially in Process Monitor
> 5. Consider legal and privacy implications before collecting data from systems 