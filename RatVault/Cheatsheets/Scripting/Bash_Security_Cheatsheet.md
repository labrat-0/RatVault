---
tags: [cheatsheet, scripting, bash, linux, security]
date: {{date}}
author: 
version: 1.0
---

# 🐧 Bash for Security Analysts Cheatsheet

> [!info] About Bash
> Bash (Bourne Again SHell) is the default command-line interpreter for most Linux distributions. This cheatsheet focuses on commands and techniques useful for security analysts working in Linux environments.

## 📋 Table of Contents

- [Basic Commands](#basic-commands)
- [System Information](#system-information)
- [File Operations](#file-operations)
- [User Management](#user-management)
- [Network Analysis](#network-analysis)
- [Process Monitoring](#process-monitoring)
- [Log Analysis](#log-analysis)
- [Security Tools](#security-tools)
- [Forensic Commands](#forensic-commands)
- [One-Liners for Security](#one-liners-for-security)

## Basic Commands

```bash
# Get command help
man <command>
<command> --help

# Command history
history
history | grep ssh

# Clear screen
clear

# Command redirects
command > file.txt     # Redirect output to file (overwrite)
command >> file.txt    # Append output to file
command 2> errors.txt  # Redirect errors
command &> all.txt     # Redirect both output and errors

# Execute multiple commands
command1 && command2    # Run command2 if command1 succeeds
command1 || command2    # Run command2 if command1 fails
command1 ; command2     # Run command1 then command2 regardless
```

## System Information

```bash
# System and kernel
uname -a                # All system info
cat /etc/os-release     # OS details
lsb_release -a          # Distribution info
hostnamectl             # Detailed system info

# Hardware details
lscpu                   # CPU information
free -h                 # Memory usage (human-readable)
df -h                   # Disk usage (human-readable)
lsblk                   # Block devices

# System uptime and load
uptime
w                       # Who is logged in and what they're doing
last                    # Recent logins

# System logs
dmesg                   # Kernel ring buffer
journalctl              # systemd logs
cat /var/log/syslog     # System log
cat /var/log/auth.log   # Authentication log
```

## File Operations

```bash
# File permissions
ls -la                             # List files with permissions
chmod 755 file                     # Change permissions (rwx r-x r-x)
chmod u+x file                     # Add execute permission for user
chmod g-w file                     # Remove write permission for group
chown user:group file              # Change file owner and group

# Find files
find / -name "passwd"                                  # Find file by name
find / -type f -perm -04000 -ls                        # Find SUID files
find / -type f -mtime -1                               # Files modified in last 24 hours
find / -type f -size +100M                             # Files larger than 100MB
find /home -type f -name "*.sh" -exec grep -l "password" {} \;   # Find scripts containing "password"

# File checksums
md5sum file
sha256sum file
sha1sum file

# Compare files
diff file1 file2
cmp file1 file2

# File text search
grep -i "password" file                # Case-insensitive search
grep -r "api_key" /var/www/            # Recursive search
grep -A 3 -B 3 "error" logfile         # Show 3 lines before and after match
grep -E "192\.168\.[0-9]{1,3}\.[0-9]{1,3}" file    # Regex search for IP addresses

# View file content
cat file                      # Display entire file
head -n 20 file               # First 20 lines
tail -n 50 file               # Last 50 lines
tail -f /var/log/auth.log     # Follow file updates in real-time
less file                     # Paginated file viewing
```

## User Management

```bash
# Current user
whoami                  # Current username
id                      # User ID, group ID and groups

# User information
cat /etc/passwd         # User accounts
cat /etc/shadow         # Password hashes (requires root)
cat /etc/group          # Groups

# User activity
who                     # Currently logged in users
w                       # Currently logged in users and activity
last                    # All recent user logins
lastlog                 # Last login for all users
lastb                   # Failed login attempts

# User management
useradd -m username     # Create user
usermod -aG sudo username  # Add user to sudo group
passwd username         # Change user password
userdel -r username     # Delete user and home directory

# Switch user
su - username           # Switch to user with environment
sudo command            # Execute command as superuser
sudo -i                 # Get root shell
```

## Network Analysis

```bash
# Network configuration
ip a                    # Show interfaces and IP addresses
ip route                # Routing table
ss -tuln                # Active listening ports (-t TCP, -u UDP, -l listening, -n numeric)
netstat -tuln           # Alternative for ss command
nmcli connection show   # Network connections (NetworkManager)

# DNS lookups
host example.com
dig example.com
nslookup example.com
dig -x 8.8.8.8          # Reverse DNS lookup

# Network scanning
ping -c 4 192.168.1.1           # Basic connectivity test
traceroute example.com           # Trace network path
mtr example.com                  # Continuous traceroute
nmap -sS 192.168.1.0/24          # Scan subnet for open ports (needs root)
nmap -sV -p 1-1000 192.168.1.1   # Service version detection

# Network traffic
tcpdump -i eth0 -n               # Capture traffic on interface
tcpdump -i eth0 port 80          # Capture HTTP traffic
tcpdump -i eth0 -w capture.pcap  # Save capture to file
tcpdump -r capture.pcap          # Read from capture file
tcpdump host 192.168.1.1         # Traffic to/from specific host
tcpdump 'tcp[tcpflags] & (tcp-syn) != 0'  # Capture SYN packets

# Firewall
iptables -L                      # List rules
iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Allow SSH
ufw status                       # Ubuntu firewall status
firewall-cmd --list-all          # Firewalld rules (CentOS/RHEL)
```

## Process Monitoring

```bash
# Process listing
ps aux                                # All processes
ps aux | grep apache                  # Find specific process
ps -ef --forest                       # Process tree
pstree                                # Process tree alternative
top                                   # Dynamic process viewer
htop                                  # Enhanced top (may need installation)

# Process management
kill <pid>                            # Kill process by PID
killall <name>                        # Kill process by name
pkill <pattern>                       # Kill processes matching pattern
nice -n 19 command                    # Run with lower priority
renice +10 -p <pid>                   # Change priority of running process

# Process details
lsof                                  # List open files by processes
lsof -i :80                           # Processes using port 80
lsof -p <pid>                         # Files opened by PID
lsof -u username                      # Files opened by user
pmap <pid>                            # Memory map of process

# Service management
systemctl status sshd                 # Service status
systemctl start|stop|restart apache2  # Service control
service sshd status                   # Alternative for non-systemd
```

## Log Analysis

```bash
# System logs
tail -f /var/log/syslog               # Follow system log
tail -f /var/log/auth.log             # Follow authentication log
grep "Failed password" /var/log/auth.log  # Find failed logins
journalctl -u ssh                     # SSH service logs
journalctl --since "2023-05-01"       # Logs since date
journalctl -p err                     # Error level logs

# Web server logs
tail -f /var/log/apache2/access.log   # Apache access log
tail -f /var/log/nginx/access.log     # Nginx access log
grep "POST /login" /var/log/nginx/access.log  # Find login attempts

# Log analysis tools
awk '{print $1}' access.log           # Print first field (IP addresses)
awk '$9 >= 400' access.log            # HTTP error codes
sort access.log | uniq -c             # Count unique lines
cut -d' ' -f1 access.log | sort | uniq -c  # Count unique IPs
sed -n '/2023-05-01/,/2023-05-02/p' logfile.log  # Extract date range
```

## Security Tools

```bash
# File integrity
sha256sum -c checksums.txt            # Verify file checksums
stat file                             # File details including times
touch -r ref_file target_file         # Match timestamps

# Encryption/decryption
gpg -c file                           # Encrypt file
gpg file.gpg                          # Decrypt file
openssl enc -aes-256-cbc -in file -out file.enc  # Encrypt with OpenSSL
openssl enc -d -aes-256-cbc -in file.enc -out file  # Decrypt with OpenSSL

# SSH
ssh-keygen -t ed25519                 # Generate SSH key
ssh-copy-id user@hostname             # Copy SSH key to server
ssh -i key.pem user@hostname          # Use specific key
scp file.txt user@hostname:/path/     # Secure copy

# Security scanning
lynis audit system                    # System security audit
chkrootkit                            # Check for rootkits
rkhunter --check                      # Rootkit hunter
clamscan -r /                         # Scan for malware with ClamAV
```

## Forensic Commands

```bash
# Disk forensics
dd if=/dev/sda of=disk.img bs=4M      # Create disk image
dd if=/dev/sda1 | nc -l 9999          # Network disk clone
debugfs -c /dev/sda1                  # Examine ext filesystem
testdisk disk.img                     # Recover partitions/files

# Memory capture
memdump > mem.img                     # Capture RAM (needs memdump tool)
LiME (Linux Memory Extractor)         # Kernel module for memory acquisition

# File recovery
foremost -i disk.img -o recovered     # Recover files by headers
photorec disk.img                     # Alternative file recovery
extundelete /dev/sda1 --restore-all   # Recover deleted files on ext3/4

# Forensic analysis
strings disk.img | grep -i password   # Find strings in binary files
hexdump -C file | less                # Hex view of file
file suspicious_file                  # Determine file type
binwalk suspicious_file               # Analyze file for embedded files
```

## One-Liners for Security

### Find Recently Modified Files
```bash
find / -type f -mtime -7 -not -path "/proc/*" -not -path "/sys/*" | sort
```

### Monitor Authentication Attempts in Real-time
```bash
tail -f /var/log/auth.log | grep --line-buffered "Failed password"
```

### Find Files with SUID Bit Set
```bash
find / -type f -perm -4000 -ls 2>/dev/null
```

### List All Listening Network Services
```bash
netstat -tulpn | grep LISTEN
```

### Check for Users with Empty Passwords
```bash
cat /etc/shadow | awk -F: '($2==""){print $1}'
```

### Monitor Real-time Network Connections
```bash
watch -n 1 "netstat -tunapl | grep ESTABLISHED"
```

### Find World-Writable Files
```bash
find / -type f -perm -o+w -not -path "/proc/*" 2>/dev/null
```

### Check Running Web Servers for Info Leakage
```bash
curl -I localhost | grep -E "Server:|X-Powered-By:"
```

### Find Files Containing the Word "password"
```bash
grep -r -i "password" /home/ --include="*.conf" --include="*.txt" 2>/dev/null
```

### Find Processes Running as Root
```bash
ps -aux | grep "^root" | grep -v "\[" | awk '{print $11}'
```

### Find Unusual Large Files
```bash
find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null
```

### Check for Unauthorized Cron Jobs
```bash
find /var/spool/cron/ -type f -exec cat {} \;
```

### Find Users with UID 0 (Additional Root Users)
```bash
grep ":0:" /etc/passwd
```

### Monitor Failed Login Attempts
```bash
grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -nr
```

### List All Installed Packages
```bash
dpkg -l                   # Debian/Ubuntu
rpm -qa                   # RHEL/CentOS
```

## 📎 Related Items

- [[Cheatsheets/Scripting/PowerShell_Cheatsheet]]
- [[Cheatsheets/Systems/Linux_Forensics]]
- [[Tool_Guides/Linux_Security_Tools]]

---

> [!tip] Bash Security Tips
> 1. Always use full paths in security scripts to avoid path manipulation
> 2. Quote variables to prevent word splitting and globbing
> 3. Use `set -e` in scripts to exit on errors
> 4. Avoid storing sensitive information like passwords in shell scripts
> 5. Use `set -o pipefail` to detect errors in piped commands 