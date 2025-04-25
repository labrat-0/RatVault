---
tags: [cheatsheet, scripting, bash, linux]
aliases: [Bash Reference, Shell Scripting]
created: {{date}}
updated: {{date}}
---

# 🐧 Bash Scripting Cheatsheet

> [!tip] Quick Start
> ```bash
> #!/bin/bash
> 
> # Your first bash script
> echo "Hello, Security World!"
> ```
> Save as `script.sh`, make executable with `chmod +x script.sh`, then run with `./script.sh`

## 📋 Basic Syntax

### Script Structure
```bash
#!/bin/bash
# Comments start with #
# Set strict mode
set -euo pipefail
IFS=$'\n\t'

# Your code here
```

### Variables
```bash
# Declaring variables (no spaces around =)
NAME="RatVault"
NUMBER=42

# Using variables
echo "The name is $NAME"
echo "The name is ${NAME}" # Better for complex cases

# Command substitution
CURRENT_DIR=$(pwd)
FILES=`ls -la` # Older syntax

# Constants (by convention)
readonly API_KEY="secret"

# Special variables
echo "Script name: $0"
echo "First argument: $1"
echo "All arguments: $@"
echo "Number of arguments: $#"
echo "Exit code of last command: $?"
```

### Conditionals
```bash
# If-else statement
if [ "$COUNT" -eq 100 ]; then
    echo "Count is 100"
elif [ "$COUNT" -gt 100 ]; then
    echo "Count is greater than 100"
else
    echo "Count is less than 100"
fi

# Modern test syntax
if [[ "$STRING" == *"substring"* ]]; then
    echo "String contains substring"
fi

# File tests
if [ -f "$FILE" ]; then echo "File exists"; fi
if [ -d "$DIR" ]; then echo "Directory exists"; fi
if [ -r "$FILE" ]; then echo "File is readable"; fi
if [ -w "$FILE" ]; then echo "File is writable"; fi
if [ -x "$FILE" ]; then echo "File is executable"; fi
```

### Loops
```bash
# For loop
for i in {1..10}; do
    echo "Number: $i"
done

# For loop with step
for i in {1..20..2}; do
    echo "Odd: $i"
done

# C-style for loop
for ((i=0; i<10; i++)); do
    echo "Index: $i"
done

# While loop
while [ "$COUNT" -lt 10 ]; do
    echo "Count: $COUNT"
    ((COUNT++))
done

# Until loop
until [ "$COUNT" -ge 10 ]; do
    echo "Count: $COUNT"
    ((COUNT++))
done

# Loop through files
for FILE in *.log; do
    echo "Processing $FILE"
done
```

## 🔍 String Operations

```bash
# String length
STRING="Security"
echo "Length: ${#STRING}"

# Substring
echo "First 3 chars: ${STRING:0:3}"

# String replacement
echo "Replace: ${STRING/curity/cond}"

# Replace all occurrences
echo "Replace all: ${STRING//r/R}"

# Default value if empty
EMPTY=""
echo "Default: ${EMPTY:-default_value}"

# Upper/lowercase (bash 4+)
echo "Uppercase: ${STRING^^}"
echo "Lowercase: ${STRING,,}"
```

## 🔢 Arrays

```bash
# Declare array
TOOLS=("nmap" "wireshark" "tcpdump")

# Access element
echo "First tool: ${TOOLS[0]}"

# All elements
echo "All tools: ${TOOLS[@]}"

# Array length
echo "Number of tools: ${#TOOLS[@]}"

# Add element
TOOLS+=("metasploit")

# Remove element
unset TOOLS[1]

# Iterate over array
for TOOL in "${TOOLS[@]}"; do
    echo "Tool: $TOOL"
done

# Associative arrays (bash 4+)
declare -A PORTS
PORTS[http]=80
PORTS[https]=443
echo "HTTP port: ${PORTS[http]}"
```

## 📝 Functions

```bash
# Defining a function
function greet() {
    local NAME="$1"
    echo "Hello, $NAME!"
    return 0
}

# Alternative syntax
check_status() {
    if [ "$1" -eq 0 ]; then
        echo "Success"
    else
        echo "Failed"
        return 1
    fi
}

# Calling functions
greet "Analyst"
check_status $?

# Capturing function output
RESULT=$(greet "SOC")
```

## 🔧 Command Line Arguments

```bash
# Parse command line args
while getopts ":h:f:v" opt; do
    case $opt in
        h)
            echo "Help: $OPTARG"
            ;;
        f)
            FILE="$OPTARG"
            ;;
        v)
            VERBOSE=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            ;;
    esac
done
```

## 📂 File Operations

```bash
# Read file line by line
while IFS= read -r LINE; do
    echo "Line: $LINE"
done < "input.txt"

# Process CSV
while IFS=, read -r FIELD1 FIELD2 FIELD3; do
    echo "Field 1: $FIELD1"
    echo "Field 2: $FIELD2"
    echo "Field 3: $FIELD3"
done < "data.csv"

# Write to file
echo "Log entry: $(date)" >> logs.txt

# Check if file exists before reading
if [ -f "$FILE" ]; then
    source "$FILE"
fi
```

## 🛡️ Security-Focused Examples

### Network Scanning
```bash
# Simple port scanner
for PORT in {1..1000}; do
    timeout 1 bash -c "echo >/dev/tcp/target.com/$PORT" 2>/dev/null && 
        echo "Port $PORT is open"
done

# Monitor failed SSH logins
grep "Failed password" /var/log/auth.log | 
    awk '{print $11}' | sort | uniq -c | sort -nr
```

### Log Analysis
```bash
# Extract IP addresses from logs
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" access.log | sort | uniq -c

# Find top HTTP status codes
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```

### File System Security
```bash
# Find SUID files
find / -type f -perm -4000 -ls 2>/dev/null

# Find world-writable files
find / -type f -perm -o+w -ls 2>/dev/null

# Find files modified in the last 24 hours
find / -type f -mtime -1 -ls 2>/dev/null
```

## 🐞 Debugging

```bash
# Enable debug mode
set -x

# Debug specific section
set -x
echo "Debugging this section"
set +x

# Trace execution
bash -x ./script.sh

# Check script for issues
shellcheck script.sh
```

## 🔗 Related Resources

- [[Cheatsheets/Scripting/PowerShell_Cheatsheet|PowerShell Cheatsheet]]
- [[Tool_Guides/Linux_Commands|Linux Commands Guide]]
- [[Cheatsheets/Systems/Linux_Hardening|Linux Hardening]]

---

> [!warning] Security Note
> - Always validate and sanitize input
> - Avoid using `eval` with user input
> - Use quotes around variables to prevent word splitting
> - Consider using `set -e` to exit on errors
> - Run scripts with least privilege necessary 