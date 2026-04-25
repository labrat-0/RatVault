---
title: "Bash Scripting Cheatsheet"
slug: "bash-cheatsheet"
created: "2026-04-25"
ingested_at: "2026-04-25T00:00:00Z"
summary: "Essential bash syntax, patterns, and best practices for shell scripting"
tags: [bash, shell, scripting, linux, cheatsheet]
category: development
difficulty: intermediate
key_concepts: [variables, functions, arrays, pipes, grep-sed-awk]
questions_answered: [how-to-iterate, how-to-parse-json, how-to-handle-errors]
provider: manual
status: active
type: reference
---

# Bash Scripting Cheatsheet

## Variables

```bash
# Variable assignment
name="Alice"
age=30

# Command substitution
date=$(date +%Y-%m-%d)
files=$(ls *.txt)

# Default values
${var:-default}    # Use default if var is unset
${var:=default}    # Assign and use default

# Parameter expansion
${var#pattern}     # Remove prefix
${var%pattern}     # Remove suffix
${var/old/new}     # Replace
```

## Arrays

```bash
# Indexed array
arr=(one two three)
arr[3]=four
echo "${arr[@]}"      # All elements
echo "${#arr[@]}"     # Length
echo "${arr[0]}"      # First element

# Associative array (bash 4+)
declare -A map
map["key"]="value"
for key in "${!map[@]}"; do
    echo "$key -> ${map[$key]}"
done
```

## Functions

```bash
# Simple function
greet() {
    echo "Hello, $1!"
}
greet "World"

# With return value
add() {
    echo $((1 + 2))
}
result=$(add 5 3)

# Local variables
outer_var="global"
inner_func() {
    local inner_var="local"  # Only in this function
}
```

## Conditionals

```bash
# If/elif/else
if [ -f "$file" ]; then
    echo "File exists"
elif [ -d "$file" ]; then
    echo "Is directory"
else
    echo "Not found"
fi

# String tests
[ -z "$var" ]      # Empty string?
[ -n "$var" ]      # Non-empty?
[ "$a" = "$b" ]    # Equal?
[ "$a" != "$b" ]   # Not equal?

# File tests
[ -f $file ]       # Regular file?
[ -d $file ]       # Directory?
[ -r $file ]       # Readable?
[ -w $file ]       # Writable?
[ -x $file ]       # Executable?
```

## Loops

```bash
# For loop
for i in {1..5}; do
    echo "Number: $i"
done

# While loop
count=0
while [ $count -lt 5 ]; do
    echo $count
    count=$((count + 1))
done

# Until loop (opposite of while)
until [ $count -eq 10 ]; do
    count=$((count + 1))
done

# Iterating files
for file in *.txt; do
    echo "Processing: $file"
done
```

## Pipes & Redirection

```bash
# Output redirection
cmd > file          # Write to file (overwrite)
cmd >> file         # Append to file
cmd 2> errors.log   # Redirect stderr

# Pipe
cmd1 | cmd2         # cmd2 reads output of cmd1

# Useful commands
grep "pattern" file              # Search
sed 's/old/new/g' file          # Replace
awk '{print $1, $3}' file       # Extract columns
cut -d: -f1 file                # Cut by delimiter
sort file | uniq -c             # Count occurrences
```

## Error Handling

```bash
#!/bin/bash
set -e          # Exit on error
set -u          # Error on undefined variable
set -o pipefail # Catch errors in pipes

# Trap errors
trap 'echo "Error on line $LINENO"' ERR

# Manual error handling
if ! command; then
    echo "Command failed"
    exit 1
fi
```

## Useful Patterns

```bash
# Check if script is sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Script is being executed"
fi

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file) file="$2"; shift 2 ;;
        -v|--verbose) verbose=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Retry logic
retry_count=0
max_retries=3
until [ $retry_count -ge $max_retries ]; do
    if curl https://api.example.com; then
        break
    fi
    retry_count=$((retry_count + 1))
    sleep 2
done
```

## Resources
- [GNU Bash Manual](https://www.gnu.org/software/bash/manual/)
- [ShellCheck](https://www.shellcheck.net) - Linter
- [Bash Pitfalls](https://mywiki.wooledge.org/BashPitfalls)
