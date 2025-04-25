---
tags: [cheatsheet, yara, malware, threat-hunting, detection]
date: {{date}}
author: 
version: 1.0
---

# 🔎 YARA Rules Guide for Threat Hunting

> [!info] About YARA
> YARA is a tool designed to help malware researchers identify and classify malware samples. It uses pattern matching with rules to describe and detect malware families or specific threats.

## 📋 Table of Contents

- [YARA Basics](#yara-basics)
- [Rule Structure](#rule-structure)
- [Condition Operators](#condition-operators)
- [Writing Effective Rules](#writing-effective-rules)
- [String Patterns](#string-patterns)
- [Modules and Extensions](#modules-and-extensions)
- [Performance Optimization](#performance-optimization)
- [Testing and Validating Rules](#testing-and-validating-rules)
- [Real-World Examples](#real-world-examples)
- [YARA Tools and Integration](#yara-tools-and-integration)

## YARA Basics

### Installation

**Linux**:
```bash
sudo apt-get install yara
```

**macOS**:
```bash
brew install yara
```

**Windows**:
- Download from the [GitHub releases page](https://github.com/VirusTotal/yara/releases)
- Or install via Chocolatey: `choco install yara`

### Basic Usage

```bash
# Scan a file with a single rule
yara rule.yar suspicious_file

# Scan a directory recursively
yara -r rule.yar directory/

# Scan with multiple rule files
yara -r rules1.yar rules2.yar directory/

# Show strings that matched
yara -s rule.yar suspicious_file

# Show metadata for matched rules
yara -m rule.yar suspicious_file

# Show which rules were matched
yara -w rule.yar suspicious_file
```

## Rule Structure

A basic YARA rule has the following structure:

```yara
rule RuleName {
    meta:
        description = "Description of what this rule detects"
        author = "Your Name"
        date = "2023-05-01"
        hash = "SHA256 hash of a sample that matches this rule"
        
    strings:
        $string1 = "Plain text string"
        $hex_string = { 4D 5A 90 00 03 00 }
        $regex = /http:\/\/[a-z0-9\.]+\.evil\.com/
        
    condition:
        $string1 and $hex_string or $regex
}
```

### Meta Section

The `meta` section contains information about the rule itself:

```yara
meta:
    description = "Detects Emotet banking trojan"
    author = "Security Analyst"
    date = "2023-05-15"
    hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    reference = "https://example.com/blog/emotet-analysis"
    severity = "high"
    tlp = "amber"
    category = "banking_trojan"
```

Meta fields are completely optional and can be customized to your needs.

### Strings Section

The `strings` section defines the patterns to search for:

```yara
strings:
    // Plain text strings (case-sensitive)
    $text1 = "command.exe"
    
    // Case-insensitive string
    $text2 = "SYSTEM32" nocase
    
    // Wide (UTF-16) string
    $wide_string = "password" wide
    
    // Both ASCII and wide
    $ascii_wide = "admin" ascii wide
    
    // Hex strings
    $mz = { 4D 5A }  // MZ header
    $hex_with_wildcards = { 4D 5A ?? ?? 00 00 }
    
    // Regular expressions
    $regex1 = /[a-zA-Z0-9]{20,}\.exe/
    $regex2 = /https?:\/\/[^\x20\x22]+\/[a-z]{5,10}\.php/ nocase
    
    // String modifiers
    $fullword = "cmd.exe" fullword  // Only match whole words
    $xor_string = "backdoor" xor(1-255)  // Match XOR encoded with any key 1-255
```

### Condition Section

The `condition` section defines the logic for triggering the rule:

```yara
condition:
    // Basic boolean logic
    $text1 and $text2
    
    // Any of the strings
    any of them
    
    // Complex condition
    ($mz at 0) and (2 of ($text*)) and #regex1 > 3
    
    // File properties
    filesize < 1MB and $mz at 0
```

## Condition Operators

### Boolean Operators

```yara
$a and $b      // Both strings must be present
$a or $b       // Either string must be present
not $a         // String must not be present
$a and not $b  // $a must be present, $b must not be present
```

### Counting Operators

```yara
// Count matches in a file
#a > 5         // String $a must appear more than 5 times
#a < 10        // String $a must appear less than 10 times
#a >= 3        // String $a must appear 3 or more times

// Sets of strings
2 of ($a,$b,$c)          // At least 2 of these strings must be present
all of ($a,$b,$c)        // All of these strings must be present
any of ($a,$b,$c)        // Any of these strings must be present
3 of ($a*)               // At least 3 strings matching $a* pattern must be present
all of them              // All strings defined in the rule must be present
for all i in (1..#a): (  // For all occurrences of $a, a specific condition must be true
    @a[i] + 10 == @b[i]  // The offset of $b is 10 bytes after the offset of $a
)
```

### Positional Operators

```yara
$a at 0                // String $a must be at position 0
$a in (0..100)         // String $a must be in the first 100 bytes
$a at entrypoint       // String $a must be at the entry point (PE files)
$a in (entrypoint..entrypoint+100) // String in the first 100 bytes from entry point
```

### Reference Operators

```yara
@a               // Offset of the first occurrence of $a
!a               // Length of the first occurrence of $a
@a[i]            // Offset of the i-th occurrence of $a
!a[i]            // Length of the i-th occurrence of $a
```

### Special Conditions

```yara
filesize < 1MB         // File must be smaller than 1MB
filesize > 100KB       // File must be larger than 100KB
filename contains "temp" // Filename contains "temp"
extension_is "exe"     // File extension is "exe"
```

## Writing Effective Rules

### Balancing Specificity vs. Coverage

> [!tip] Rule Writing Guidelines
> - **Too specific**: May miss variants (false negatives)
> - **Too generic**: May trigger on benign files (false positives)
> - **Balanced approach**: Combine different indicators

### Best Practices

1. **Focus on unique behaviors**:
   - C2 communication patterns
   - Decoding/encryption routines
   - Persistence mechanisms
   
2. **Incorporate multiple string types**:
   - Mix of plain text, hex patterns, and regular expressions
   - Include strings from different parts of the malware

3. **Use contextual conditions**:
   - String relationships (proximity, order)
   - String locations (at file beginning, within a specific section)

4. **Test against known samples**:
   - Test against known malicious samples
   - Validate against benign programs to avoid false positives

## String Patterns

### Hex Strings

```yara
// Basic hex string
$hex1 = { 4D 5A 90 00 }  // Matches the exact bytes

// Wildcards
$hex2 = { 4D 5A ?? ?? }  // ?? matches any byte

// Alternative bytes
$hex3 = { 4D 5A (90|91) 00 }  // Matches either 90 or 91

// Ranges
$hex4 = { 4D 5A [2-4] 00 }  // Matches 2-4 bytes between 4D 5A and 00

// Jump
$hex5 = { 4D 5A [-] 00 }  // Matches any number of bytes between 4D 5A and 00

// Byte nibbles
$hex6 = { 4? ?5 }  // 4 as high nibble, 5 as low nibble
```

### Regular Expressions

```yara
// Email pattern
$email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/

// URL pattern
$url = /https?:\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?/

// IP address
$ip = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/

// Base64 pattern (matches 20+ character blocks)
$base64 = /[A-Za-z0-9+\/]{20,}={0,2}/

// Command line flags
$cmd_flags = /\s--(config|install|update|server)\s/

// Common obfuscation
$obf_var = /[a-z]{1,2}\d{1,3}[a-z]{1,2}\d{1,3}/
```

### String Modifiers

```yara
$s1 = "command" nocase       // Case-insensitive
$s2 = "unicode" wide         // Unicode/wide strings (UTF-16)
$s3 = "cmd.exe" fullword     // Only match if surrounded by non-alphanumeric chars
$s4 = "api" ascii wide       // Match both ASCII and Unicode
$s5 = "secret" xor           // Match XOR'd string (any 1-byte key)
$s6 = "message" xor(0x01-0x10) // Match string XOR'd with keys 0x01 to 0x10
$s7 = "kernel" base64        // Match base64 encoded string
```

## Modules and Extensions

YARA supports modules that extend its functionality:

### PE Module

```yara
import "pe"

rule PE_File_Example {
    condition:
        pe.is_pe and
        pe.number_of_sections > 5 and
        pe.imports("urlmon.dll", "URLDownloadToFileA") and
        pe.sections[0].name == ".text" and
        pe.entry_point > pe.sections[0].virtual_address and
        pe.entry_point < (pe.sections[0].virtual_address + pe.sections[0].virtual_size)
}
```

### Hash Module

```yara
import "hash"

rule Hash_Example {
    condition:
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" or
        hash.sha1(0, 100) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
}
```

### File System Module

```yara
import "math"
import "time"

rule File_Stats_Example {
    condition:
        time.now() - time.ctime() < 86400 and  // File created in last 24 hours
        math.entropy(0, filesize) > 7.7         // High entropy (potentially packed)
}
```

### Cuckoo Sandbox Module

```yara
import "cuckoo"

rule Cuckoo_Network_Activity {
    condition:
        cuckoo.network.http_request(/evil\.com/) or
        cuckoo.network.dns_lookup(/evil\.com/) or
        cuckoo.filesystem.file_access(/C:\\Windows\\Temp\\[^\\]+\.exe/)
}
```

## Performance Optimization

### Efficient Rules

1. **Start with fast conditions**:
   ```yara
   condition:
       uint16(0) == 0x5A4D and    // Check MZ header first (fast)
       filesize < 1000000 and      // Check file size (fast)
       $suspicious_string          // Only then look for strings (slower)
   ```

2. **Avoid expensive operations in initial filtering**:
   - Limit regex usage in large-scale scanning
   - Use simple string/hex patterns for initial detection

3. **Use file size constraints**:
   ```yara
   condition:
       filesize < 5MB and $string
   ```

4. **Optimize string patterns**:
   - Prefer fixed strings over regex when possible
   - Use anchored regex patterns like `/^prefix/` or `/suffix$/`

5. **Combine multiple weak indicators**:
   ```yara
   condition:
       3 of ($s*)  // Require multiple matches for higher confidence
   ```

## Testing and Validating Rules

### Testing Methodology

1. **Test against known samples**:
   ```bash
   yara -r my_rule.yar malware_samples/
   ```

2. **Verify string matches**:
   ```bash
   yara -s my_rule.yar suspicious_file
   ```

3. **Check for false positives**:
   ```bash
   yara -r my_rule.yar clean_files/
   ```

4. **Benchmark rule performance**:
   ```bash
   time yara -r my_rule.yar large_dataset/
   ```

### Debugging Tools

- YARA Editor: Visual Studio Code with YARA extension
- Online YARA Rule Test: [YaraRules](https://yara.readthedocs.io/en/stable/yarapython.html)
- Yara Rule Profiler: [yaraProfiling](https://github.com/PUNCH-Cyber/stoq-plugins-public/tree/master/yara)

## Real-World Examples

### Emotet Banking Trojan

```yara
rule Emotet_Loader {
    meta:
        description = "Detects Emotet malware loader"
        author = "Security Analyst"
        date = "2023-01-15"
        hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        
    strings:
        $s1 = { 8B 55 ?? 83 C2 ?? 89 14 24 }
        $s2 = { 8B 45 ?? 83 C0 ?? 89 45 ?? }
        $s3 = { 83 EC 20 53 55 56 57 8B 45 0C 8B 5D 10 }
        $s4 = { 83 7D 0C 01 75 ?? 8B 55 08 83 C2 04 }
        $api1 = "GetProcAddress" fullword
        $api2 = "LoadLibraryA" fullword
        $api3 = "VirtualAlloc" fullword
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        3 of ($s*) and
        all of ($api*)
}
```

### Ransomware File Encryption Function

```yara
rule Generic_Ransomware_Behavior {
    meta:
        description = "Detects common ransomware encryption behaviors"
        author = "Security Analyst"
        date = "2023-01-20"
        
    strings:
        $crypto1 = "CryptEncrypt" fullword
        $crypto2 = "CryptCreateHash" fullword
        $crypto3 = "CryptAcquireContext" fullword
        $file1 = "CreateFileA" fullword
        $file2 = "SetFilePointer" fullword
        $file3 = "WriteFile" fullword
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypt" nocase
        $ransom = "ransom" nocase
        $bitcoin = "bitcoin" nocase
        $payment = "payment" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($crypto*)) and
        (2 of ($file*)) and
        (1 of ($ext*)) and
        (1 of ($ransom, $bitcoin, $payment))
}
```

### Fileless Malware Detection

```yara
rule Fileless_Malware_PowerShell {
    meta:
        description = "Detects fileless malware using PowerShell"
        author = "Security Analyst"
        date = "2023-02-01"
        
    strings:
        $ps1 = "powershell" nocase
        $encode1 = "-enc" nocase
        $encode2 = "-encodedcommand" nocase
        $hex = "-w hidden" nocase
        $downloader1 = "downloadstring" nocase
        $downloader2 = "downloadfile" nocase
        $downloader3 = "webclient" nocase
        $inject1 = "reflection.assembly" nocase
        $inject2 = "[system.runtime.interopservices.marshal]::copy" nocase
        $invoke = "invoke-expression" nocase
        $b64long = /[A-Za-z0-9+\/]{100,}={0,2}/
        
    condition:
        $ps1 and
        (1 of ($encode*) or $hex) and
        (1 of ($downloader*)) and
        (1 of ($inject*) or $invoke) and
        $b64long
}
```

## YARA Tools and Integration

### Command-line Tools

- **yarGen**: Automatic YARA rule generation
  ```bash
  python yarGen.py -m /malware/samples/ --excludegood -o my_rule.yar
  ```

- **YARA-CI**: Continuous integration for YARA rules
  ```bash
  yara-ci scan -r rules/ -t samples/
  ```

- **yarAnalyzer**: Analyzes and tests YARA rules
  ```bash
  yarAnalyzer -r rule.yar -s samples/ -c clean/
  ```

### Integration with Other Tools

- **VirusTotal**: Uses YARA for custom detection
- **THOR Scanner**: Uses YARA for IOC scanning
- **Cuckoo Sandbox**: Can generate and use YARA rules from malware behavior
- **TheHive/Cortex**: YARA scanning of submitted samples
- **IDA Pro**: YARA integration for binary analysis
- **Volatility**: Memory forensics with YARA scanning

### YARA Rules Repositories

- [YARA-Rules](https://github.com/Yara-Rules/rules)
- [Awesome-YARA](https://github.com/InQuest/awesome-yara)
- [Florian Roth's Signature Base](https://github.com/Neo23x0/signature-base)
- [ESET YARA Rules](https://github.com/eset/malware-ioc)
- [US-CERT YARA Rules](https://github.com/cisagov/CHIRP)

## 📎 Related Items

- [[Cheatsheets/Scripting/PowerShell_Cheatsheet]]
- [[Templates/Malware_Analysis/Malware_Triage_Template]]
- [[Threat_Intel/YARA_Rules/Example_Rules]]

---

> [!tip] YARA Rule Development Tips
> 1. Start by identifying unique sections of malware and focus on those
> 2. Test your rules against both malicious and benign samples
> 3. Balance specificity and detection scope for best results
> 4. Document your rules thoroughly with sources, samples, and context
> 5. Use version control and consistent naming for rule management 