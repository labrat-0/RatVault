---
tags: [yara, rules, examples, threat-intel, detection]
date: {{date}}
author: 
version: 1.0
---

# 📊 Example YARA Rules Collection

> [!info] About This Collection
> This collection contains example YARA rules for detecting common malware techniques and specific threat actors. Use these as starting points for your own detection rules.

## 📋 Table of Contents

- [PowerShell Empire Detection](#powershell-empire-detection)
- [Cobalt Strike Beacon Detection](#cobalt-strike-beacon-detection)
- [Common Ransomware Behaviors](#common-ransomware-behaviors)
- [Credential Dumping Techniques](#credential-dumping-techniques)
- [Document Maldocs](#document-maldocs)
- [Living Off The Land Techniques](#living-off-the-land-techniques)
- [Obfuscation Techniques](#obfuscation-techniques)

## PowerShell Empire Detection

```yara
rule PowerShell_Empire_Indicators {
    meta:
        description = "Detects PowerShell Empire indicators"
        author = "RatVault Project"
        date = "2023-05-01"
        reference = "https://github.com/EmpireProject/Empire"
        severity = "high"
        
    strings:
        // Empire launcher patterns
        $launcher1 = "powershell -NoP -sta -NonI -W Hidden -Enc" nocase
        $launcher2 = "powershell.exe -NoP -NonI -w Hidden -c \"IEX" nocase
        
        // Common Empire strings
        $empire1 = "Invoke-Empire" nocase
        $empire2 = "$K=[System.Text.Encoding]::ASCII.GetBytes($R)" nocase
        $empire3 = "FromBase64String(" nocase
        $empire4 = "function Invoke-Shellcode" nocase
        $empire5 = "-NoExit -Command PowerShell" nocase
        
        // Empire agent communication
        $comm1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword
        $comm2 = "Cookie: session=" nocase
        
        // Common base64 patterns in Empire
        $b64_pattern = /[A-Za-z0-9+\/]{100,}={0,2}/
        
    condition:
        (1 of ($launcher*)) and
        (2 of ($empire*) or $b64_pattern) or
        (1 of ($comm*) and 1 of ($empire*))
}
```

## Cobalt Strike Beacon Detection

```yara
rule CobaltStrike_Beacon_Indicators {
    meta:
        description = "Detects Cobalt Strike Beacon in memory or dumped samples"
        author = "RatVault Project"
        date = "2023-05-02"
        reference = "https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/"
        hash = "5992f1948dcb376e6ddbe2bbcb24ed98"
        
    strings:
        // Beacon configuration
        $config1 = "%s as %s\\%s: %d" 
        $config2 = "beacon.x64.dll" nocase
        $config3 = "%s (admin)" 
        
        // Cobalt Strike specific strings
        $cs1 = "ReflectiveLoader" fullword
        $cs2 = "www.stage.%x%x.%s" fullword
        $cs3 = "Content-Type: application/octet-stream"
        
        // Common shellcode strings
        $shell1 = { 48 8B C4 48 89 58 }
        $shell2 = { 48 89 5C 24 ?? 48 89 6C 24 }
        $shell3 = { 48 8B CF E8 ?? ?? ?? ?? 48 85 C0 74 }
        
        // Encoded config/strings
        $enc1 = { 00 01 00 01 00 02 }
        $enc2 = { 69 68 69 68 69 }
        
        // Named pipes
        $pipe1 = "\\\\%s\\pipe\\msagent_%x" fullword
        $pipe2 = "\\\\%s\\pipe\\MSSE-%u" fullword
        
    condition:
        (uint16(0) == 0x5A4D) and
        (2 of ($config*) or 2 of ($cs*)) and
        (2 of ($shell*) or 1 of ($enc*) or 1 of ($pipe*))
}
```

## Common Ransomware Behaviors

```yara
rule Generic_Ransomware_Indicators {
    meta:
        description = "Detects common behaviors found in ransomware"
        author = "RatVault Project"
        date = "2023-05-03"
        
    strings:
        // File encryption APIs
        $crypt1 = "CryptEncrypt" nocase fullword
        $crypt2 = "CryptGenRandom" nocase fullword
        $crypt3 = "CryptCreateHash" nocase fullword
        $crypt4 = "CryptDeriveKey" nocase fullword
        
        // Crypto libraries
        $lib1 = "advapi32.dll" nocase fullword
        $lib2 = "crypt32.dll" nocase fullword
        $lib3 = "bcrypt.dll" nocase fullword
        
        // File operations
        $file1 = "GetFileAttributesW" nocase fullword
        $file2 = "SetFileAttributesW" nocase fullword
        $file3 = "GetTempPathW" nocase fullword
        $file4 = "ReadFile" nocase fullword
        $file5 = "WriteFile" nocase fullword
        
        // Ransom note indicators
        $note1 = "ransom" nocase
        $note2 = "bitcoin" nocase
        $note3 = "decrypt" nocase
        $note4 = "encrypt" nocase
        $note5 = "payment" nocase
        $note6 = ".txt" nocase
        $note7 = ".html" nocase
        
        // Common extension patterns
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypt" nocase
        $ext4 = ".CRYPTED" nocase
        $ext5 = { 00 2E 00 72 00 61 00 6E 00 73 00 6F 00 6D } // ".ransom" unicode
        
        // Shadow copy deletion
        $shadow1 = "vssadmin delete shadows" nocase
        $shadow2 = "wmic shadowcopy delete" nocase
        $shadow3 = "WMIC.exe shadowcopy" nocase
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($crypt*) and 1 of ($lib*) and 3 of ($file*)) or
            (1 of ($shadow*) and (2 of ($note*) or 1 of ($ext*))) or
            (2 of ($ext*) and 2 of ($note*) and 2 of ($file*))
        )
}
```

## Credential Dumping Techniques

```yara
rule Credential_Dumping_Techniques {
    meta:
        description = "Detects common credential dumping techniques"
        author = "RatVault Project"
        date = "2023-05-04"
        
    strings:
        // Mimikatz strings
        $mimikatz1 = "mimikatz" nocase fullword
        $mimikatz2 = "mimilib" nocase
        $mimikatz3 = "sekurlsa::" nocase
        $mimikatz4 = "kerberos::" nocase
        $mimikatz5 = "lsadump::" nocase
        $mimikatz6 = "privilege::" nocase
        $mimikatz7 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 } // "kernel32.dll"
        
        // LSASS access
        $lsass1 = "lsass.exe" nocase fullword
        $lsass2 = { 50 72 6F 63 65 73 73 49 64 3A 20 }  // "ProcessId: "
        $lsass3 = { 00 5C 00 6C 00 73 00 61 00 73 00 73 00 2E 00 65 00 78 00 65 } // "\lsass.exe" unicode
        
        // Process dump techniques
        $dump1 = "dbghelp.dll" nocase fullword
        $dump2 = "MiniDump" nocase
        $dump3 = "MiniDumpWriteDump" nocase fullword
        $dump4 = "comsvcs.dll" nocase
        $dump5 = "#24" fullword // Rundll32 ordinal for MiniDumpW
        
        // ProcExp/Dumper patterns
        $procdump1 = "procdump" nocase
        $procdump2 = "processhacker" nocase
        
        // Credential file access
        $credfile1 = "sam" nocase fullword
        $credfile2 = "system" nocase fullword
        $credfile3 = "security" nocase fullword
        $credfile4 = { 00 5C 00 53 00 41 00 4D 00 00 00 } // "\SAM" unicode
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($mimikatz*)) or
            (1 of ($lsass*) and 1 of ($dump*)) or
            (1 of ($procdump*) and 1 of ($lsass*)) or
            (2 of ($credfile*) and 1 of ($dump*))
        )
}
```

## Document Maldocs

```yara
rule Office_Maldoc_Indicators {
    meta:
        description = "Detects malicious Office documents with common exploitation techniques"
        author = "RatVault Project"
        date = "2023-05-05"
        
    strings:
        // VBA macro indicators
        $vba1 = "ThisDocument" nocase
        $vba2 = "Auto_Open" nocase
        $vba3 = "AutoOpen" nocase
        $vba4 = "Document_Open" nocase
        $vba5 = "Workbook_Open" nocase
        
        // Shell execution methods
        $shell1 = "Shell" nocase fullword
        $shell2 = "WScript.Shell" nocase
        $shell3 = "ShellExecute" nocase
        $shell4 = "Wscript.CreateObject" nocase
        
        // PowerShell usage from Office
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "-ExecutionPolicy bypass" nocase
        $ps4 = "-NoProfile" nocase
        $ps5 = "hidden" nocase
        
        // Suspicious functions
        $func1 = "CreateObject" nocase
        $func2 = "GetObject" nocase
        $func3 = "Chr(" nocase
        $func4 = "Mid(" nocase
        $func5 = "URLDownloadToFile" nocase
        $func6 = "MSXML2.XMLHTTP" nocase
        $func7 = "ADODB.Stream" nocase
        
        // Obfuscation techniques
        $obf1 = { 43 68 72 28 [0-2] 29 [0-1] 26 [0-1] 43 68 72 28 } // Chr() & Chr()
        $obf2 = "Chr(Asc(" nocase
        
        // Document-specific exploits
        $exploit1 = "CVE-2017-11882" nocase
        $exploit2 = "CVE-2018-0802" nocase
        $exploit3 = /equation\.3/ nocase
        
        // OLE objects and ActiveX
        $ole1 = { D0 CF 11 E0 A1 B1 1A E1 } // OLE header
        $ole2 = "objdata" nocase
        $ole3 = "MSScriptControl.ScriptControl" nocase
        
    condition:
        (uint32(0) == 0xE011CFD0 or // OLE document
         uint32(0) == 0x04034B50) and // ZIP/OOXML document
        (
            (2 of ($vba*) and (1 of ($shell*) or 1 of ($ps*))) or
            (1 of ($exploit*)) or
            (2 of ($func*) and 1 of ($obf*)) or
            (1 of ($ole*) and 1 of ($func*) and 1 of ($shell*))
        )
}
```

## Living Off The Land Techniques

```yara
rule Living_Off_The_Land_Techniques {
    meta:
        description = "Detects malicious use of legitimate Windows tools"
        author = "RatVault Project"
        date = "2023-05-06"
        reference = "https://lolbas-project.github.io/"
        
    strings:
        // LOLBAS binaries with suspicious parameters
        $lolbas1 = "certutil" nocase
        $lolbas2 = "bitsadmin" nocase
        $lolbas3 = "wmic" nocase
        $lolbas4 = "regsvr32" nocase
        $lolbas5 = "mshta" nocase
        $lolbas6 = "rundll32" nocase
        $lolbas7 = "msiexec" nocase
        
        // Suspicious parameters
        $param1 = "-urlcache" nocase
        $param2 = "-decode" nocase
        $param3 = "downloadfile" nocase
        $param4 = "/scrobj" nocase
        $param5 = "javascript:" nocase
        $param6 = "vbscript:" nocase
        $param7 = "/i:http" nocase
        $param8 = "scrnsave.scr" nocase
        $param9 = "RunDLL32.exe" nocase
        
        // Command execution
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "cmd.exe /k" nocase
        $cmd3 = "cmd /c" nocase
        $cmd4 = "powershell.exe -" nocase
        
        // Execution evasion
        $evade1 = "^s^e^t" nocase
        $evade2 = "&&set" nocase
        $evade3 = "^V^A^R" nocase
        $evade4 = "\"s\"e\"t\"" nocase
        $evade5 = "f^or /L" nocase
        
        // File operations
        $file1 = "%temp%" nocase
        $file2 = "%appdata%" nocase
        
        // Remote resources
        $remote1 = "http://" nocase
        $remote2 = "https://" nocase
        $remote3 = "ftp://" nocase
        
    condition:
        (1 of ($lolbas*)) and
        (
            (1 of ($param*) and 1 of ($remote*)) or
            (1 of ($cmd*) and 1 of ($file*)) or
            (1 of ($evade*) and 1 of ($lolbas*)) or
            (1 of ($param*) and 1 of ($cmd*))
        )
}
```

## Obfuscation Techniques

```yara
rule Code_Obfuscation_Techniques {
    meta:
        description = "Detects common code obfuscation techniques"
        author = "RatVault Project"
        date = "2023-05-07"
        
    strings:
        // PowerShell obfuscation
        $ps_obf1 = "[char[]](0x" nocase
        $ps_obf2 = "-join[char[]]" nocase
        $ps_obf3 = "[string][char[]](0x" nocase
        $ps_obf4 = {5B 00 63 00 68 00 61 00 72 00 5B 00 5D 00 5D} // "[char[]]" Unicode
        $ps_obf5 = {69 00 65 00 78 00} // "iex" Unicode
        $ps_obf6 = {5B 00 73 00 79 00 73 00 74 00 65 00 6D 00 2E 00 63 00 6F 00 6E 00 76 00 65 00 72 00 74 00 5D 00 3A 00 3A} // "[system.convert]::" Unicode
        
        // String manipulation
        $str_manip1 = "replace(" nocase
        $str_manip2 = "substring(" nocase
        $str_manip3 = "reverse(" nocase
        $str_manip4 = "FromBase64String(" nocase
        $str_manip5 = "ToBase64String(" nocase
        
        // JavaScript obfuscation
        $js_obf1 = "eval(" nocase
        $js_obf2 = "String.fromCharCode" nocase
        $js_obf3 = "unescape(" nocase
        $js_obf4 = "parseInt(" nocase fullword
        $js_obf5 = "atob(" nocase fullword
        $js_obf6 = "decodeURIComponent" nocase
        
        // VBS/VBA obfuscation
        $vb_obf1 = "Chr(" nocase
        $vb_obf2 = "ChrW(" nocase
        $vb_obf3 = "Asc(" nocase
        $vb_obf4 = "Mid(" nocase
        $vb_obf5 = "&Chr(" nocase
        
        // Hex/encoding patterns
        $enc1 = /["'](%[0-9a-fA-F]{2}){10,}["']/ // URL encoding
        $enc2 = /0x[0-9a-fA-F]{2},0x[0-9a-fA-F]{2}/ // Hex array
        $enc3 = { 22 5C 78 [2] 5C 78 [2] 5C 78 [2] 22 } // "\xNN\xNN\xNN"
        
        // Base64 patterns with padding variations
        $b64_1 = /[A-Za-z0-9+\/]{40,}[=]{0,2}/ // Standard Base64
        $b64_2 = /[0-9a-zA-Z_-]{40,}[=]{0,2}/ // URL-safe Base64
        
    condition:
        (
            // PowerShell specific
            (2 of ($ps_obf*) and 1 of ($str_manip*)) or
            
            // JavaScript specific
            (2 of ($js_obf*) and (1 of ($enc*) or 1 of ($b64_*))) or
            
            // VB/VBA specific
            (3 of ($vb_obf*)) or
            
            // Generic obfuscation
            (1 of ($str_manip*) and 1 of ($b64_*) and 1 of ($enc*))
        )
}
```

## 🔧 Using These Rules

### Combining Multiple Rules

You can combine multiple rules into a single file for broader coverage:

```yara
import "pe"
include "./ransomware_rules.yar"
include "./credential_dumping_rules.yar"

rule Combined_Threat_Detection {
    condition:
        Credential_Dumping_Techniques or 
        Generic_Ransomware_Indicators or
        PowerShell_Empire_Indicators
}
```

### Integration with EDR/SIEM

These rules can be integrated with security platforms:

1. **EDR Tools**: Import as custom detection rules
2. **SIEM Platforms**: Convert to appropriate query format
3. **Threat Hunting**: Use with file scanning tools across endpoints

### Rule Testing and Validation

To validate these rules against your environment:

```bash
# Test all rules against a directory
yara -r all_rules.yar /path/to/scan/ -t

# Generate performance metrics
yara -r all_rules.yar -f -p 10 -S /path/to/scan/

# Check for errors in rule syntax
yarac all_rules.yar compiled_rules.yarc
```

## 📎 Related Items

- [[Cheatsheets/Query_Languages/YARA_Rules_Guide]]
- [[Templates/Malware_Analysis/Malware_Triage_Template]]
- [[Tool_Guides/Endpoint_Analysis/Yara_Scanning]]

---

> [!tip] Rule Customization
> These are example rules that should be customized to your environment:
> 1. Test against known-good files to reduce false positives
> 2. Update string patterns based on your specific threat landscape
> 3. Consider performance impact when deploying to production
> 4. Regularly update rules as new threat techniques emerge 