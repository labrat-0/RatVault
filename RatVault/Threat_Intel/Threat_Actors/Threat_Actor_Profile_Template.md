---
tags: [threat-actor, profile, threat-intel]
aliases: [APT Profile, Threat Group Profile]
actor_name: 
suspected_origin: 
first_observed: 
active: true
motivation: [financial, espionage, hacktivism, destruction, supply-chain]
sophistication: [basic, intermediate, advanced, strategic]
---

# 🎭 {{actor_name}} Threat Actor Profile

> [!quote] Actor Overview
> Brief 2-3 sentence summary of the threat actor, including their primary targets, notable characteristics, and general sophistication level.

## 📋 Key Details

| Attribute | Value |
|-----------|-------|
| **Also Known As** | Alternate names, group numbers (APT##, etc.) |
| **Suspected Origin** | Country/region of origin |
| **Active Since** | Year first observed |
| **Still Active** | Yes/No/Unknown |
| **Target Industries** | Finance, Healthcare, Government, etc. |
| **Target Regions** | Geographic focus of operations |
| **Motivation** | Financial, Espionage, Hacktivism, etc. |
| **Sophistication** | Basic, Intermediate, Advanced, Strategic |

## 🔍 Attribution & Analysis

Detailed information about the threat actor, including:
- Attribution confidence 
- Intelligence sources
- Evolution of activities over time
- Relationships with other threat actors or state sponsors
- Any legal actions, indictments, or public disclosures

## 🎯 Targeting Pattern

- Types of organizations targeted
- Geographic focus
- Vertical industries
- Strategic objectives
- Victim selection methodology

## ⚔️ TTPs (Tactics, Techniques & Procedures)

### Initial Access
- Common access vectors (e.g., spear phishing, exploit kits, supply chain)
- Example attack paths

### Execution & Persistence
- Malware families and tools used
- Persistence mechanisms
- Execution techniques

### Command & Control
- C2 infrastructure patterns
- Communication protocols
- Evasion techniques

### Lateral Movement & Privilege Escalation
- Techniques for spreading within networks
- Credential theft methods
- Administrative access patterns

### Data Exfiltration
- Types of data targeted
- Exfiltration mechanisms
- Data staging and compression

## 🔐 IOCs (Indicators of Compromise)

### Malware Families
- List of associated malware with links to detailed analysis

### Network Indicators
- C2 domains and IPs
- Communication patterns
- TLS certificates

### File Indicators
- File hashes
- File paths
- Registry modifications

## 🛡️ Detection & Mitigation

### YARA Rules
```yara
rule {{actor_name}}_Detection {
    meta:
        description = "Detects artifacts associated with {{actor_name}}"
        author = "Your Organization"
        date = "YYYY-MM-DD"
        
    strings:
        $s1 = "Example string 1"
        $s2 = "Example string 2"
        
    condition:
        any of them
}
```

### SIGMA Rules
```yaml
title: {{actor_name}} Activity Detection
status: experimental
description: Detects activity patterns associated with {{actor_name}}
author: Your Organization
date: YYYY/MM/DD
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine|contains: 'suspicious command'
    condition: selection
falsepositives:
    - Legitimate administrative tools
    - Similar legitimate processes
level: high
```

### Detection Strategies
- SIEM detection opportunities
- EDR detection strategies
- Network traffic analysis approaches
- Recommended monitoring

### Mitigation Strategies
- Specific hardening recommendations
- Patch priorities
- Network segmentation advice

## 📚 References & Further Reading

- [Link to threat reports]()
- [Link to blog posts]()
- [MITRE ATT&CK Profile](https://attack.mitre.org/)
- [Related threat intel]()

## 📎 Related Items

- [[Threat_Intel/YARA_Rules/{{actor_name}}_Rules]]
- [[Threat_Intel/IOCs/{{actor_name}}_IOCs]]
- [[Templates/Incident_Response/{{actor_name}}_Playbook]]

---

> [!note] Revision History
> - Created: {{date}}
> - Last Updated: {{date}} 