---
tags: [phishing, analysis, template, email, incident]
date: {{date}}
status: new
case_id: "PH-{{date:YYYYMMDD}}-XX"
reporter: 
target_users: []
severity: medium
campaign: 
blocked: 
analysis_complete: false
---

# 🎣 Phishing Email Analysis: {{title}}

> [!info] Case Information
> - **Case ID**: `PH-{{date:YYYYMMDD}}-XX`
> - **Date Received**: {{date:YYYY-MM-DD}}
> - **Status**: New
> - **Severity**: Medium
> - **Analyst**: {{analyst}}

## 📝 Executive Summary

*Brief overview of the phishing attempt, targeting strategy, and potential impact*

## 📨 Email Details

| Attribute | Value |
|-----------|-------|
| From (Display Name) | |
| From (Email) | |
| Reply-To | |
| To | |
| CC | |
| BCC | |
| Subject | |
| Date/Time | |
| Contains Attachment | Yes/No |
| Contains Links | Yes/No |

## 🔍 Email Headers

```
Insert relevant email headers here
```

### Header Analysis

| Header Field | Value | Notes |
|--------------|-------|-------|
| Return-Path | | |
| X-Originating-IP | | |
| Received-SPF | | |
| DKIM Signature | | |
| DMARC | | |
| Authentication-Results | | |

### Sender Analysis

**Sender Domain Age**: 
**WHOIS Information**:
**Previously Known/Seen**: Yes/No

## ⚔️ Tactics, Techniques, and Procedures

**Social Engineering Methods**:
- [ ] Urgency/Time Pressure
- [ ] Authority Impersonation
- [ ] Fear/Threat
- [ ] Curiosity
- [ ] Financial Gain
- [ ] Technical Deception
- [ ] Familiarity/Trust

**Technical Mechanisms**:
- [ ] Malicious Attachment
- [ ] Malicious Link
- [ ] Credential Harvesting
- [ ] Document with Macros
- [ ] Drive-by Download
- [ ] Browser Exploit
- [ ] Other: _____________

## 📎 Attachment Analysis

*Complete this section if email contained attachments*

| Attribute | Value |
|-----------|-------|
| Filename | |
| File Size | |
| File Type | |
| MD5 Hash | |
| SHA1 Hash | |
| SHA256 Hash | |
| File Extension | |
| Actual MIME Type | |
| Contains Macros | Yes/No |
| Detection Ratio | |

### Sandbox Analysis

**Sandbox Used**: (VirusTotal, Any.Run, Hybrid Analysis, etc.)
**Sandbox Report Link**:

**Observed Behavior**:
- 
- 
- 

## 🔗 URL/Link Analysis

*Complete this section if email contained links*

| URL | Status | Destination | Purpose |
|-----|--------|-------------|---------|
| | | | |
| | | | |

### Landing Page Analysis

**Domain Age**: 
**Hosting Provider**: 
**IP Address**: 
**SSL Certificate**: 
**Similar to Legitimate Site**: Yes/No (Details)

**Page Purpose**:
- [ ] Credential Harvesting
- [ ] Malware Delivery
- [ ] Command & Control
- [ ] Redirect Chain
- [ ] Other: _____________

**Screenshot**:
*Add screenshot of landing page if available*

## 🖥️ Infrastructure Analysis

**Sending Infrastructure**:
**Hosting Provider**:
**Related Campaigns**:
**Connected Infrastructure**:

## 🔄 Payload Analysis

**Malware Family**: 
**Command & Control Servers**:
**Capabilities**:
- [ ] Keylogging
- [ ] Screenshot Capture
- [ ] Data Exfiltration
- [ ] Remote Access
- [ ] Cryptomining
- [ ] Ransomware
- [ ] Lateral Movement
- [ ] Other: _____________

## ⛔ Impact Assessment

**Potential Impact**: 
**Targeted Data/Access**:
**Number of Recipients**:
**Number of Interactions**:

## 🔍 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Initial Access | T1566 | Phishing |
| | | |
| | | |

## 🔐 Defensive Recommendations

### Immediate Response Actions
1. 
2. 
3. 

### Technical Controls
1. 
2. 
3. 

### User Awareness
1. 
2. 
3. 

## 🧮 Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|------|-----------|---------|
| Email | | |
| Domain | | |
| URL | | |
| IP | | |
| Hash | | |
| File | | |

## 📎 Related Items

- [[Daily_Logs/{{date:YYYY-MM-DD}}]]
- [[Threat_Intel/IOCs/Email_Campaigns]]
- [[Templates/Incident_Response/IR_Report_Template]]

---

> [!tip] Phishing Analysis Process
> 1. Always analyze emails in a secure environment
> 2. Extract and document all IOCs
> 3. Check against known campaigns and threat intelligence
> 4. Determine the campaign scope and targets
> 5. Assess potential impact and recommend mitigations 