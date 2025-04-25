---
tags: [forensics, dfir, investigation, template, evidence]
date: {{date}}
status: pending
case_id: "DF-{{date:YYYYMMDD}}-XX"
examiner: 
priority: medium
evidence_items: []
goals: []
chain_of_custody: true
---

# 🔎 Digital Forensics Worksheet: {{title}}

> [!info] Case Information
> - **Case ID**: `DF-{{date:YYYYMMDD}}-XX`
> - **Date Initiated**: {{date:YYYY-MM-DD}}
> - **Examiner**: {{examiner}}
> - **Priority**: Medium
> - **Status**: Pending
> - **Related Incident**: 

## 📝 Investigation Overview

### Case Background
*Brief description of the incident or investigation that prompted this forensic analysis*

### Investigation Goals
- [ ] 
- [ ] 
- [ ] 

### Legal Authority
*Document legal authority for forensic examination (warrant, consent form, company policy, etc.)*

## 🖥️ Evidence Item Details

### Evidence Item #1

| Attribute | Value |
|-----------|-------|
| Evidence ID | |
| Description | |
| Make/Model | |
| Serial Number | |
| Owner/Custodian | |
| Location Acquired | |
| Date/Time Acquired | |
| Acquired By | |
| Acquisition Method | |
| Storage Capacity | |
| Condition | |
| Write Blocker Used | Yes/No |
| Chain of Custody Doc | |

### Image Information

| Attribute | Value |
|-----------|-------|
| Image Type | (E01, RAW/DD, etc.) |
| Compression | Yes/No |
| Segmented | Yes/No |
| Image Location | |
| Acquisition Tool | |
| Acquisition Tool Version | |
| Image Verification | |
| Source Hash (MD5) | |
| Source Hash (SHA1) | |
| Source Hash (SHA256) | |
| Image Hash (MD5) | |
| Image Hash (SHA1) | |
| Image Hash (SHA256) | |

*Repeat this section for each evidence item as needed*

## 📊 Initial Assessment

### Storage Media Analysis
*Overview of partitions, file systems, encryption status, etc.*

| Partition | File System | Size | Status |
|-----------|-------------|------|--------|
| | | | |
| | | | |

### Timeline of System Activity

| Date/Time | Event | Source | Notes |
|-----------|-------|--------|-------|
| | | | |
| | | | |

## 🔍 Examination Steps & Findings

### Step 1: [Description of Examination Step]
*Document the specific process, tools used, and command syntax*

**Commands/Tools Used**:
```
Insert command syntax or tool settings here
```

**Findings**:
*Document what was found during this step*

**Artifacts Collected**:
*List specific files, logs, or other digital artifacts*

### Step 2: [Description of Examination Step]
*Repeat format for each major examination step*

## 👤 User Activity Analysis

### User Accounts

| Username | Type | Last Login | Login Count | Admin Rights |
|----------|------|------------|------------|--------------|
| | | | | |
| | | | | |

### Browser History

| Date/Time | URL | Browser | User | 
|-----------|-----|---------|------|
| | | | |
| | | | |

### Recent Files

| Date/Time | Filename | Path | Action |
|-----------|----------|------|--------|
| | | | |
| | | | |

## 📡 Network Forensics

### Network Connections

| Date/Time | Source IP:Port | Destination IP:Port | Protocol | Process | 
|-----------|----------------|---------------------|----------|---------|
| | | | | |
| | | | | |

### Network Shares & Remote Access

| Share/Connection | Type | Access Time | User |
|------------------|------|-------------|------|
| | | | |
| | | | |

## 🦠 Malware/IOC Analysis

| Indicator | Type | Location | Detection Method | Context |
|-----------|------|----------|------------------|---------|
| | | | | |
| | | | | |

## 🧩 Recovery Efforts

### Deleted Files Recovered

| Filename | Path | Deletion Time | Recovery Status | Content/Relevance |
|----------|------|--------------|-----------------|-------------------|
| | | | | |
| | | | | |

## 🔐 Evidence of Security Incidents

| Date/Time | Event | Evidence Source | Significance |
|-----------|-------|-----------------|--------------|
| | | | |
| | | | |

## 📈 Timeline Analysis

*Key events in chronological order, reconstructing activity timeline*

| Date/Time | Event | Source | Significance |
|-----------|-------|--------|--------------|
| | | | |
| | | | |

## 🔀 Cross-Validation

*Document how findings were cross-validated between different evidence sources*

## 📝 Analysis Summary

### Key Findings
1. 
2. 
3. 

### Unanswered Questions
1. 
2. 
3. 

### Recommendations for Further Analysis
1. 
2. 
3. 

## 📎 Evidence Preservation

| Evidence Item | Preservation Method | Storage Location | Access Restrictions |
|---------------|---------------------|------------------|---------------------|
| | | | |
| | | | |

## 📚 Tools Used

| Tool Name | Version | Purpose | 
|-----------|---------|---------|
| | | |
| | | |

## 🧰 Technical Attachments

- [ ] Disk images
- [ ] Tool reports
- [ ] Log extracts
- [ ] Timeline files
- [ ] Screenshots
- [ ] Chain of custody forms

## 📎 Related Items

- [[Daily_Logs/{{date:YYYY-MM-DD}}]]
- [[Templates/Incident_Response/IR_Report_Template]]
- [[Cheatsheets/Systems/Windows_Forensics]]

---

> [!tip] Digital Forensics Best Practices
> 1. Always maintain chain of custody
> 2. Work from forensic copies, never original evidence
> 3. Document all steps thoroughly, including negative results
> 4. Use write blockers when acquiring evidence
> 5. Validate findings with multiple tools when possible 