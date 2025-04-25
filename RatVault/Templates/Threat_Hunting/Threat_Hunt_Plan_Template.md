---
tags: [threat-hunting, plan, template]
date: {{date}}
status: planning
hunt_id: "TH-{{date:YYYYMMDD}}-XX"
hypothesis: 
techniques: []
data_sources: []
time_range: "last 30 days"
assigned_to: 
priority: medium
---

# 🔍 Threat Hunt Plan: {{title}}

> [!info] Hunt Information
> - **Hunt ID**: `TH-{{date:YYYYMMDD}}-XX`
> - **Status**: Planning
> - **Priority**: Medium
> - **Lead Hunter**: {{hunter}}
> - **Date Created**: {{date:YYYY-MM-DD}}
> - **Time Range**: Last 30 days

## 📝 Hunt Hypothesis

*Clearly define what threat activity you suspect might be present in your environment*

## 🎯 Objectives

*What you hope to accomplish with this hunt*

- 
- 
- 

## 🏆 Success Criteria

*What determines if this hunt was successful*

- 
- 
- 

## 📊 Threat Intelligence Context

*Relevant threat intel that informed this hunt*

> [!note] Intelligence Sources
> - CTI Report: 
> - Previous Incidents: 
> - Industry Alerts:

## 🧠 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Sub-technique |
|--------|--------------|----------------|---------------|
| | | | |
| | | | |

## 💾 Data Sources

| Data Source | Location | Retention Period | Notes |
|-------------|----------|------------------|-------|
| | | | |
| | | | |

## 🔮 Hunt Methodology

### Approach

*The general hunting approach (hypothesis-driven, TTP-based, anomaly detection, etc.)*

### Data Collection

*What data needs to be gathered and how*

### Detection Logic

*Detection queries, log search patterns, or analytics*

#### KQL Query Examples

```kql
// Query 1: Description
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == "4624"
// Add more filtering
```

```kql
// Query 2: Description
```

#### PowerShell Collection Script

```powershell
# Example collection script
```

### Analysis Process

*How the data will be analyzed and reviewed*

## 🚨 Possible Findings & Escalation

| Finding | Severity | Escalation Path | Notes |
|---------|----------|-----------------|-------|
| | | | |
| | | | |

## 📅 Timeline & Resources

| Phase | Start Date | End Date | Resources | Deliverables |
|-------|------------|----------|-----------|--------------|
| Planning | {{date:YYYY-MM-DD}} | | | Hunt plan document |
| Data Collection | | | | Raw data sets |
| Analysis | | | | Findings report |
| Remediation | | | | |

## 📎 Related Items

- [[Threat Intel/Threat_Actors/{{related threat actor}}]]
- [[Cheatsheets/Query_Languages/KQL_Cheatsheet]]
- [[Cheatsheets/Systems/Windows_Event_Logs]]

---

> [!tip] Hunt Journal
> Document all steps, tools, techniques, and findings in the [[Daily Logs/{{date:YYYY-MM-DD}}|Daily Log]] as you proceed with this hunt. 