---
tags: [home, dashboard]
banner: "![[banner.png]]"
banner_x: 0.5
banner_y: 0.5
created: {{date}}
updated: {{date}}
---

<div align="center">
  <pre>
    ██████╗  █████╗ ████████╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
    ██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
    ██████╔╝███████║   ██║   ██║   ██║███████║██║   ██║██║     ██║   
    ██╔══██╗██╔══██║   ██║   ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
    ██║  ██║██║  ██║   ██║    ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
  </pre>

  <h3>Security Analyst's Knowledge Vault</h3>
  <h4>Created by <a href="https://github.com/labrat-0">Mick Donahue (@labrat-0)</a></h4>

  <a href="https://github.com/labrat-0"><img src="https://img.shields.io/badge/GitHub-@labrat--0-181717?style=for-the-badge&logo=github&logoColor=white"></a>&nbsp;&nbsp;
  <a href="https://buymeacoffee.com/labrat"><img src="https://img.shields.io/badge/Support_My_Work-Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black"></a>
</div>

# 🏠 Welcome to RatVault

Welcome to RatVault, your comprehensive knowledge base and toolkit for security analysis! This vault contains templates, cheatsheets, tool guides, and more to help you with security operations, incident response, and threat intelligence.

## 🗺️ Quick Navigation

| Category | Description | Links |
|----------|-------------|-------|
| 📋 **Templates** | Ready-to-use templates for various security tasks | [[Templates/Incident_Response/IR_Report_Template\|IR Report]], [[Templates/Malware_Analysis/Malware_Triage_Template\|Malware Analysis]], [[Templates/Daily_Logs/Daily_Security_Operations_Log\|Daily Log]] |
| 📝 **Cheatsheets** | Quick reference for commands, syntax, and procedures | [[Cheatsheets/Scripting/PowerShell_Cheatsheet\|PowerShell]], [[Cheatsheets/Query_Languages/KQL_Cheatsheet\|KQL]], [[Cheatsheets/Systems/Windows_Event_Logs\|Windows Event Logs]] |
| 🛠️ **Tool Guides** | How to use common security tools effectively | [[Tool_Guides/Endpoint_Analysis/Sysinternals_Guide\|Sysinternals]], [[Tool_Guides/Network_Analysis/Wireshark_Guide\|Wireshark]] |
| 🔍 **Threat Intel** | Threat intelligence resources and tracking | [[Threat_Intel/IOCs/IOC_Collection\|IOC Collection]], [[Threat_Intel/YARA_Rules/Example_Rules\|YARA Rules]] |
| 📊 **Dashboards** | Visual dashboards for security operations | [[Canvas_Dashboards/SOC_Dashboard\|SOC Dashboard]], [[Canvas_Dashboards/Threat_Hunting_Dashboard\|Threat Hunting]] |

## 📌 Getting Started

If you're new to RatVault, here are some suggested starting points:

1. Read the [[about|About RatVault]] page
2. Explore the [[README|README]] for usage tips
3. Check out the [[Templates/Daily_Logs/Daily_Security_Operations_Log|Daily Log Template]] to start your security journaling
4. Browse the [[Cheatsheets/Systems/Microsoft_Security_Tools|Microsoft Security Tools]] overview
5. Learn about [[Cheatsheets/Systems/Windows_Event_Logs|Windows Event Logs]] for security analysis

## 🔄 Recent Updates

```dataview
TABLE file.mtime as "Last Modified"
FROM "Cheatsheets" OR "Templates" OR "Tool_Guides"
SORT file.mtime DESC
LIMIT 5
```

## 🔗 External Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS Internet Storm Center](https://isc.sans.edu/)
- [Microsoft Security Blog](https://www.microsoft.com/security/blog/)
- [The DFIR Report](https://thedfirreport.com/)
- [Red Canary Blog](https://redcanary.com/blog/)

---

<div align="right">
  <p>Created with 💖 by <a href="https://github.com/labrat-0">Mick Donahue</a></p>
</div> 