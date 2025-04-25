---
tags: [plugins, obsidian, setup, reference]
date: {{date}}
author: 
version: 1.0
---

# 🔌 Recommended Plugins for RatVault

> [!info] About Plugins
> These plugins enhance your Obsidian experience specifically for security analysis workflows. Install them from Settings → Community plugins → Browse.

## 📋 Essential Plugins

| Plugin | Purpose | Security Use Cases |
|--------|---------|-------------------|
| [Dataview](https://github.com/blacksmithgu/obsidian-dataview) | Query and display data from notes | Create dashboards of incidents, IOCs, or threat intelligence |
| [Templater](https://github.com/SilentVoid13/Templater) | Enhanced templates with scripting | Automate creation of standardized security reports |
| [Calendar](https://github.com/liamcain/obsidian-calendar-plugin) | Calendar view for daily notes | Track daily SOC activities and incidents over time |
| [Excalidraw](https://github.com/zsviczian/obsidian-excalidraw-plugin) | Diagram creation | Create attack flow diagrams and network maps |
| [Tasks](https://github.com/obsidian-tasks-group/obsidian-tasks) | Task management | Track security tasks, remediation efforts, and follow-ups |
| [Kanban](https://github.com/mgmeyers/obsidian-kanban) | Visual task management | Manage incident workflow and investigation status |
| [Advanced Tables](https://github.com/tgrosinger/advanced-tables-obsidian) | Improved table editing | Better management of indicator tables and event timelines |

## 🛠️ Additional Helpful Plugins

| Plugin | Purpose | Security Use Cases |
|--------|---------|-------------------|
| [Mind Map](https://github.com/lynchjames/obsidian-mind-map) | Visual mind maps from notes | Map attack paths and threat actor TTPs |
| [Timeline](https://github.com/George-debug/obsidian-timeline) | Create visual timelines | Document incident timelines and attack sequences |
| [Admonition](https://github.com/valentine195/obsidian-admonition) | Create callout blocks | Highlight important security alerts and warnings |
| [QuickAdd](https://github.com/chhoumann/quickadd) | Quickly add content | Rapidly document security events and observations |
| [Outliner](https://github.com/vslinko/obsidian-outliner) | Enhance lists and outlines | Better structure for procedure documents and checklists |
| [Git](https://github.com/denolehov/obsidian-git) | Git integration | Version control your security documentation |
| [Advanced URI](https://github.com/Vinzent03/obsidian-advanced-uri) | Advanced URI capabilities | Link between notes with specific parameters |
| [Day Planner](https://github.com/lynchjames/obsidian-day-planner) | Day planning and time tracking | Track time spent on security investigations |
| [Periodic Notes](https://github.com/liamcain/obsidian-periodic-notes) | Create periodic notes | Standard weekly/monthly security reviews |
| [Buttons](https://github.com/shabegom/buttons) | Create buttons in notes | Automate common security workflows |
| [Database Folder](https://github.com/RafaelGB/obsidian-db-folder) | Create database from folder | Manage collections of IOCs or vulnerabilities |

## 🔍 Data Analysis Plugins

| Plugin | Purpose | Security Use Cases |
|--------|---------|-------------------|
| [Obsidian Query Language](https://github.com/jplattel/obsidian-query-language) | Advanced querying | Complex queries for security data analysis |
| [Charts](https://github.com/phibr0/obsidian-charts) | Data visualization | Visualize security metrics and trends |
| [Dataview JS](https://blacksmithgu.github.io/obsidian-dataview/) | JavaScript for dataview | Create advanced security dashboards |
| [MetaEdit](https://github.com/chhoumann/MetaEdit) | Edit frontmatter easily | Quickly update status of security cases |

## 🔒 Useful Security-Specific Plugins

| Plugin | Purpose | Security Use Cases |
|--------|---------|-------------------|
| [Regex Find/Replace](https://github.com/Gru80/obsidian-regex-replace) | Regex search and replace | Clean up log data and standardize formats |
| [Text Format](https://github.com/Benature/obsidian-text-format) | Format text | Format IOCs and other technical data |
| [Markdown Table Editor](https://github.com/ganesshkumar/obsidian-table-editor) | Edit markdown tables | Manage complex data tables of security information |
| [Highlightr](https://github.com/chetachiezikeuzor/Highlightr-Plugin) | Advanced highlighting | Highlight important findings in security logs |
| [Dice Roller](https://github.com/javalent/dice-roller) | Roll dice and generate random data | Generate test data or random sampling for security testing |

## 🚀 Installation and Setup

1. Open Obsidian Settings
2. Navigate to "Community plugins"
3. Turn off "Safe mode" (if prompted)
4. Click "Browse" to open the plugin browser
5. Search for the plugin by name
6. Click "Install"
7. Enable the plugin after installation

## ⚙️ Plugin Configuration

After installing plugins, follow these steps for optimal security workflow:

1. **Dataview**: Enable JavaScript queries and inline queries
2. **Templater**: Set template folder to `Templates` and enable folder templates
3. **Calendar**: Configure to work with Daily Logs
4. **Tasks**: Customize task formats for security workflow states
5. **Git**: Set up automatic backups if using for team collaboration

## 📎 Related Items

- [[Custom_Plugins/settings.json|Recommended Settings File]]
- [[README|RatVault Overview]]
- [[Templates/README|Templates Overview]]

---

> [!tip] Plugin Best Practices
> 1. Only install plugins you actually need
> 2. Keep plugins updated regularly
> 3. Be cautious with plugins that require external connections if working with sensitive data
> 4. Check plugin settings after Obsidian updates
> 5. Maintain backups before installing new plugins 