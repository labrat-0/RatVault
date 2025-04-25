---
tags: [themes, obsidian, setup, reference]
date: {{date}}
author: 
version: 1.0
---

# 🎨 Recommended Themes for RatVault

> [!info] About Themes
> These themes are selected specifically for security analysts who often work in dark environments and need eye-friendly interfaces for long analysis sessions.

## 🌃 Dark Retro-Professional Themes

These themes combine a professional look with dark mode aesthetics that are ideal for security work, often with a retro/cyberpunk feel that many security professionals appreciate.

| Theme | Style | Benefits for Security Work |
|-------|-------|---------------------------|
| [Cybertron](https://github.com/nickmilo/cybertron) | Dark, neon accents, futuristic | High contrast for log analysis, retro-tech aesthetic |
| [Terminal](https://github.com/krios2146/obsidian-terminal) | Hacker-style terminal theme | Familiar terminal look, excellent for code blocks |
| [California Coast](https://github.com/mgmeyers/obsidian-california-coast-theme) | Dark blue with balanced contrast | Easy on the eyes for long analysis sessions |
| [Obsidian Nord](https://github.com/insanum/obsidian-nord) | Muted blue/dark theme | Low eye strain for night shifts |
| [Primary](https://github.com/ceciliamay/obsidianmd-theme-primary) | Clean dark theme with color options | Highly readable for documentation |
| [Solarized](https://github.com/Slowbad/obsidian-solarized) | Dark solarized color scheme | Scientific color theory for eye comfort |

## 🧩 Themes with Special Features

These themes include special features that can be particularly useful for security analysis work.

| Theme | Special Features | Benefits for Security Work |
|-------|-----------------|---------------------------|
| [Minimal](https://github.com/kepano/obsidian-minimal) | Customizable with style settings | Can be adapted to different security workflows |
| [AnuPpuccin](https://github.com/AnubisNekhet/AnuPpuccin) | Extensive customization options | Personalize for different security tasks |
| [Prism](https://github.com/damiankorcz/Prism-Theme) | Focus mode, advanced callouts | Great for incident response documentation |
| [ITS Theme](https://github.com/SlRvb/Obsidian--ITS-Theme) | Enhanced organization features | Better structure for complex security documentation |
| [Shimmering Focus](https://github.com/chrisgrieser/shimmering-focus) | Distraction-free mode, keyboard focus | Ideal for focused analysis sessions |

## 🎯 Themes with Enhanced Readability

These themes excel at making text highly readable, which is crucial when reviewing logs, code, or lengthy security reports.

| Theme | Readability Features | Benefits for Security Work |
|-------|---------------------|---------------------------|
| [Things](https://github.com/colineckert/obsidian-things) | Clean typography, excellent spacing | Makes log analysis more comfortable |
| [Dracula Official](https://github.com/dracula/obsidian) | High contrast syntax highlighting | Superior for code and script review |
| [Sanctum](https://github.com/jdanielmourao/obsidian-sanctum) | Enhanced typography, clear layout | Excellent for documentation readability |
| [Tokyo Night](https://github.com/tcmmichaelb139/obsidian-tokyonight) | Code-focused design | Perfect for script analysis and coding |

## 🛠️ Installation Instructions

1. Open Obsidian Settings
2. Navigate to "Appearance"
3. Click "Manage" under Themes
4. Search for the theme name
5. Click "Install and Use"

## ⚙️ Theme Customization

Some themes support additional customization through CSS snippets or the Style Settings plugin:

1. Install the [Style Settings](https://github.com/mgmeyers/obsidian-style-settings) plugin
2. Open Settings → Style Settings
3. Customize the active theme to your preferences

### 📝 Recommended CSS Snippets for Security Analysis

Add these snippets to your `obsidian.css` or as individual CSS snippets in the `.obsidian/snippets` folder:

#### Enhanced Code Blocks

```css
/* Better code blocks for security analysis */
.markdown-rendered pre code {
  font-family: 'Fira Code', monospace !important;
  font-size: 0.9em !important;
  line-height: 1.5 !important;
}

/* Log file formatting */
.language-log {
  font-family: 'Consolas', monospace !important;
  font-size: 0.85em !important;
  white-space: pre;
  overflow-x: auto;
}

/* Highlight important security events */
.security-alert {
  background-color: rgba(255, 82, 82, 0.1);
  border-left: 3px solid #ff5252;
  padding: 10px;
  margin: 10px 0;
}

/* IOC highlighting */
.ioc-ip { color: #ffcb6b; }
.ioc-domain { color: #89ddff; }
.ioc-hash { color: #c792ea; }
.ioc-file { color: #f78c6c; }
```

## 🔄 Theme Switching Workflow

For security analysts who work both day and night shifts, consider setting up theme switching:

1. Install the [Obsidian Advanced URI](https://github.com/Vinzent03/obsidian-advanced-uri) plugin
2. Create a note with links to switch themes:

```markdown
- [Switch to Day Theme](obsidian://advanced-uri?settingid=theme&settingvalue=Minimal)
- [Switch to Night Theme](obsidian://advanced-uri?settingid=theme&settingvalue=Cybertron)
```

## 📎 Related Items

- [[Custom_Plugins/recommended_plugins|Recommended Plugins]]
- [[Custom_Plugins/settings.json|Recommended Settings]]
- [[README|RatVault Overview]]

---

> [!tip] Theme Selection Tips
> 1. Choose a theme that reduces eye strain during long analysis sessions
> 2. Consider themes with good syntax highlighting for reviewing code
> 3. Test readability with different content types (logs, code, documentation)
> 4. Ensure good contrast for visibility of security-critical information
> 5. If using Canvas for attack mapping, test how the theme handles diagrams 