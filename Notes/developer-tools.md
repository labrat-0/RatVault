---
title: "Essential Developer Tools"
slug: "developer-tools"
created: "2026-04-25"
ingested_at: "2026-04-25T00:00:00Z"
summary: "Curated list of tools indie hackers use daily: editors, terminals, version control, and productivity"
tags: [tools, editors, productivity, indie-hacker, reference]
category: development
difficulty: beginner
key_concepts: [neovim, lazyvim, tmux, git, cli-tools]
questions_answered: [what-is-nvim, why-neovim, lazyvim-vs-nvim]
provider: manual
status: active
type: reference
---

# Essential Developer Tools

## Editors & IDEs

### Neovim
Modern extension of Vim with Lua-based configuration, built-in LSP support, and treesitter integration.

```bash
# Install
brew install neovim        # macOS
sudo pacman -S neovim      # Arch Linux
apt-get install neovim     # Debian/Ubuntu

# Basic usage
nvim filename.txt
:e file.txt                # Open file
:w                         # Save
:q                         # Quit
:wq                        # Save and quit
```

**Resources:** [Neovim](https://neovim.io), [Vim Cheatsheet](https://vim.rtorr.com)

### LazyVim
Opinionated Neovim configuration framework with batteries included: LSP, autocompletion, fuzzy finder, treesitter.

```bash
# Install LazyVim
git clone https://github.com/LazyVim/starter ~/.config/nvim
nvim                       # Opens with all plugins auto-installed
```

**Why LazyVim:** Pre-configured LSP, package management with lazy.nvim, sensible defaults that work out-of-the-box.

**Resources:** [LazyVim](https://www.lazyvim.org), [GitHub](https://github.com/LazyVim/LazyVim)

### VS Code
Lightweight, extensible IDE with excellent language support and marketplace.

```bash
# Install
brew install visual-studio-code    # macOS
snap install code                  # Linux
choco install vscode               # Windows

# Useful extensions
code --install-extension ms-python.python
code --install-extension dbaeumer.vscode-eslint
code --install-extension GitHub.copilot
```

**Resources:** [VS Code](https://code.visualstudio.com), [Extensions Marketplace](https://marketplace.visualstudio.com)

---

## Terminal Multiplexers

### Tmux
Terminal multiplexer allowing multiple windows, panes, and persistent sessions.

```bash
# Installation
brew install tmux          # macOS
sudo pacman -S tmux        # Arch Linux

# Basic commands
tmux new-session -s myapp              # Create session
tmux list-sessions                     # List sessions
tmux attach -t myapp                   # Attach to session
Ctrl+b c                               # Create new window
Ctrl+b % or Ctrl+b "                  # Split pane
Ctrl+b d                               # Detach
tmux kill-session -t myapp             # Kill session

# Configuration: ~/.tmux.conf
set -g prefix C-a                      # Change prefix to Ctrl+a
set -g mouse on                        # Enable mouse
set -g pane-border-status bottom       # Show pane titles
```

**Resources:** [Tmux GitHub](https://github.com/tmux/tmux), [Tmux Cheatsheet](https://tmuxcheatsheet.com)

---

## Version Control

### Git
Distributed version control system for tracking code changes.

```bash
# Installation
brew install git           # macOS
sudo pacman -S git         # Arch Linux

# Basic workflow
git init                   # Initialize repo
git add .                  # Stage changes
git commit -m "message"    # Create commit
git push origin main       # Push to remote
git pull                   # Fetch and merge
git clone <url>            # Clone repo

# Branches
git branch -a              # List all branches
git checkout -b feature    # Create and switch branch
git merge feature          # Merge branch
git branch -d feature      # Delete branch

# History
git log --oneline          # View commit history
git diff                   # See unstaged changes
git log -p --follow file   # File history with changes
```

**Resources:** [Git Book](https://git-scm.com/book), [GitHub Docs](https://docs.github.com)

### GitHub / GitLab / Gitea
Git hosting platforms with collaboration features.

**GitHub:** Most popular, excellent for open source.
```bash
# Clone and contribute
git clone https://github.com/user/repo
git checkout -b fix-issue-123
git push origin fix-issue-123
# Create PR via web interface
```

**GitLab:** Strong CI/CD integration, self-hosted option.

**Gitea:** Lightweight, self-hosted Git service.

**Resources:** [GitHub](https://github.com), [GitLab](https://gitlab.com), [Gitea](https://gitea.io)

---

## CLI Tools

### curl
Fetch web content and APIs from command line.

```bash
curl https://api.example.com
curl -X POST https://api.example.com -d "key=value"
curl -H "Authorization: Bearer TOKEN" https://api.example.com
curl -o filename.txt https://example.com/file.txt
curl -L https://example.com/redirect                 # Follow redirects
```

**Resources:** [curl Man Page](https://curl.se/docs/manpage.html)

### jq
Parse and manipulate JSON.

```bash
# Pretty-print JSON
echo '{"name":"Alice","age":30}' | jq .

# Extract field
echo '{"name":"Alice"}' | jq .name

# Filter array
curl https://api.example.com/items | jq '.items[] | select(.status=="active")'

# Transform
echo '[{"name":"Alice","age":30}]' | jq '.[] | {name, adult: (.age >= 18)}'
```

**Resources:** [jq Manual](https://stedolan.github.io/jq/manual/)

### grep / ripgrep
Search text patterns.

```bash
# grep - classic text search
grep "pattern" file
grep -r "pattern" .         # Recursive search
grep -i "pattern" file      # Case-insensitive
grep -l "pattern" *.txt     # List matching files

# ripgrep (rg) - faster, modern grep
rg "pattern"
rg "pattern" --type py      # Search only Python files
rg -i "pattern"
```

**Resources:** [ripgrep GitHub](https://github.com/BurntSushi/ripgrep)

### fzf
Fuzzy finder for interactive searching.

```bash
# Fuzzy file finder
fzf

# Fuzzy search history
Ctrl+R                      # In bash/zsh

# Fuzzy search and pipe
cat file.txt | fzf

# Integrate with vim
:FzfFiles                   # Requires vim plugin
```

**Resources:** [fzf GitHub](https://github.com/junegunn/fzf)

---

## Package Managers

### pip (Python)
Python package manager.

```bash
pip install package_name
pip install --upgrade package_name
pip list
pip freeze > requirements.txt
pip install -r requirements.txt

# Virtual environment
python3 -m venv venv
source venv/bin/activate
deactivate
```

**Resources:** [pip Documentation](https://pip.pypa.io)

### npm (Node.js)
JavaScript package manager.

```bash
npm init                    # Create package.json
npm install package_name
npm install --save-dev package_name
npm list
npm update

# Package scripts
npm run build
npm run test
npm run dev
```

**Resources:** [npm Docs](https://docs.npmjs.com)

### Homebrew (macOS)
Package manager for macOS and Linux.

```bash
brew install formula
brew search query
brew list
brew upgrade
brew uninstall package

# Cask (GUI apps)
brew install --cask app-name
```

**Resources:** [Homebrew](https://brew.sh)

---

## Productivity & Knowledge Management

### Notion
All-in-one workspace for notes, databases, and team collaboration.

**Features:**
- Databases with filtering and sorting
- Templates for common patterns
- Team collaboration
- Integration with 100+ tools

**Resources:** [Notion](https://www.notion.so)

### Obsidian
Local-first markdown notes with linking, backlinks, and graph visualization.

**Features:**
- Vault-based organization
- Bidirectional linking
- Dataview plugin for dynamic queries
- Community plugins ecosystem
- Sync available (optional)

**Resources:** [Obsidian](https://obsidian.md), [Community](https://obsidian.md/community)

### GitHub Copilot
AI pair programmer powered by OpenAI Codex.

```bash
# Install
# VS Code: Install "GitHub Copilot" extension
# Neovim: https://github.com/github/copilot.vim

# Usage
# Start typing, Copilot suggests completions
# Tab to accept, Escape to dismiss
```

**Resources:** [GitHub Copilot](https://github.com/features/copilot)

### RatLabs.tech
Personal platform for technical content and tooling.

**Features:**
- Curated tutorials and guides
- Code snippets and boilerplates
- Community-driven resources
- Integration with RatVault knowledge system

**Resources:** [RatLabs.tech](https://ratlabs.tech)

---

## Developer Communities & Resources

- **Stack Overflow:** Q&A for developers [stackoverflow.com](https://stackoverflow.com)
- **Dev.to:** Developer community and blogging [dev.to](https://dev.to)
- **Hacker News:** Tech news and discussion [news.ycombinator.com](https://news.ycombinator.com)
- **GitHub Discussions:** Project communities [github.com](https://github.com)
- **Indie Hackers:** Build and share projects [indiehackers.com](https://www.indiehackers.com)

---

## Recommended Workflow

```bash
# 1. Use git for version control
git init && git add . && git commit -m "initial commit"

# 2. Choose an editor
# - Quick edits: Neovim/LazyVim
# - Full IDE: VS Code
# - Team work: VS Code with Remote Development

# 3. Organize work in terminal
tmux new-session -s work
# Create windows and panes for different tasks

# 4. Manage knowledge
# - Code changes: Git logs
# - Architecture: Obsidian vault
# - Team knowledge: Notion
# - Personal learning: RatLabs.tech

# 5. Automate with CLI
curl -X POST https://api.example.com | jq '.result' | grep "success"
```
