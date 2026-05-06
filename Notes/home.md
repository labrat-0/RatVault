---
title: "RatVault Home"
slug: "home"
created: "2026-05-02"
ingested_at: "2026-05-05T17:20:00Z"
category: "reference"
type: "reference"
tags: ["index", "overview", "wiki", "home"]
related: ["getting-started", "ai-llm-docs", "python-cheatsheet", "bash-cheatsheet"]
---

# 🐀 RatVault — Your Persistent Knowledge Vault

![Local](https://img.shields.io/badge/Local-First-3da26f?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-3da26f?style=flat-square)
![LLM](https://img.shields.io/badge/LLM-Optional-666?style=flat-square)
![Obsidian](https://img.shields.io/badge/Obsidian-Compatible-666?style=flat-square)
![Mobile](https://img.shields.io/badge/Mobile-Termux-3da26f?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-3da26f?style=flat-square)

> A personal wiki that grows smarter with every source you add.
> Inspired by [Andrej Karpathy's "LLM Wiki" pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f) — a **persistent, compounding knowledge artifact**, not a re-derived RAG result.

---

## ⚡ How It Works

```
inbox/  →  Python indexing (always)  →  Notes/
            ▲
            └── (optional) LLM enrichment overlay
```

**Three layers**

| Layer | What | Purpose |
|---|---|---|
| `inbox/` | Raw sources you drop in | Markdown, text, PDFs, images, videos |
| `Notes/` | LLM-enriched wiki | One markdown file per entity/concept |
| `config.yaml` | Provider + model | Schema layer |

**Three operations**

| Op | What it does |
|---|---|
| **Ingest** | Process new sources → integrate into wiki with cross-references |
| **Query** | Chat over the wiki and get context-aware answers |
| **Lint** | Check for orphaned pages and broken links *(coming soon)* |

---

## 🚀 Get Started

```bash
# 1. Drop a source
echo "# My Research" > inbox/my-research.md

# 2. Index it (no LLM required)
python ingest.py --provider none

# 3. Open dashboard
python serve.py
# → http://localhost:8055
```

That's it. No API key, no internet, no model. Add an LLM later for richer summaries — never required.

---

## 📚 Featured Pages

| Page | Tags |
|---|---|
| [AI & LLM Documentation Hub](ai-llm-docs) | `ai` `llm` `docs` |
| [Getting Started Guide](getting-started) | `setup` `howto` |
| [Python Cheatsheet](python-cheatsheet) | `python` `programming` |
| [Bash Cheatsheet](bash-cheatsheet) | `bash` `shell` |

---

## 📐 Wiki Conventions

Every page has:

- **Frontmatter** — metadata (title, slug, tags, related pages)
- **Definition** — what is this?
- **Properties** — key attributes
- **Relationships** — links to related concepts
- **Sources** — where the info came from

See [`readme-structure.md`](README-STRUCTURE) for the full guide.

---

## 🧠 Key Principles

- ⚙ **Compilation over retrieval** — built once, kept current
- 🔗 **Persistent cross-references** — links survive and strengthen over time
- 👤 **Human direction + LLM execution** — you manage sources, AI handles synthesis
- 📋 **Frontmatter as truth** — tags, categories, and relationships live in metadata

---

## ⚙ Configuration

Manage providers and models in the **Config** tab of the dashboard, or in `config.yaml`:

| Provider | Local? | Best for |
|---|---|---|
| `none` | n/a | Pure Python deterministic indexing |
| `ollama` | ✅ | Recommended local default — `mistral:7b-instruct` |
| `openai` | ❌ | Highest-quality enrichment + vision chat |
| `anthropic` | ❌ | Long-context summaries |
| `openrouter` | ❌ | One key, many models |

---

## 🔗 Quick Links

- 🌐 **Dashboard:** http://localhost:8055
- 🏗 **Architecture:** see `CLAUDE.md` in the repo root
- 📝 **Page template:** `readme-structure.md`
- 💻 **Source:** [github.com/labrat-0/RatVault](https://github.com/labrat-0/RatVault)

---

<sub>Last updated: 2026-05-05 · Built for fast, local, private knowledge work.</sub>
