---
title: "RatVault Home"
slug: "home"
created: "2026-05-02"
ingested_at: "2026-05-02T12:00:00Z"
category: "reference"
type: "reference"
tags: ["index", "overview"]
related: []
---

# RatVault — Your Persistent Knowledge Vault

A personal wiki that grows smarter with every source you add. Following [Andrej Karpathy's LLM Wiki pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).

## How It Works

**Three layers**:
1. **Raw Sources** (`inbox/`) — Your notes, articles, research
2. **The Wiki** (`Notes/`) — AI-generated, interconnected knowledge base
3. **The Schema** — Guidelines and configuration

**Three operations**:
- **Ingest**: Process new sources → integrate into wiki with cross-references
- **Query**: Chat to search the wiki and get context-aware answers
- **Lint**: Check for orphaned pages and broken links (coming soon)

## Get Started

1. Add `.md` files to `inbox/`
2. Run: `python ingest.py`
3. Chat with your vault in the web dashboard
4. Update `Notes/` pages directly for manual refinement

## Wiki Conventions

Every page has:
- **Frontmatter**: metadata (title, slug, tags, related pages)
- **Definition**: what is this?
- **Properties**: key attributes
- **Relationships**: links to related concepts
- **Sources**: where the info came from

See `README-STRUCTURE.md` for the full guide.

## Example Pages

The wiki includes structured knowledge on:

- [AI & LLM Documentation Hub](ai-llm-docs)
- [Getting Started Guide](getting-started)
- [Developer Tools](developer-tools)
- [Python Cheatsheet](python-cheatsheet)
- [Bash Cheatsheet](bash-cheatsheet)

## Building Your Wiki

Start with a topic you care about:

1. Create `inbox/my-research.md` with notes
2. Run `python ingest.py`
3. RatVault creates `Notes/my-topic.md` with:
   - Structured outline
   - Key concepts extracted
   - Cross-references to existing pages
4. Query: "Tell me about my-topic" → villa returns context-rich answer

With each new source, the wiki gets **richer, more connected, and more valuable**.

## Key Principles

- **Compilation over retrieval**: Built once, kept current (not re-derived per query)
- **Persistent cross-references**: Links survive and strengthen over time
- **Human direction + LLM execution**: You manage sources, AI handles synthesis
- **Frontmatter as truth**: Tags, categories, and relationships live in metadata

## Configuration

Manage providers and models in the dashboard or `config.yaml`:
- **Ollama** (local, recommended)
- **OpenAI**, **Anthropic**, **OpenRouter**

See `CLAUDE.md` for full architecture documentation.

---

**Dashboard**: http://localhost:8055  
**Architecture**: See `CLAUDE.md`  
**Structure Guide**: See `README-STRUCTURE.md`  
**Template**: Use `TEMPLATE-ENTITY.md` for new pages  

Last updated: 2026-05-02
