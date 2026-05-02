---
title: Getting Started with RatVault
slug: getting-started
date: 2026-05-01
summary: A simple guide to adding documents and querying your knowledge vault with LLMs.
tags: [guide, setup, howto]
---

# Getting Started with RatVault

## Adding Documents

1. Add `.md` files to the `Notes/` folder
2. Each file should be valid markdown
3. Documents are automatically indexed

Example:
```
Notes/
├── python-tips.md
├── async-patterns.md
├── machine-learning.md
```

## Querying Documents

1. Start the dashboard: `python serve.py`
2. Open `http://localhost:8000` in your browser
3. Go to **Chat**
4. Select your LLM provider in **Config**
5. Ask questions - RatVault will find relevant documents and include them as context

## Document Format

Simple markdown is all you need:

```markdown
# Document Title

Your content here...

## Section

More content...
```

RatVault extracts the title and summary automatically.

## Vault View

Click **Vault** to see all documents in your knowledge base. You can:
- Search documents by title or content
- Click to read full document content
- See document summaries

## Configuration

Click **Config** to set up your LLM:

- **Ollama** (local, free): `localhost:11434`
- **OpenAI**: Requires API key
- **Claude**: Requires API key  
- **OpenRouter**: Requires API key

---

That's it! Simple documents + powerful LLM queries = your personal knowledge vault.
