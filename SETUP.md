# RatVault Complete Setup

## What Works Now

✅ **Dashboard UI** - Live at `http://localhost:8055`  
✅ **Vault ingestion** - Process markdown files  
✅ **RAG chat** - Chat searches vault + queries LLM  
✅ **Multi-view** - Chat, Search, Analytics, Settings  
✅ **Multi-LLM** - OpenAI, Anthropic, Ollama, OpenRouter  

## The Complete Workflow

```
inbox/example.md  →  python ingest.py  →  Notes/example.md  →  Dashboard Chat (with RAG)
     (write note)       (process)           (vault entry)        (search + answer)
```

## Option 1: Quick Test (No Setup Required)

Your vault already has **7 test entries**. Try the chat now:

1. Open `http://localhost:8055`
2. Click **Search** tab → Try "Python" or "multi-llm"
3. See it returns relevant vault entries immediately

**This works without any LLM** — pure vault search.

---

## Option 2: Enable Chat (5 minutes)

### A. Use Local Ollama (Recommended for Privacy)

```bash
# 1. Install Ollama from ollama.ai
# 2. Run Ollama service
ollama serve

# 3. In another terminal, pull a model
ollama pull mistral
# or
ollama pull llama2
# or
ollama pull neural-chat
```

### B. Use OpenAI (Instant, No Install)

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Configure
python ingest.py --setup
# Choose: openai
# Model: gpt-3.5-turbo (cheap) or gpt-4 (powerful)
```

### C. Use Anthropic (Claude)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python ingest.py --setup
# Choose: anthropic
# Model: claude-opus or claude-sonnet
```

### D. Use OpenRouter (50+ Models)

```bash
export OPENROUTER_API_KEY="..."
python ingest.py --setup
# Choose: openrouter
# Model: Pick any from catalog
```

---

## Test the Full Workflow

### Step 1: Add Your First Note

Create `inbox/my-topic.md`:

```markdown
---
title: My First Topic
summary: A brief description
tags: [learning, test]
---

# My Topic

Write anything here. Explain concepts, code examples, anything.

## Section
Details...
```

### Step 2: Ingest Into Vault

```bash
# See what will happen
python ingest.py --dry-run

# Actually process
python ingest.py
```

You should see:
```
✓ inbox/my-topic.md → Notes/my-first-topic.md
✓ Frontmatter extracted
✓ LLM enhancing content (if using chat)
✓ Saved to vault
```

### Step 3: Try the Dashboard

1. Open `http://localhost:8055`
2. Go to **Settings** (⚙) → Choose LLM provider & model
3. **Chat** tab → Ask: "What did I write about in my topic?"
4. It searches vault + uses LLM to answer

---

## Upload Images with Descriptions

RatVault auto-extracts images from markdown:

```markdown
---
title: My Design
summary: Explanation with images
tags: [design, ui]
---

# My Design

Here's a screenshot:

![Alt text describing the image](images/screenshot.png)

More text explaining what you see...
```

Images are automatically:
- Extracted to `assets/images/`
- Linked in vault entries
- Available in dashboard gallery

---

## What Each Command Does

```bash
python ingest.py --setup
# Interactive config: choose provider, model, API keys

python ingest.py --dry-run
# Preview: show what files will be processed, don't change anything

python ingest.py
# Go: read inbox/, process with LLM, save to Notes/

python ingest.py --serve
# Start dashboard at http://localhost:8055

python ingest.py --force
# Re-process already-processed files (ignore timestamps)

python ingest.py --provider ollama --model mistral
# Override config for this run only
```

---

## Verify It's Working

### Check Vault Has Entries

```bash
ls -la Notes/
# Should show multiple .md files
```

### Check Ingestion Worked

```bash
cat Notes/*.md | head -20
# Should see YAML frontmatter at top
```

### Check Search API

```bash
curl http://localhost:8055/api/search?q=python | jq .
# Should return results
```

### Check Chat API

```bash
curl -X POST http://localhost:8055/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"What topics are in the vault?","history":[]}' | jq .
# Will error if no LLM, but shows sources it found
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Chat says "model not found" | Ollama not running: `ollama serve` |
| Ingest stuck/slow | Check LLM connection. Use `--dry-run` first |
| Files not ingesting | Make sure they're in `inbox/` with `.md` extension |
| Can't find search results | Files in `Notes/` = searchable. Run `python ingest.py` |
| Settings not saving | Refresh browser, check localStorage in DevTools |

---

## Architecture Overview

```
RatVault/
├── inbox/                  # Drop .md files here
├── Notes/                  # Processed vault (searchable)
├── dashboard/              # Web UI
│   ├── index.html         # Main interface
│   ├── sw.js              # Service worker (offline)
│   └── manifest.json      # PWA metadata
├── pipeline/
│   ├── ingest.py          # Main ingestion CLI
│   ├── providers.py       # LLM provider abstraction
│   ├── parser.py          # Markdown frontmatter parser
│   ├── media.py           # Image/video extraction
│   ├── writer.py          # Vault entry writer
│   ├── config.py          # Config management
│   ├── models.py          # Data models
│   └── prompts.py         # LLM system prompts
├── serve.py               # FastAPI backend
└── config.yaml            # User config (created by --setup)
```

---

## Next Steps

1. **Add a few notes** - Create markdown files in `inbox/`
2. **Run ingest** - `python ingest.py`
3. **Chat with vault** - Open dashboard, ask questions
4. **View in Obsidian** - Open root as vault for beautiful editing
5. **Configure cross-refs** - Link entries with `[[note-name]]` syntax
