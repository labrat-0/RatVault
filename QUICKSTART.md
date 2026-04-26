# RatVault Quick Start Guide

## The Workflow

1. **Create markdown files** in `inbox/` folder with your notes
2. **Run ingest pipeline** to process them into the vault
3. **Chat with vault** using the web dashboard to ask questions

## Step 1: Create a Test Note

Create `inbox/test-python.md`:

```markdown
---
title: Python Basics
summary: Essential Python concepts for beginners
tags: [python, learning, basics]
---

# Python Fundamentals

## Variables
Variables store data. Python is dynamically typed.

```python
name = "Alice"
age = 30
score = 95.5
```

## Data Types
- `str` - Text
- `int` - Whole numbers
- `float` - Decimal numbers
- `list` - Ordered collection
- `dict` - Key-value pairs

## Functions
```python
def greet(name):
    return f"Hello, {name}!"
```

## If/Else
```python
if age >= 18:
    print("Adult")
else:
    print("Minor")
```
```

## Step 2: Run Ingest Pipeline

```bash
# First time setup (choose your LLM provider)
python ingest.py --setup

# Dry run to preview what will happen
python ingest.py --dry-run

# Actually ingest the files
python ingest.py
```

The pipeline will:
- Read your markdown from `inbox/`
- Extract frontmatter (title, summary, tags)
- Process with your LLM to enhance content
- Save to `Notes/` as vault entries
- Update Obsidian indexes

## Step 3: Use the Web Dashboard

```bash
# Start the server (or it's already running on 8055)
python ingest.py --serve
```

Then:
1. Open `http://localhost:8055` in your browser
2. Click **Settings** (⚙) to choose your LLM provider and model
3. In the **Chat** tab, ask questions like:
   - "What are Python data types?"
   - "How do I write a Python function?"
   - "Explain Python variables"

The chat will search your vault and reference relevant entries when answering.

## What Gets Created

```
RatVault/
├── inbox/              # Drop markdown files here
│   └── test-python.md
├── Notes/              # Processed vault entries
│   └── python-basics.md
├── dashboard/          # Web interface
└── .obsidian/          # Obsidian configuration
```

## Using Different LLM Providers

### Local (Ollama)
```bash
python ingest.py --setup
# Choose: ollama
# Model: llama2, mistral, neural-chat, etc.
```

### OpenAI
```bash
OPENAI_API_KEY=sk-... python ingest.py --setup
# Choose: openai
# Model: gpt-4, gpt-3.5-turbo, etc.
```

### Anthropic (Claude)
```bash
ANTHROPIC_API_KEY=sk-ant-... python ingest.py --setup
# Choose: anthropic
# Model: claude-opus, claude-sonnet, etc.
```

### OpenRouter (Any model)
```bash
OPENROUTER_API_KEY=... python ingest.py --setup
# Choose: openrouter
# Model: Any model from OpenRouter catalog
```

## Markdown Format

Minimum example:
```markdown
---
title: My Topic
summary: One line description
tags: [tag1, tag2]
---

# Heading

Your content here.
```

Full format with all fields:
```markdown
---
title: My Topic
summary: One sentence description
tags: [tag1, tag2, tag3]
category: development  # security, development, research, personal, reference, workflow
difficulty: intermediate  # beginner, intermediate, advanced
key_concepts: [concept1, concept2]
questions_answered: [question1, question2]
---

# Content
```

## Troubleshooting

**"Model not found" error in chat?**
- Make sure Ollama is running: `ollama serve`
- Or switch to OpenAI/Anthropic in Settings

**Files not ingesting?**
- Check they're in `inbox/` folder
- Make sure they have `.md` extension
- Verify frontmatter is valid YAML

**Can't see vault entries in chat?**
- Run `python ingest.py` to process files
- Check `Notes/` folder exists with entries
- Try searching with keywords from your notes

## Next Steps

- Add more markdown files to `inbox/`
- Open vault in Obsidian for beautiful note-taking
- Configure backlinks and cross-references
- Export vault entries to other formats
