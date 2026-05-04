<div align="center">
  <img src="dashboard/logo-256.png" alt="RatVault" width="180">
  <h1>RatVault</h1>
  <p><strong>Local LLM-powered knowledge wiki — drop sources in, get a structured, queryable wiki out.</strong></p>
  <p><em>Inspired by Karpathy's "persistent, compounding knowledge artifact" pattern.</em></p>
</div>

![intro](assets/images/rat-vault-intro-site.png)

---

## What it does

RatVault turns a folder of raw sources (`.md`, `.txt`, `.pdf`, images) into a structured, cross-referenced wiki. An LLM enriches each ingested file with frontmatter (title, slug, tags, summary, key concepts), and a web dashboard lets you browse, edit, search, and chat against the vault.

Three layers, one workflow:

| Layer | What | Purpose |
|---|---|---|
| `inbox/` | Raw sources, append-only | Where you drop new material |
| `Notes/` | LLM-enriched markdown | The wiki — one file per entity/concept |
| `config.yaml` | Provider + model config | Schema layer |

Three operations: **ingest**, **query**, **lint**.

---

## Features

- **Web dashboard** at `http://localhost:8055` — Chat, Vault browser, Config, file viewer
- **Multi-provider LLM** — Ollama (local), OpenAI, Anthropic, OpenRouter
- **PDF + image ingest** — PDFs embed inline in their wiki note; images copy to `assets/` and link in
- **Live edit + preview** — split-pane markdown editor with live HTML preview
- **Save back to inbox** — edits in the wiki are written back to `inbox/` so the next reindex picks them up
- **In-app file viewer** — preview PDFs, images, video, audio, text without leaving the dashboard
- **Vision chat** — attach images to chat for vision-capable models (GPT-4o, Claude 3+, OpenRouter VLMs)
- **Theme + screenshot** — accent color cycling, dashboard snapshot button
- **API key safety** — pre-commit hook blocks any commit containing API key patterns; `config.yaml` is gitignored

---

## Quick start

```bash
git clone https://github.com/labrat-0/RatVault.git
cd RatVault
pip install -r requirements.txt

# Optional: configure provider/model
cp config.yaml.example config.yaml
# edit config.yaml — set provider: ollama|openai|anthropic|openrouter

# Start dashboard
python serve.py
# open http://localhost:8055
```

Drop files into `inbox/`, hit **⚙ Reindex Inbox** in the sidebar, and watch them land as wiki entries in `Notes/`.

---

## CLI

```bash
python ingest.py                    # process inbox/
python ingest.py --dry-run          # preview, no writes
python ingest.py --force            # reprocess everything
python ingest.py --provider ollama  # override provider
python ingest.py --lint             # report orphaned/broken pages
python ingest.py --serve            # launch dashboard
```

---

## Document format

Each Note in `Notes/` carries YAML frontmatter:

```yaml
---
title: "Entity Name"
slug: "entity-slug"
created: "2026-05-04"
ingested_at: "2026-05-04T..."
category: development|science|tools|reference
type: entity|concept|summary|note
tags: [tag1, tag2]
related: [slug1, slug2]
---

# Title

## Definition / Overview
...

## Related
- [[other-slug]]
```

---

## Provider config

Set in `config.yaml` (gitignored) or via the **Config** modal in the dashboard:

| Provider   | Needs key | Example model              |
|------------|-----------|----------------------------|
| ollama     | no        | `mistral`, `phi3:mini`     |
| openai     | yes       | `gpt-4o-mini`              |
| anthropic  | yes       | `claude-haiku-4-5-20251001`|
| openrouter | yes       | `anthropic/claude-3-haiku` |

---

## Security

- `.env`, `config.yaml`, `config.local.yaml`, `data/`, `inbox/`, and uploaded `dashboard/assets/profile-*` are all in `.gitignore`.
- A **pre-commit hook** (`.git/hooks/pre-commit`) blocks any staged file that matches common API key patterns (`sk-proj-…`, `sk-or-v1-…`, `sk-ant-…`, AWS keys, Google API keys). The commit aborts with a path + matched pattern.
- API keys live only in `config.yaml`. Never commit that file.

If you need to share a config: copy from `config.yaml.example`.

**Install the pre-commit hook on a fresh clone:**

```bash
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

---

## File layout

```
RatVault/
├── inbox/           # drop sources here (gitignored, append-only)
├── Notes/           # the wiki (LLM-maintained markdown)
├── assets/          # extracted images, pdfs, videos
│   ├── images/<slug>/...
│   ├── pdfs/<slug>/...
│   └── videos/<slug>/...
├── dashboard/       # web UI (vanilla JS + marked + html2canvas)
├── pipeline/        # parser, providers, media, prompts, writer, lint
├── data/            # ingest_state.json (skip-already-processed cache)
├── config.yaml      # provider + model (gitignored)
├── ingest.py        # main pipeline entry
└── serve.py         # FastAPI dashboard server
```

---

## Endpoints (FastAPI)

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/entries` / `/api/entries/{slug}` | List / fetch wiki entries |
| POST | `/api/entries` | Create new entry |
| PUT  | `/api/entries/{slug}` | Update entry |
| GET  | `/api/search?q=` | Full-text search |
| GET  | `/api/inbox` | List inbox files |
| POST | `/api/inbox/upload` | Upload file to inbox |
| POST | `/api/inbox/save-edit` | Save wiki edit back to inbox for re-ingest |
| GET  | `/api/inbox/file/{name}` | Inline serve (PDF/image/video preview) |
| DELETE | `/api/inbox/{name}` | Remove inbox file |
| POST | `/api/reindex` | Run `ingest.py` |
| GET/POST | `/api/config` | Read/write provider config |
| POST | `/api/chat` | RAG chat (vault context + optional images) |
| GET/POST | `/api/profile` | Sidebar profile media |
| GET  | `/assets/{path}` | Serve repo `assets/` (with fallback to `dashboard/assets/`) |

---

## License

MIT — © labrat. Made for fast, local, private knowledge work.
