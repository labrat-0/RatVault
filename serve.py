#!/usr/bin/env python3
"""FastAPI server for RatVault web dashboard."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="RatVault Dashboard")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    message: str
    history: list = []
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None


@app.on_event("startup")
async def startup():
    """Initialize dashboard on startup."""
    pass


def load_vault_entries() -> list[dict]:
    """Load all vault entries and parse frontmatter."""
    notes_dir = Path("Notes")
    if not notes_dir.exists():
        return []

    entries = []
    for md_file in notes_dir.glob("*.md"):
        if md_file.name == "home.md":
            continue

        try:
            content = md_file.read_text(encoding="utf-8")
            entry_data = parse_frontmatter(content)
            if entry_data:
                entry_data["file"] = md_file.name
                entry_data["body"] = extract_body(content)
                entries.append(entry_data)
        except Exception as e:
            print(f"Error loading {md_file}: {e}")

    return entries


def parse_frontmatter(content: str) -> Optional[dict]:
    """Parse YAML frontmatter from markdown."""
    if not content.startswith("---"):
        return None

    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        return None

    try:
        frontmatter_text = match.group(1)
        data = yaml.safe_load(frontmatter_text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def extract_body(content: str) -> str:
    """Extract body content after frontmatter."""
    if not content.startswith("---"):
        return content

    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if match:
        return match.group(2).strip()
    return content


def build_search_index(entries: list[dict]) -> dict:
    """Build in-memory inverted index for full-text search."""
    index = {}
    for entry in entries:
        content = f"{entry.get('title', '')} {entry.get('summary', '')} {' '.join(entry.get('tags', []))}"
        tokens = re.findall(r"\w+", content.lower())

        for token in tokens:
            if token not in index:
                index[token] = set()
            index[token].add(entry.get("slug", ""))

    return index


@app.get("/api/entries")
async def get_entries(tag: Optional[str] = None, provider: Optional[str] = None):
    """Get all vault entries with optional filtering."""
    entries = load_vault_entries()

    if tag:
        entries = [e for e in entries if tag in e.get("tags", [])]
    if provider:
        entries = [e for e in entries if e.get("provider") == provider]

    entries.sort(key=lambda e: e.get("ingested_at", ""), reverse=True)
    return entries


@app.get("/api/entries/{slug}")
async def get_entry(slug: str):
    """Get a single entry by slug."""
    entries = load_vault_entries()
    for entry in entries:
        if entry.get("slug") == slug:
            return entry
    raise HTTPException(status_code=404, detail="Entry not found")


@app.get("/api/search")
async def search(q: str = ""):
    """Full-text search over entries."""
    if not q or len(q) < 2:
        return []

    entries = load_vault_entries()
    index = build_search_index(entries)
    tokens = re.findall(r"\w+", q.lower())

    if not tokens:
        return []

    matching_slugs = set()
    for token in tokens:
        if token in index:
            matching_slugs.update(index[token])

    results = [e for e in entries if e.get("slug") in matching_slugs]
    results.sort(key=lambda e: e.get("ingested_at", ""), reverse=True)
    return results


@app.get("/api/timeline")
async def get_timeline():
    """Get entries grouped by date."""
    entries = load_vault_entries()
    entries.sort(key=lambda e: e.get("ingested_at", ""), reverse=True)

    timeline = {}
    for entry in entries:
        date = entry.get("created", "unknown")
        if date not in timeline:
            timeline[date] = []
        timeline[date].append(entry)

    return timeline


@app.get("/api/gallery")
async def get_gallery():
    """Get all media assets."""
    assets_dir = Path("assets")
    media = {"images": [], "videos": []}

    if (assets_dir / "images").exists():
        for img_file in (assets_dir / "images").rglob("*.png") + (assets_dir / "images").rglob("*.jpg") + (assets_dir / "images").rglob("*.jpeg") + (assets_dir / "images").rglob("*.gif"):
            media["images"].append(str(img_file.relative_to(Path.cwd())))

    if (assets_dir / "videos").exists():
        for vid_file in (assets_dir / "videos").rglob("*.mp4") + (assets_dir / "videos").rglob("*.webm"):
            media["videos"].append(str(vid_file.relative_to(Path.cwd())))

    return media


@app.get("/api/analytics")
async def get_analytics():
    """Get analytics data."""
    entries = load_vault_entries()

    entries_by_date = {}
    providers = {}
    tags_freq = {}

    for entry in entries:
        date = entry.get("created", "unknown")
        entries_by_date[date] = entries_by_date.get(date, 0) + 1

        provider = entry.get("provider", "unknown")
        providers[provider] = providers.get(provider, 0) + 1

        for tag in entry.get("tags", []):
            tags_freq[tag] = tags_freq.get(tag, 0) + 1

    return {
        "entries_by_date": entries_by_date,
        "providers": providers,
        "tags": tags_freq,
        "total_entries": len(entries),
    }


@app.get("/api/tags")
async def get_tags():
    """Get tag cloud data."""
    entries = load_vault_entries()
    tag_counts = {}

    for entry in entries:
        for tag in entry.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"tag": t, "count": c} for t, c in sorted_tags]


@app.get("/api/config")
async def get_config():
    """Get current configuration (masks API keys)."""
    try:
        from pipeline.config import load_config
        config = load_config()
        return {
            "provider": config.provider,
            "model": config.model,
            "has_openai_key": bool(config.openai_api_key),
            "has_anthropic_key": bool(config.anthropic_api_key),
            "has_openrouter_key": bool(config.openrouter_api_key),
            "ollama_base_url": config.ollama_base_url,
            "temperature": config.temperature,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ConfigUpdate(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    temperature: Optional[float] = None


@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    """Update configuration and persist to config.yaml."""
    try:
        config_path = Path("config.yaml")
        existing = {}
        if config_path.exists():
            with open(config_path) as f:
                existing = yaml.safe_load(f) or {}

        if update.provider:
            existing["provider"] = update.provider
        if update.model:
            existing["model"] = update.model
        if update.temperature is not None:
            existing["temperature"] = update.temperature
        if update.api_key and update.provider:
            key_map = {
                "openai": "openai_api_key",
                "anthropic": "anthropic_api_key",
                "openrouter": "openrouter_api_key",
            }
            if update.provider in key_map:
                existing[key_map[update.provider]] = update.api_key

        with open(config_path, "w") as f:
            yaml.dump(existing, f, default_flow_style=False)
        return {"status": "ok", "config": {k: v for k, v in existing.items() if "key" not in k}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reindex")
async def reindex():
    """Reindex vault (scan for new/changed files)."""
    return {"status": "ok"}


@app.get("/api/providers")
async def get_providers():
    """Get current provider configuration."""
    try:
        from pipeline.config import load_config

        config = load_config()
        return {
            "provider": config.provider,
            "model": config.model,
        }
    except Exception:
        return {
            "provider": "ollama",
            "model": "llama3.2",
        }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Handle chat queries against the knowledge vault with RAG"""
    try:
        from pipeline.providers import call_llm
        from pipeline.config import load_config
        from pipeline.models import ProviderConfig

        # Search vault for relevant entries
        entries = load_vault_entries()
        index = build_search_index(entries)
        tokens = re.findall(r"\w+", request.message.lower())

        matching_slugs = set()
        for token in tokens:
            if token in index:
                matching_slugs.update(index[token])

        relevant_entries = [e for e in entries if e.get("slug") in matching_slugs][:3]

        # Build context from relevant entries
        context = ""
        if relevant_entries:
            context = "\n\n## Relevant vault entries:\n"
            for entry in relevant_entries:
                context += f"- **{entry.get('title', 'Untitled')}**: {entry.get('summary', 'No summary')}\n"

        system_prompt = f"""You are a helpful assistant for RatVault, a developer knowledge base.
Help users learn about programming languages, tools, development environments, AI/LLM, and technology.
Keep answers concise and practical. When relevant, suggest related vault topics.

{context}

Use the vault entries above as context when answering. If the user asks about something in the vault, reference those entries."""

        vault_config = load_config()
        # Apply per-request overrides onto vault_config, then use get_provider_config()
        if request.provider:
            vault_config.provider = request.provider
        if request.model:
            vault_config.model = request.model
        if request.api_key:
            if vault_config.provider == "openai":
                vault_config.openai_api_key = request.api_key
            elif vault_config.provider == "anthropic":
                vault_config.anthropic_api_key = request.api_key
            elif vault_config.provider == "openrouter":
                vault_config.openrouter_api_key = request.api_key

        provider_config = vault_config.get_provider_config()

        response = call_llm(
            prompt=request.message,
            system=system_prompt,
            config=provider_config
        )

        return {
            "reply": response.content,
            "model": response.model,
            "provider": response.provider,
            "sources": [e.get("title") for e in relevant_entries]
        }
    except Exception as e:
        import traceback
        return {"error": str(e), "reply": None}


class DocRequest(BaseModel):
    title: str
    content: str


@app.post("/api/docs")
async def create_document(request: DocRequest):
    """Create and save a new document to the vault."""
    try:
        notes_dir = Path("Notes")
        notes_dir.mkdir(exist_ok=True)

        # Generate filename from title
        filename = request.title.lower().replace(" ", "-")
        # Remove invalid filename characters
        filename = re.sub(r'[^\w\-]', '', filename)
        if not filename:
            filename = f"doc-{datetime.now().timestamp()}"

        filepath = notes_dir / f"{filename}.md"

        # Avoid overwriting existing files
        counter = 1
        base_filepath = filepath
        while filepath.exists():
            filename_parts = filepath.stem.rsplit('-', 1)
            if filename_parts[-1].isdigit():
                base_name = filename_parts[0]
                counter = int(filename_parts[-1]) + 1
            else:
                base_name = filepath.stem
            filepath = notes_dir / f"{base_name}-{counter}.md"

        # Write the document with frontmatter
        content = f"""---
title: {request.title}
created: {datetime.now().isoformat()}
---

{request.content}
"""

        filepath.write_text(content)

        return {
            "success": True,
            "filename": filepath.name,
            "message": f"Document '{request.title}' saved successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


from fastapi.responses import FileResponse as FastAPIFileResponse

@app.get("/{file_path:path}")
async def serve_files(file_path: str):
    """Serve static files from dashboard directory"""
    from pathlib import Path
    file_full_path = Path("dashboard") / file_path
    if file_full_path.is_file():
        return FastAPIFileResponse(file_full_path)
    elif file_path == "" or file_path == "/":
        return FastAPIFileResponse("dashboard/index.html")
    else:
        return FastAPIFileResponse("dashboard/index.html")
