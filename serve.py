#!/usr/bin/env python3
"""FastAPI server for RatVault web dashboard."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.responses import FileResponse as FastAPIFileResponse
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


class DocumentRequest(BaseModel):
    title: str
    slug: str
    content: str


class DocumentUpdateRequest(BaseModel):
    content: str


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
        except Exception:
            pass

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
    """Reindex vault: run ingest.py on inbox/ to populate Notes/."""
    import subprocess
    try:
        result = subprocess.run(
            ["python", "ingest.py"],
            capture_output=True, text=True, cwd=".", timeout=300
        )
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-2000:] if result.stderr else "",
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "stderr": "Ingest timed out after 5 minutes"}
    except Exception as e:
        return {"status": "error", "stderr": str(e)}


@app.get("/api/inbox")
async def list_inbox():
    """List files in inbox/ folder."""
    inbox = Path("inbox")
    if not inbox.exists():
        return []
    files = []
    for f in inbox.iterdir():
        if f.is_file() and not f.name.startswith("."):
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "type": f.suffix.lower(),
            })
    files.sort(key=lambda x: x["modified"], reverse=True)
    return files


@app.post("/api/inbox/upload")
async def upload_to_inbox(file: UploadFile = File(...)):
    """Upload a file (doc, image, video, pdf) to inbox/ folder."""
    try:
        inbox = Path("inbox")
        inbox.mkdir(parents=True, exist_ok=True)
        safe_name = Path(file.filename).name
        target = inbox / safe_name
        content = await file.read()
        target.write_bytes(content)
        return {
            "success": True,
            "filename": safe_name,
            "size": len(content),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/inbox/file/{filename}")
async def serve_inbox_file(filename: str):
    """Serve a file from inbox/ for in-app preview (PDFs, images, video, etc.)."""
    safe = Path(filename).name
    target = Path("inbox") / safe
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    # Inline disposition so PDFs render in browser, not download
    return FastAPIFileResponse(
        target,
        headers={"Content-Disposition": f'inline; filename="{safe}"'},
    )


@app.delete("/api/inbox/{filename}")
async def delete_inbox_file(filename: str):
    """Remove a file from inbox/."""
    try:
        inbox = Path("inbox")
        target = inbox / Path(filename).name
        if target.exists():
            target.unlink()
            return {"success": True}
        raise HTTPException(status_code=404, detail="Not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/inbox/save-edit")
async def save_edit_to_inbox(req: DocumentRequest):
    """Save edited document back to inbox/ for re-ingestion."""
    try:
        inbox = Path("inbox")
        inbox.mkdir(parents=True, exist_ok=True)
        safe_slug = req.slug.lower().replace(" ", "-").replace("/", "-")
        target = inbox / f"{safe_slug}.md"
        now = datetime.now().isoformat().split('T')[0]
        content = f"""---
title: "{req.title}"
slug: "{safe_slug}"
created: "{now}"
source: "edited-from-vault"
---

{req.content}"""
        target.write_text(content, encoding="utf-8")
        return {"success": True, "filename": target.name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        return {"error": str(e), "reply": None}


@app.post("/api/entries")
async def create_document(req: DocumentRequest):
    """Create a new document in Notes/."""
    try:
        notes_dir = Path("Notes")
        notes_dir.mkdir(parents=True, exist_ok=True)

        slug = req.slug.lower().replace(" ", "-").replace("/", "-")
        filepath = notes_dir / f"{slug}.md"

        if filepath.exists():
            raise HTTPException(status_code=409, detail="Document already exists")

        # Build frontmatter
        now = datetime.now().isoformat().split('T')[0]
        frontmatter = f"""---
title: "{req.title}"
slug: "{slug}"
created: "{now}"
tags: []
---

{req.content}"""

        filepath.write_text(frontmatter, encoding="utf-8")

        return {
            "success": True,
            "slug": slug,
            "title": req.title,
            "created": now
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/entries/{slug}")
async def update_document(slug: str, req: DocumentUpdateRequest):
    """Update an existing document."""
    try:
        notes_dir = Path("Notes")
        filepath = notes_dir / f"{slug}.md"

        if not filepath.exists():
            raise HTTPException(status_code=404, detail="Document not found")

        # Parse existing frontmatter
        existing = filepath.read_text(encoding="utf-8")
        entry = parse_frontmatter(existing)

        if not entry:
            raise HTTPException(status_code=400, detail="Invalid document format")

        # Rebuild with updated content
        frontmatter = f"""---
title: "{entry.get('title', 'Untitled')}"
slug: "{entry.get('slug', slug)}"
created: "{entry.get('created', '')}"
tags: {entry.get('tags', [])}
"""
        if 'related' in entry:
            frontmatter += f'related: {entry["related"]}\n'
        frontmatter += f"---\n\n{req.content}"

        filepath.write_text(frontmatter, encoding="utf-8")

        return {
            "success": True,
            "slug": slug,
            "updated_at": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/profile/current")
async def get_current_profile():
    """Get the most recent profile image/video."""
    try:
        assets_dir = Path("dashboard/assets")
        profile_files = sorted(assets_dir.glob("profile-*"), key=lambda p: p.stat().st_mtime, reverse=True)

        if profile_files:
            latest = profile_files[0]
            return {
                "url": f"/assets/{latest.name}",
                "filename": latest.name
            }
        return {"url": None, "filename": None}
    except Exception as e:
        return {"url": None, "filename": None}


@app.post("/api/profile")
async def upload_profile(file: UploadFile = File(...)):
    """Upload a new profile image or video."""
    try:
        assets_dir = Path("dashboard/assets")
        assets_dir.mkdir(parents=True, exist_ok=True)

        # Save with timestamp to ensure uniqueness
        timestamp = int(datetime.now().timestamp() * 1000)
        ext = Path(file.filename).suffix
        new_filename = f"profile-{timestamp}{ext}"
        filepath = assets_dir / new_filename

        # Save the file
        content = await file.read()
        filepath.write_bytes(content)

        return {
            "success": True,
            "url": f"/assets/{new_filename}",
            "filename": new_filename
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8055)
