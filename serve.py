#!/usr/bin/env python3
"""FastAPI server for RatVault web dashboard."""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
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
    images: list = []  # list of {name, dataUrl} dicts (base64 data: URLs)


class DocumentRequest(BaseModel):
    title: str
    slug: str
    content: str


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

    cwd = Path.cwd().resolve()
    if (assets_dir / "images").exists():
        images_dir = assets_dir / "images"
        for img_file in [*images_dir.rglob("*.png"), *images_dir.rglob("*.jpg"), *images_dir.rglob("*.jpeg"), *images_dir.rglob("*.gif")]:
            media["images"].append(str(img_file.resolve().relative_to(cwd)))

    if (assets_dir / "videos").exists():
        videos_dir = assets_dir / "videos"
        for vid_file in [*videos_dir.rglob("*.mp4"), *videos_dir.rglob("*.webm")]:
            media["videos"].append(str(vid_file.resolve().relative_to(cwd)))

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
            capture_output=True, text=True, cwd=Path(__file__).parent, timeout=300
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
    return FileResponse(
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
_prev_slug: "{safe_slug}"
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
    """Handle chat queries against the knowledge vault with RAG.
    Supports image attachments for vision-capable models (OpenAI gpt-4o*, Claude)."""
    try:
        from pipeline.providers import call_llm
        from pipeline.config import load_config

        entries = load_vault_entries()
        index = build_search_index(entries)
        tokens = re.findall(r"\w+", request.message.lower())

        matching_slugs = set()
        for token in tokens:
            if token in index:
                matching_slugs.update(index[token])

        relevant_entries = [e for e in entries if e.get("slug") in matching_slugs][:3]

        context = ""
        if relevant_entries:
            context = "\n\n## Relevant vault entries:\n"
            for entry in relevant_entries:
                context += f"- **{entry.get('title', 'Untitled')}**: {entry.get('summary', 'No summary')}\n"

        system_prompt = f"""You are a helpful assistant for RatVault, a knowledge vault.
Answer questions based on the user's notes. Keep responses concise and practical.

{context}

Use the vault entries above as context. Reference them when relevant."""

        vault_config = load_config()
        if request.provider:
            vault_config.provider = request.provider
        if request.model:
            vault_config.model = request.model
        if request.api_key:
            key_map = {"openai": "openai_api_key", "anthropic": "anthropic_api_key", "openrouter": "openrouter_api_key"}
            provider_key = key_map.get(vault_config.provider)
            if provider_key:
                setattr(vault_config, provider_key, request.api_key)

        # Extract images referenced in matching vault entries
        context_images = []
        import re as _re
        import base64 as _base64
        for entry in relevant_entries:
            body = entry.get("body", "")
            for img_match in _re.finditer(r'!\[[^\]]*\]\((assets/images/[^)]+)\)', body):
                img_path = Path(img_match.group(1))
                if img_path.is_file():
                    mime = "image/jpeg" if img_path.suffix.lower() in ('.jpg', '.jpeg') else f"image/{img_path.suffix.lower().lstrip('.')}"
                    b64 = _base64.b64encode(img_path.read_bytes()).decode()
                    context_images.append({"name": img_path.name, "dataUrl": f"data:{mime};base64,{b64}"})

        # Vision path: if images supplied AND provider supports vision, use vision API directly.
        all_images = request.images + context_images
        if all_images:
            reply = _call_vision_llm(
                request.message, system_prompt, vault_config,
                all_images, request.history
            )
            if reply is not None:
                return {
                    "reply": reply,
                    "model": vault_config.model,
                    "provider": vault_config.provider,
                    "sources": [e.get("title") for e in relevant_entries],
                    "vision": True,
                }
            # Fallback: provider doesn't support vision — note in prompt
            if request.images:
                request.message += f"\n\n[Note: {len(request.images)} image(s) were attached but the current model does not support vision. Images saved to inbox for indexing.]"

        provider_config = vault_config.get_provider_config()
        response = call_llm(
            prompt=request.message,
            system=system_prompt,
            config=provider_config,
        )

        return {
            "reply": response.content,
            "model": response.model,
            "provider": response.provider,
            "sources": [e.get("title") for e in relevant_entries]
        }
    except Exception as e:
        return {"error": str(e), "reply": None}


def _call_vision_llm(message: str, system: str, vault_config, images: list, history: list):
    """Call a vision-capable LLM with images. Returns reply text, or None if unsupported."""
    import httpx

    provider = vault_config.provider
    model = vault_config.model

    # OpenAI gpt-4o and Anthropic Claude 3+ support vision.
    if provider == "openai" and ("4o" in model or "gpt-4-vision" in model or "gpt-4-turbo" in model):
        api_key = vault_config.openai_api_key
        content_blocks = [{"type": "text", "text": message}]
        for img in images:
            url = img.get("dataUrl") or img.get("url")
            if url:
                content_blocks.append({
                    "type": "image_url",
                    "image_url": {"url": url}
                })
        msgs = [{"role": "system", "content": system}]
        for h in (history or [])[-10:]:
            if h.get("role"):
                msgs.append({"role": h["role"], "content": h.get("content", "")})
        msgs.append({"role": "user", "content": content_blocks})

        with httpx.Client(timeout=120) as c:
            r = c.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"model": model, "messages": msgs, "max_tokens": 2000},
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

    if provider == "anthropic" and ("claude" in model.lower()):
        api_key = vault_config.anthropic_api_key
        content_blocks = []
        for img in images:
            url = img.get("dataUrl", "")
            # Expect data:image/{type};base64,{data}
            if url.startswith("data:"):
                mime = url.split(";")[0].split(":")[1]
                b64 = url.split(",", 1)[1]
                content_blocks.append({
                    "type": "image",
                    "source": {"type": "base64", "media_type": mime, "data": b64},
                })
        content_blocks.append({"type": "text", "text": message})

        msgs = []
        for h in (history or [])[-10:]:
            if h.get("role"):
                msgs.append({"role": h["role"], "content": h.get("content", "")})
        msgs.append({"role": "user", "content": content_blocks})

        with httpx.Client(timeout=120) as c:
            r = c.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={"model": model, "system": system, "messages": msgs, "max_tokens": 2000},
            )
            r.raise_for_status()
            return r.json()["content"][0]["text"]

    if provider == "openrouter":
        # Many OpenRouter models support vision via the same OpenAI format
        api_key = vault_config.openrouter_api_key
        content_blocks = [{"type": "text", "text": message}]
        for img in images:
            url = img.get("dataUrl") or img.get("url")
            if url:
                content_blocks.append({"type": "image_url", "image_url": {"url": url}})
        msgs = [{"role": "system", "content": system}]
        for h in (history or [])[-10:]:
            if h.get("role"):
                msgs.append({"role": h["role"], "content": h.get("content", "")})
        msgs.append({"role": "user", "content": content_blocks})

        with httpx.Client(timeout=120) as c:
            r = c.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "HTTP-Referer": "http://localhost:8055",
                    "X-Title": "RatVault",
                },
                json={"model": model, "messages": msgs, "max_tokens": 2000},
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            # If model doesn't support vision, OpenRouter returns 400 — fall through

    return None


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

@app.get("/assets/{file_path:path}")
async def serve_assets(file_path: str):
    """Serve vault media assets from repo-root assets/ (wiki images, videos, etc.)"""
    assets_root = Path("assets").resolve()
    try:
        candidate = (assets_root / file_path).resolve()
        candidate.relative_to(assets_root)
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden")
    if candidate.is_file():
        return FileResponse(candidate)
    # Fall back to dashboard/assets/ for profile images
    dash_assets = Path("dashboard/assets").resolve()
    try:
        dash_candidate = (dash_assets / file_path).resolve()
        dash_candidate.relative_to(dash_assets)
        if dash_candidate.is_file():
            return FileResponse(dash_candidate)
    except ValueError:
        pass
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/{file_path:path}")
async def serve_files(file_path: str):
    """Serve static files from dashboard directory"""
    dashboard_root = Path("dashboard").resolve()
    if not file_path or file_path == "/":
        return FileResponse(dashboard_root / "index.html")
    try:
        candidate = (dashboard_root / file_path).resolve()
        candidate.relative_to(dashboard_root)  # raises ValueError if outside dashboard/
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden")
    if candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(dashboard_root / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8055)
