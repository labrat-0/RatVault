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

app = FastAPI(title="RatVault Dashboard")


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


@app.post("/api/config")
async def update_config(config: dict):
    """Update configuration."""
    try:
        config_path = Path("config.yaml")
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        return {"status": "ok"}
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


app.mount("/", StaticFiles(directory="dashboard", html=True), name="dashboard")
