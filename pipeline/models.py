"""Data models for RatVault ingest pipeline."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field


class AssetRecord(BaseModel):
    """Metadata for an extracted asset (image/video)."""

    type: Literal["image", "video", "file"]
    original_name: str
    vault_path: str
    url: Optional[str] = None


class LLMResponse(BaseModel):
    """Response from an LLM provider."""

    content: str
    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    duration_ms: int


class VaultEntry(BaseModel):
    """A processed vault entry with all frontmatter fields."""

    title: str
    slug: str
    created: str
    ingested_at: str
    summary: str
    tags: list[str] = Field(default_factory=list)
    category: Literal[
        "security", "development", "research", "personal", "reference", "workflow"
    ] = "reference"
    difficulty: Literal["beginner", "intermediate", "advanced"] = "intermediate"
    key_concepts: list[str] = Field(default_factory=list)
    questions_answered: list[str] = Field(default_factory=list)
    source_file: str
    source_hash: str
    provider: str
    model: str
    cross_refs: list[str] = Field(default_factory=list)
    assets: list[AssetRecord] = Field(default_factory=list)
    status: Literal["active", "archived", "draft"] = "active"
    type: Literal["note", "template", "cheatsheet", "guide", "log"] = "note"


class InboxFile(BaseModel):
    """A file in the inbox awaiting processing."""

    path: Path
    hash: str
    size: int
    detected_title: Optional[str] = None


class IngestRecord(BaseModel):
    """Record of a processed file, stored in IngestState."""

    file_hash: str
    output_path: str
    ingested_at: str
    provider: str
    model: str
    title: str
    tags: list[str] = Field(default_factory=list)


class IngestState(BaseModel):
    """Tracks what has been ingested, persisted to disk."""

    records: dict[str, IngestRecord] = Field(default_factory=dict)
    last_full_run: Optional[str] = None

    def mark_processed(self, source_path: Path, file_hash: str, output_path: str, entry: VaultEntry) -> None:
        """Record that a file has been processed."""
        record_key = source_path.name
        self.records[record_key] = IngestRecord(
            file_hash=file_hash,
            output_path=output_path,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            provider=entry.provider,
            model=entry.model,
            title=entry.title,
            tags=entry.tags,
        )

    def is_already_processed(self, source_path: Path, file_hash: str) -> bool:
        """Check if a file with this hash has been processed."""
        record_key = source_path.name
        if record_key not in self.records:
            return False
        return self.records[record_key].file_hash == file_hash

    @classmethod
    def load(cls, path: Path) -> IngestState:
        """Load state from JSON file, or return empty state if file doesn't exist."""
        if path.exists():
            import json

            try:
                data = json.loads(path.read_text())
                return cls(**data)
            except Exception:
                return cls()
        return cls()

    def save(self, path: Path) -> None:
        """Save state to JSON file."""
        import json

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.model_dump(), indent=2))


class ProviderConfig(BaseModel):
    """Configuration for a specific LLM provider."""

    provider: Literal["openai", "anthropic", "ollama", "openrouter"]
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.3
    max_tokens: int = 1024


class VaultConfig(BaseModel):
    """Complete vault configuration."""

    provider: Literal["openai", "anthropic", "ollama", "openrouter"] = "ollama"
    model: str = "llama3.2"
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    openrouter_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"
    output_dir: str = "Notes"
    assets_dir: str = "assets"
    cross_references: bool = True
    fetch_remote_images: bool = False
    enable_embedding: bool = False
    embed_model: str = "nomic-embed-text"
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    temperature: float = 0.3
    max_tokens: int = 1024

    def get_provider_config(self) -> ProviderConfig:
        """Get a ProviderConfig for the active provider."""
        api_key = None
        base_url = None

        if self.provider == "openai":
            api_key = self.openai_api_key
        elif self.provider == "anthropic":
            api_key = self.anthropic_api_key
        elif self.provider == "openrouter":
            api_key = self.openrouter_api_key
            base_url = "https://openrouter.ai/api/v1"
        elif self.provider == "ollama":
            base_url = self.ollama_base_url

        return ProviderConfig(
            provider=self.provider,
            model=self.model,
            api_key=api_key,
            base_url=base_url,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )


def compute_file_hash(content: str) -> str:
    """Compute SHA-256 hash of file content."""
    return hashlib.sha256(content.encode()).hexdigest()


def compute_binary_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:100]
