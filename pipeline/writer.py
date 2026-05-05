"""Writing vault entries with YAML frontmatter."""

from datetime import datetime, timezone
from pathlib import Path

import yaml

from pipeline.models import VaultEntry, slugify


def write_entry(
    entry: VaultEntry,
    content: str,
    output_dir: Path,
) -> Path:
    """
    Write a vault entry to disk as Markdown with YAML frontmatter.

    Args:
        entry: VaultEntry with metadata
        content: Processed content (media paths rewritten)
        output_dir: Directory to write entry

    Returns:
        Path to written file
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{entry.slug}.md"
    output_path = output_dir / filename

    frontmatter_dict = {
        "title": entry.title,
        "slug": entry.slug,
        "created": entry.created,
        "ingested_at": entry.ingested_at,
        "summary": entry.summary,
        "tags": entry.tags,
        "category": entry.category,
        "difficulty": entry.difficulty,
        "key_concepts": entry.key_concepts,
        "questions_answered": entry.questions_answered,
        "source_file": entry.source_file,
        "source_hash": entry.source_hash,
        "provider": entry.provider,
        "model": entry.model,
        "cross_refs": entry.cross_refs,
        "assets": [a.model_dump() for a in entry.assets],
        "status": entry.status,
        "type": entry.type,
    }

    frontmatter_yaml = yaml.dump(frontmatter_dict, default_flow_style=False, allow_unicode=True)

    markdown = f"---\n{frontmatter_yaml}---\n\n{content}"

    if entry.cross_refs:
        markdown += "\n\n## Related Notes\n\n"
        for ref in entry.cross_refs:
            if not ref.startswith("[["):
                ref = f"[[{ref}]]"
            markdown += f"- {ref}\n"

    output_path.write_text(markdown, encoding="utf-8")
    return output_path
