#!/usr/bin/env python3
"""RatVault ingest pipeline - main entry point."""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}
VIDEO_EXTENSIONS = {'.mp4', '.webm', '.mov', '.mkv'}

import re

import yaml

from pipeline.config import load_config, setup_wizard
from pipeline.media import extract_and_rewrite_media
from pipeline.models import (
    IngestState,
    ProviderConfig,
    VaultConfig,
    VaultEntry,
    compute_file_hash,
    slugify,
)
from pipeline.parser import (
    discover_inbox_files,
    parse_input_file,
    strip_frontmatter,
)
from pipeline.prompts import ENRICHMENT_SYSTEM, ENRICHMENT_USER
from pipeline.providers import call_llm_json, LLMError
from pipeline.writer import write_entry


def _parse_inbox_frontmatter(raw_content: str) -> dict:
    """Extract frontmatter dict from inbox file (empty dict if none)."""
    if not raw_content.startswith("---"):
        return {}
    match = re.match(r"^---\n(.*?)\n---\n", raw_content, re.DOTALL)
    if not match:
        return {}
    try:
        return yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}


def _first_paragraph_summary(body: str, max_chars: int = 200) -> str:
    """Take first non-empty paragraph of body for deterministic summary."""
    for block in re.split(r"\n\s*\n", body.strip()):
        cleaned = re.sub(r"^#+\s*", "", block.strip())
        cleaned = re.sub(r"\s+", " ", cleaned)
        if cleaned and not cleaned.startswith("!["):
            return cleaned[:max_chars].rstrip()
    return ""


def _llm_enabled(config: VaultConfig) -> bool:
    """LLM enrichment runs only if a usable provider is configured."""
    if config.provider == "none":
        return False
    if config.provider == "ollama":
        return True
    key_attr = f"{config.provider}_api_key"
    return bool(getattr(config, key_attr, "").strip())


def _build_deterministic_entry(
    *,
    title: str,
    slug: str,
    body: str,
    inbox_frontmatter: dict,
    source_file: str,
    source_hash: str,
    provider: str,
    model: str,
    assets: list,
) -> VaultEntry:
    """Build a VaultEntry without any LLM call. Preserves user-supplied frontmatter."""
    now = datetime.now(timezone.utc)
    valid_categories = {"security", "development", "research", "personal", "reference", "workflow"}
    valid_difficulty = {"beginner", "intermediate", "advanced"}

    fm_category = inbox_frontmatter.get("category")
    category = fm_category if fm_category in valid_categories else "reference"

    fm_diff = inbox_frontmatter.get("difficulty")
    difficulty = fm_diff if fm_diff in valid_difficulty else "intermediate"

    fm_tags = inbox_frontmatter.get("tags") or []
    if not isinstance(fm_tags, list):
        fm_tags = []

    fm_summary = inbox_frontmatter.get("summary")
    summary = fm_summary if isinstance(fm_summary, str) and fm_summary.strip() else _first_paragraph_summary(body)

    return VaultEntry(
        title=title,
        slug=slug,
        created=inbox_frontmatter.get("created") or now.strftime("%Y-%m-%d"),
        ingested_at=now.isoformat(),
        summary=summary,
        tags=fm_tags,
        category=category,
        difficulty=difficulty,
        key_concepts=inbox_frontmatter.get("key_concepts") or [],
        questions_answered=inbox_frontmatter.get("questions_answered") or [],
        source_file=source_file,
        source_hash=source_hash,
        provider=provider,
        model=model,
        assets=assets,
    )


def _archive_inbox_file(path: Path) -> None:
    """Move successfully indexed source out of inbox/ into inbox/.archive/.

    Keeps the raw source as an artifact while removing it from the active inbox
    listing so the UI shows only un-indexed files.
    """
    import shutil
    archive_dir = path.parent / ".archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    target = archive_dir / path.name
    if target.exists():
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        target = archive_dir / f"{path.stem}_{ts}{path.suffix}"
    shutil.move(str(path), str(target))


def _overlay_llm_enrichment(entry: VaultEntry, enrichment: dict) -> VaultEntry:
    """Apply LLM enrichment over deterministic baseline. LLM never overwrites non-empty user fields."""
    data = entry.model_dump()
    if enrichment.get("title") and data["title"] in ("", entry.source_file):
        data["title"] = enrichment["title"]
        data["slug"] = slugify(enrichment["title"])
    if enrichment.get("summary") and not data["summary"]:
        data["summary"] = enrichment["summary"]
    if enrichment.get("tags") and not data["tags"]:
        data["tags"] = enrichment["tags"]
    if enrichment.get("category") and data["category"] == "reference":
        data["category"] = enrichment["category"]
    if enrichment.get("difficulty") and data["difficulty"] == "intermediate":
        data["difficulty"] = enrichment["difficulty"]
    if enrichment.get("key_concepts") and not data["key_concepts"]:
        data["key_concepts"] = enrichment["key_concepts"]
    if enrichment.get("questions_answered") and not data["questions_answered"]:
        data["questions_answered"] = enrichment["questions_answered"]
    return VaultEntry(**data)


def main():
    """Main ingest pipeline."""
    parser = argparse.ArgumentParser(description="RatVault ingest pipeline")
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run configuration wizard",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and plan but don't write",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-process files even if already ingested",
    )
    parser.add_argument(
        "--model",
        help="Override model name",
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "ollama", "openrouter", "none"],
        help="Override provider (use 'none' for deterministic indexing only)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch web dashboard instead of ingesting",
    )
    parser.add_argument(
        "--output-dir",
        help="Override output directory",
    )
    parser.add_argument(
        "--no-embed",
        action="store_true",
        help="Skip embedding step",
    )
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Check wiki health (orphaned pages, broken refs, etc.)",
    )
    parser.add_argument(
        "input_path",
        nargs="?",
        help="File or directory to ingest (default: inbox/)",
    )

    args = parser.parse_args()

    if args.setup:
        setup_wizard()
        return
    
    if args.lint:
        from pipeline.lint import lint_wiki, print_lint_report
        issues = lint_wiki()
        print_lint_report(issues)
        return

    if args.serve:
        launch_dashboard()
        return

    cli_overrides = {}
    if args.model:
        cli_overrides["model"] = args.model
    if args.provider:
        cli_overrides["provider"] = args.provider
    if args.output_dir:
        cli_overrides["output_dir"] = args.output_dir

    config = load_config(cli_overrides)
    inbox_dir = Path(args.input_path or "inbox")
    output_dir = Path(config.output_dir)
    state_file = Path("data") / "ingest_state.json"

    print(f"📦 RatVault Ingest Pipeline")
    print(f"   Provider: {config.provider} ({config.model})")
    print(f"   Input: {inbox_dir}")
    print(f"   Output: {output_dir}")
    if args.dry_run:
        print(f"   Mode: DRY RUN (no changes)")
    print()

    inbox_files = discover_inbox_files(inbox_dir)
    if not inbox_files:
        print(f"No files found in {inbox_dir}")
        return

    state = IngestState.load(state_file)
    provider_config = config.get_provider_config() if config.provider != "none" else None
    llm_on = _llm_enabled(config)
    if not llm_on:
        print(f"   LLM enrichment: OFF (deterministic indexing only)")
    print()

    processed_count = 0
    skipped_count = 0
    error_count = 0

    for inbox_file in inbox_files:
        if state.is_already_processed(inbox_file.path, inbox_file.hash) and not args.force:
            print(f"⏭️  Skipping {inbox_file.path.name} (already processed)")
            skipped_count += 1
            continue

        print(f"📄 Processing {inbox_file.path.name}...")

        if inbox_file.path.suffix.lower() in IMAGE_EXTENSIONS:
            if args.dry_run:
                print(f"   Image: {inbox_file.path.name}")
                continue
            try:
                import shutil
                entry_slug = slugify(inbox_file.detected_title or inbox_file.path.stem)
                images_dir = Path(config.assets_dir) / "images" / entry_slug
                images_dir.mkdir(parents=True, exist_ok=True)
                dest = images_dir / inbox_file.path.name
                shutil.copy2(inbox_file.path, dest)
                asset_path = f"assets/images/{entry_slug}/{inbox_file.path.name}"

                img_content = f"![{inbox_file.path.stem}]({asset_path})\n"

                now = datetime.now(timezone.utc)
                entry = VaultEntry(
                    title=inbox_file.detected_title or inbox_file.path.stem,
                    slug=entry_slug,
                    created=now.strftime("%Y-%m-%d"),
                    ingested_at=now.isoformat(),
                    summary=f"Image: {inbox_file.path.name}",
                    tags=["image", "media"],
                    category="reference",
                    difficulty="beginner",
                    key_concepts=[],
                    questions_answered=[],
                    source_file=inbox_file.path.name,
                    source_hash=inbox_file.hash[:8],
                    provider=config.provider,
                    model=config.model,
                    assets=[],
                )
                output_path = write_entry(entry, img_content, output_dir)
                print(f"   ✅ Image → {output_path}")
                state.mark_processed(inbox_file.path, inbox_file.hash, str(output_path), entry)
                state.save(state_file)
                _archive_inbox_file(inbox_file.path)
                processed_count += 1
            except Exception as e:
                print(f"   ❌ Image error: {e}")
                error_count += 1
            continue

        if inbox_file.path.suffix.lower() in VIDEO_EXTENSIONS:
            if args.dry_run:
                print(f"   Video: {inbox_file.path.name}")
                continue
            try:
                import shutil
                entry_slug = slugify(inbox_file.detected_title or inbox_file.path.stem)
                videos_dir = Path(config.assets_dir) / "videos" / entry_slug
                videos_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(inbox_file.path, videos_dir / inbox_file.path.name)
                video_url = f"assets/videos/{entry_slug}/{inbox_file.path.name}"

                vid_content = (
                    f'<video controls src="/{video_url}" '
                    f'style="width:100%;max-height:720px"></video>\n\n'
                    f'[🎬 Open Video]({video_url})\n'
                )

                now = datetime.now(timezone.utc)
                entry = VaultEntry(
                    title=inbox_file.detected_title or inbox_file.path.stem,
                    slug=entry_slug,
                    created=now.strftime("%Y-%m-%d"),
                    ingested_at=now.isoformat(),
                    summary=f"Video: {inbox_file.path.name}",
                    tags=["video", "media"],
                    category="reference",
                    difficulty="beginner",
                    key_concepts=[],
                    questions_answered=[],
                    source_file=inbox_file.path.name,
                    source_hash=inbox_file.hash[:8],
                    provider=config.provider,
                    model=config.model,
                    assets=[],
                )
                output_path = write_entry(entry, vid_content, output_dir)
                print(f"   ✅ Video → {output_path}")
                state.mark_processed(inbox_file.path, inbox_file.hash, str(output_path), entry)
                state.save(state_file)
                _archive_inbox_file(inbox_file.path)
                processed_count += 1
            except Exception as e:
                print(f"   ❌ Video error: {e}")
                error_count += 1
            continue

        if inbox_file.path.suffix.lower() == ".pdf":
            if args.dry_run:
                print(f"   PDF: {inbox_file.path.name}")
                continue
            try:
                import shutil
                # Always use filename for PDFs — parsed first-page text gives garbage titles
                title = inbox_file.path.stem.replace('-', ' ').replace('_', ' ').strip(' .')
                entry_slug = slugify(title)
                pdf_dir = Path(config.assets_dir) / "pdfs" / entry_slug
                pdf_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(inbox_file.path, pdf_dir / inbox_file.path.name)
                pdf_url = f"assets/pdfs/{entry_slug}/{inbox_file.path.name}"
                pdf_body = (
                    f'<embed src="/{pdf_url}" type="application/pdf" width="100%" height="720px" />\n\n'
                    f'[📄 Open PDF]({pdf_url})\n'
                )
                now = datetime.now(timezone.utc)
                entry = VaultEntry(
                    title=title, slug=entry_slug,
                    created=now.strftime("%Y-%m-%d"), ingested_at=now.isoformat(),
                    summary=f"PDF: {inbox_file.path.name}",
                    tags=["pdf", "document"], category="reference", difficulty="beginner",
                    key_concepts=[], questions_answered=[],
                    source_file=inbox_file.path.name, source_hash=inbox_file.hash[:8],
                    provider=config.provider, model=config.model, assets=[],
                )
                output_path = write_entry(entry, pdf_body, output_dir)
                print(f"   ✅ PDF → {output_path}")
                state.mark_processed(inbox_file.path, inbox_file.hash, str(output_path), entry)
                state.save(state_file)
                _archive_inbox_file(inbox_file.path)
                processed_count += 1
            except Exception as e:
                print(f"   ❌ PDF error: {e}")
                error_count += 1
            continue

        try:
            raw_content, detected_title = parse_input_file(inbox_file.path)
            inbox_frontmatter = _parse_inbox_frontmatter(raw_content)
            body_content = strip_frontmatter(raw_content)

            if args.dry_run:
                print(f"   Title: {detected_title or '(auto-detect)'}")
                print(f"   Size: {len(body_content)} chars")
                print()
                continue

            title = detected_title or inbox_frontmatter.get("title") or inbox_file.path.stem
            entry_slug = slugify(title)

            assets_dir = Path(config.assets_dir)
            content_with_media, asset_records = extract_and_rewrite_media(
                body_content,
                inbox_file.path,
                assets_dir,
                entry_slug,
            )

            entry = _build_deterministic_entry(
                title=title,
                slug=entry_slug,
                body=content_with_media,
                inbox_frontmatter=inbox_frontmatter,
                source_file=inbox_file.path.name,
                source_hash=inbox_file.hash[:8],
                provider=config.provider,
                model=config.model,
                assets=asset_records,
            )

            if llm_on:
                try:
                    llm_content = content_with_media[:8000]
                    prompt = ENRICHMENT_USER.format(content=llm_content)
                    enrichment = call_llm_json(prompt, ENRICHMENT_SYSTEM, provider_config)
                    entry = _overlay_llm_enrichment(entry, enrichment)
                except LLMError as e:
                    print(f"   ⚠️  LLM enrichment failed, using deterministic fallback: {e}")
                except Exception as e:
                    print(f"   ⚠️  LLM enrichment skipped: {e}")

            output_path = write_entry(entry, content_with_media, output_dir)
            print(f"   ✅ Wrote to {output_path}")

            state.mark_processed(inbox_file.path, inbox_file.hash, str(output_path), entry)
            state.save(state_file)
            _archive_inbox_file(inbox_file.path)

            processed_count += 1

        except Exception as e:
            print(f"   ❌ Error: {e}")
            error_count += 1

    print()
    print(f"Summary: {processed_count} processed, {skipped_count} skipped, {error_count} errors")
    sys.exit(1 if error_count > 0 else 0)


def launch_dashboard():
    """Launch the web dashboard."""
    try:
        from serve import app
        import uvicorn

        print("🌐 Launching RatVault Dashboard")
        print("   Open http://localhost:8055")
        uvicorn.run(app, host="127.0.0.1", port=8055)
    except ImportError:
        print("Error: fastapi and uvicorn are required for --serve")
        sys.exit(1)


if __name__ == "__main__":
    main()
