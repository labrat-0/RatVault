#!/usr/bin/env python3
"""RatVault ingest pipeline - main entry point."""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from pipeline.config import load_config, setup_wizard
from pipeline.media import extract_and_rewrite_media
from pipeline.models import (
    IngestState,
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
        choices=["openai", "anthropic", "ollama", "openrouter"],
        help="Override provider",
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
        "input_path",
        nargs="?",
        help="File or directory to ingest (default: inbox/)",
    )

    args = parser.parse_args()

    if args.setup:
        setup_wizard()
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
    provider_config = config.get_provider_config()

    processed_count = 0
    skipped_count = 0
    error_count = 0

    for inbox_file in inbox_files:
        if state.is_already_processed(inbox_file.path, inbox_file.hash) and not args.force:
            print(f"⏭️  Skipping {inbox_file.path.name} (already processed)")
            skipped_count += 1
            continue

        print(f"📄 Processing {inbox_file.path.name}...")

        try:
            raw_content, detected_title = parse_input_file(inbox_file.path)
            raw_content = strip_frontmatter(raw_content)

            if args.dry_run:
                print(f"   Title: {detected_title or '(auto-detect)'}")
                print(f"   Size: {len(raw_content)} chars")
                print()
                continue

            entry_slug = slugify(detected_title or inbox_file.path.stem)

            assets_dir = Path(config.assets_dir)
            content_with_media, asset_records = extract_and_rewrite_media(
                raw_content,
                inbox_file.path,
                assets_dir,
                entry_slug,
            )

            prompt = ENRICHMENT_USER.format(content=content_with_media)
            enrichment = call_llm_json(
                prompt,
                ENRICHMENT_SYSTEM,
                provider_config,
            )

            now = datetime.now(timezone.utc)
            entry = VaultEntry(
                title=enrichment.get("title", detected_title or "Untitled"),
                slug=slugify(enrichment.get("title", entry_slug)),
                created=now.strftime("%Y-%m-%d"),
                ingested_at=now.isoformat(),
                summary=enrichment.get("summary", ""),
                tags=enrichment.get("tags", []),
                category=enrichment.get("category", "reference"),
                difficulty=enrichment.get("difficulty", "intermediate"),
                key_concepts=enrichment.get("key_concepts", []),
                questions_answered=enrichment.get("questions_answered", []),
                source_file=inbox_file.path.name,
                source_hash=inbox_file.hash[:8],
                provider=config.provider,
                model=config.model,
                assets=asset_records,
            )

            output_path = write_entry(entry, content_with_media, output_dir)
            print(f"   ✅ Wrote to {output_path.relative_to(Path.cwd())}")

            state.mark_processed(inbox_file.path, inbox_file.hash, str(output_path), entry)
            state.save(state_file)

            processed_count += 1

        except LLMError as e:
            print(f"   ❌ LLM error: {e}")
            error_count += 1
        except Exception as e:
            print(f"   ❌ Error: {e}")
            error_count += 1

    print()
    print(f"Summary: {processed_count} processed, {skipped_count} skipped, {error_count} errors")


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
