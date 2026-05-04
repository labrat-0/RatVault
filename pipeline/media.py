"""Media extraction and handling for RatVault."""

import re
import shutil
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from pipeline.models import AssetRecord, slugify


def extract_and_rewrite_media(
    content: str,
    source_path: Path,
    assets_dir: Path,
    entry_slug: str,
) -> tuple[str, list[AssetRecord]]:
    """
    Extract media from content, copy/download assets, and rewrite paths.

    Args:
        content: Raw markdown content
        source_path: Path to source file (for relative asset resolution)
        assets_dir: Path to assets directory (for output)
        entry_slug: Slug for the vault entry

    Returns:
        Tuple of (rewritten_content, asset_records)
    """
    assets = []
    modified_content = content

    images_dir = assets_dir / "images" / entry_slug
    videos_dir = assets_dir / "videos" / entry_slug

    modified_content, image_assets = _handle_images(
        modified_content,
        source_path,
        images_dir,
        entry_slug,
    )
    assets.extend(image_assets)

    modified_content, video_assets = _handle_videos(modified_content, videos_dir, entry_slug)
    assets.extend(video_assets)

    return modified_content, assets


def _handle_images(
    content: str,
    source_path: Path,
    images_dir: Path,
    entry_slug: str,
) -> tuple[str, list[AssetRecord]]:
    """Handle local and remote images."""
    assets = []
    modified_content = content

    local_image_pattern = r"!\[([^\]]*)\]\(([^)]+)\)"
    wikilink_pattern = r"!\[\[([^\]]+)\]\]"

    for match in re.finditer(local_image_pattern, content):
        alt_text = match.group(1)
        image_path = match.group(2)

        if not image_path.startswith(("http://", "https://")):
            new_path, asset_record = _copy_local_image(
                image_path, source_path, images_dir, entry_slug
            )
            if new_path:
                new_markdown = f"![{alt_text}]({new_path})"
                modified_content = modified_content.replace(match.group(0), new_markdown)
                assets.append(asset_record)

    for match in re.finditer(wikilink_pattern, content):
        image_name = match.group(1)
        new_path, asset_record = _copy_local_image(
            image_name, source_path, images_dir, entry_slug
        )
        if new_path:
            new_markdown = f"![[{new_path}]]"
            modified_content = modified_content.replace(match.group(0), new_markdown)
            assets.append(asset_record)

    return modified_content, assets


def _copy_local_image(
    image_path: str,
    source_path: Path,
    images_dir: Path,
    entry_slug: str,
) -> tuple[Optional[str], Optional[AssetRecord]]:
    """Copy a local image file to assets."""
    source_dir = source_path.parent.resolve()

    try:
        image_full_path = (source_dir / image_path).resolve()
        image_full_path.relative_to(source_dir)  # raises ValueError if outside source_dir
    except ValueError:
        print(f"Warning: Image path escapes source directory: {image_path}", file=sys.stderr)
        return None, None

    if not image_full_path.exists():
        print(f"Warning: Image not found: {image_path}", file=sys.stderr)
        return None, None

    if not image_full_path.is_file():
        return None, None

    images_dir.mkdir(parents=True, exist_ok=True)
    dest_path = images_dir / image_full_path.name

    try:
        shutil.copy2(image_full_path, dest_path)

        relative_path = f"assets/images/{entry_slug}/{dest_path.name}"

        asset = AssetRecord(
            type="image",
            original_name=image_full_path.name,
            vault_path=relative_path,
        )

        return relative_path, asset
    except Exception as e:
        print(f"Error copying image {image_path}: {e}", file=sys.stderr)
        return None, None


def _handle_videos(
    content: str,
    videos_dir: Path,
    entry_slug: str,
) -> tuple[str, list[AssetRecord]]:
    """Detect YouTube/Vimeo URLs and wrap in callout; copy local video files."""
    assets = []
    modified_content = content

    youtube_pattern = r"(https?://)?(www\.)?(youtube|youtu|youtube-nocookie)\.(com|be)/\S+"
    vimeo_pattern = r"https?://(www\.)?vimeo\.com/\d+"

    youtube_matches = list(re.finditer(youtube_pattern, content))
    for match in reversed(youtube_matches):
        url = match.group(0)
        if url.startswith("http"):
            wrapped = f"> [!video]\n> {url}"
            modified_content = modified_content[: match.start()] + wrapped + modified_content[match.end() :]

    vimeo_matches = list(re.finditer(vimeo_pattern, content))
    for match in reversed(vimeo_matches):
        url = match.group(0)
        wrapped = f"> [!video]\n> {url}"
        modified_content = modified_content[: match.start()] + wrapped + modified_content[match.end() :]

    return modified_content, assets


def sanitize_text(text: str, max_length: int = 4000) -> str:
    """Remove control characters and truncate text."""
    text = "".join(c for c in text if ord(c) >= 32 or c in ("\t", "\n", "\r"))
    return text[:max_length]
