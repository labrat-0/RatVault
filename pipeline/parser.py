"""File parsing for RatVault ingest."""

import re
import sys
from pathlib import Path
from typing import Optional, Tuple

from pipeline.models import InboxFile, compute_binary_hash, compute_file_hash

IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}


def parse_input_file(path: Path) -> Tuple[str, Optional[str]]:
    """
    Parse an input file and return raw content and detected title.

    Args:
        path: Path to input file (.md, .txt, .pdf)

    Returns:
        Tuple of (content, detected_title)
    """
    content = _read_file(path)
    title = _extract_title(content)
    return content, title


def _read_file(path: Path) -> str:
    """Read file content, handling different formats."""
    if path.suffix.lower() in IMAGE_EXTENSIONS:
        return f"# {path.stem}\n\nImage file: {path.name}"
    if path.suffix == ".pdf":
        return _read_pdf(path)
    else:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"Error reading {path}: {e}", file=sys.stderr)
            return ""


def _read_pdf(path: Path) -> str:
    """Read PDF file and extract text."""
    try:
        from pypdf import PdfReader
    except ImportError:
        print(f"Warning: pypdf not installed, skipping PDF: {path}", file=sys.stderr)
        return ""

    try:
        reader = PdfReader(path)
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        print(f"Error reading PDF {path}: {e}", file=sys.stderr)
        return ""


def _extract_title(content: str) -> Optional[str]:
    """Extract title from content (first H1 in markdown)."""
    lines = content.split("\n")
    for line in lines:
        if line.startswith("# "):
            return line[2:].strip()
    return None


def strip_frontmatter(content: str) -> str:
    """Remove existing YAML frontmatter from content."""
    if not content.startswith("---"):
        return content

    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if match:
        return match.group(2).strip()

    return content


def discover_inbox_files(inbox_dir: Path) -> list[InboxFile]:
    """
    Discover all input files in inbox directory.

    Args:
        inbox_dir: Path to inbox folder

    Returns:
        List of InboxFile objects
    """
    if not inbox_dir.exists():
        return []

    files = []
    for path in inbox_dir.glob("*"):
        if path.is_file() and path.suffix.lower() in (".md", ".txt", ".pdf", *IMAGE_EXTENSIONS):
            try:
                if path.suffix.lower() in IMAGE_EXTENSIONS:
                    raw_bytes = path.read_bytes()
                    file_hash = compute_binary_hash(raw_bytes)
                    detected_title = path.stem.replace('-', ' ').replace('_', ' ').title()
                    files.append(InboxFile(path=path, hash=file_hash, size=path.stat().st_size, detected_title=detected_title))
                    continue
                content = _read_file(path)
                file_hash = compute_file_hash(content)
                detected_title = _extract_title(content)
                files.append(
                    InboxFile(
                        path=path,
                        hash=file_hash,
                        size=path.stat().st_size,
                        detected_title=detected_title,
                    )
                )
            except Exception as e:
                print(f"Error discovering {path}: {e}", file=sys.stderr)

    return files
