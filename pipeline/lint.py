"""
Wiki health-check: lints for broken references, orphaned pages, stale content.
"""

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple
import yaml


def load_page(path: Path) -> Dict:
    """Load and parse a markdown page with frontmatter."""
    content = path.read_text(encoding="utf-8")
    
    if not content.startswith("---"):
        return None
    
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        return None
    
    try:
        frontmatter = yaml.safe_load(match.group(1))
        body = match.group(2)
        return {
            "path": path,
            "filename": path.name,
            "frontmatter": frontmatter or {},
            "body": body,
            "slug": frontmatter.get("slug") if frontmatter else None,
        }
    except Exception:
        return None


def find_all_pages(notes_dir: Path) -> Dict[str, Dict]:
    """Find all .md files in Notes/ directory."""
    pages = {}
    for md_file in sorted(notes_dir.glob("*.md")):
        if md_file.name.startswith("_") or md_file.name in ["home.md", "README-STRUCTURE.md", "TEMPLATE-ENTITY.md"]:
            continue
        
        page = load_page(md_file)
        if page and page["slug"]:
            pages[page["slug"]] = page
    
    return pages


def extract_cross_refs(page: Dict) -> List[str]:
    """Extract all cross-reference slugs from a page's body."""
    # Look for markdown links: [Text](slug)
    refs = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', page["body"])
    return [slug for _, slug in refs if slug and not slug.startswith("http")]


def lint_wiki(notes_dir: Path = None) -> Dict:
    """Run lint checks on the entire wiki."""
    if notes_dir is None:
        notes_dir = Path("Notes")
    
    if not notes_dir.exists():
        return {"error": f"{notes_dir} not found"}
    
    pages = find_all_pages(notes_dir)
    issues = {
        "missing_frontmatter": [],
        "orphaned_pages": [],
        "broken_refs": [],
        "missing_related": [],
        "stale_pages": [],
        "summary": {},
    }
    
    # Build reference graph
    all_slugs = set(pages.keys())
    ref_count = {}  # How many pages reference each page
    
    for slug, page in pages.items():
        fm = page["frontmatter"]
        
        # Check 1: Missing/incomplete frontmatter
        required = ["title", "slug", "created", "category", "type", "tags"]
        missing = [f for f in required if f not in fm]
        if missing:
            issues["missing_frontmatter"].append({
                "slug": slug,
                "page": page["filename"],
                "missing_fields": missing,
            })
        
        # Check 2: Extract cross-references
        refs_from_body = extract_cross_refs(page)
        refs_from_frontmatter = fm.get("related", [])
        all_refs = set(refs_from_body + refs_from_frontmatter)
        
        for ref_slug in all_refs:
            if ref_slug not in all_slugs:
                issues["broken_refs"].append({
                    "page": slug,
                    "broken_ref": ref_slug,
                    "file": page["filename"],
                })
            else:
                ref_count[ref_slug] = ref_count.get(ref_slug, 0) + 1
        
        # Check 3: Related field consistency
        if "related" in fm and fm["related"]:
            missing_bidirectional = []
            for related_slug in fm["related"]:
                if related_slug in pages:
                    related_page = pages[related_slug]
                    related_fm = related_page["frontmatter"]
                    if slug not in related_fm.get("related", []):
                        missing_bidirectional.append(related_slug)
            
            if missing_bidirectional:
                issues["missing_related"].append({
                    "page": slug,
                    "should_reference": missing_bidirectional,
                })
        
        # Check 4: Stale pages (not updated in 30 days)
        if "ingested_at" in fm:
            try:
                ingested = datetime.fromisoformat(fm["ingested_at"].replace("Z", "+00:00"))
                days_old = (datetime.now(ingested.tzinfo) - ingested).days
                if days_old > 30:
                    issues["stale_pages"].append({
                        "slug": slug,
                        "days_since_update": days_old,
                        "last_updated": fm["ingested_at"],
                    })
            except Exception:
                pass
    
    # Check 5: Orphaned pages (0 references)
    for slug in all_slugs:
        if ref_count.get(slug, 0) == 0 and slug != "home":
            issues["orphaned_pages"].append({
                "slug": slug,
                "references": 0,
            })
    
    # Summary stats
    issues["summary"] = {
        "total_pages": len(pages),
        "total_issues": sum(len(v) for k, v in issues.items() if k != "summary"),
        "orphaned_count": len(issues["orphaned_pages"]),
        "broken_refs_count": len(issues["broken_refs"]),
        "missing_frontmatter_count": len(issues["missing_frontmatter"]),
        "stale_count": len(issues["stale_pages"]),
    }
    
    return issues


def print_lint_report(issues: Dict) -> None:
    """Print a human-readable lint report."""
    summary = issues.get("summary", {})
    
    print("\n" + "="*60)
    print("RATVAULT WIKI LINT REPORT")
    print("="*60)
    
    print(f"\n📊 Summary:")
    print(f"  Total pages: {summary.get('total_pages', 0)}")
    print(f"  Total issues: {summary.get('total_issues', 0)}")
    
    if issues["orphaned_pages"]:
        print(f"\n🔴 Orphaned Pages ({len(issues['orphaned_pages'])}):")
        print("   (Pages with 0 references - consider merging or deleting)")
        for item in issues["orphaned_pages"]:
            print(f"     - {item['slug']}")
    
    if issues["broken_refs"]:
        print(f"\n🔴 Broken References ({len(issues['broken_refs'])}):")
        print("   (Links to pages that don't exist)")
        for item in issues["broken_refs"][:5]:
            print(f"     - {item['page']} → {item['broken_ref']}")
        if len(issues["broken_refs"]) > 5:
            print(f"     ... and {len(issues['broken_refs']) - 5} more")
    
    if issues["missing_frontmatter"]:
        print(f"\n⚠️  Missing Frontmatter ({len(issues['missing_frontmatter'])}):")
        for item in issues["missing_frontmatter"][:3]:
            print(f"     - {item['page']}: missing {item['missing_fields']}")
        if len(issues["missing_frontmatter"]) > 3:
            print(f"     ... and {len(issues['missing_frontmatter']) - 3} more")
    
    if issues["missing_related"]:
        print(f"\n⚠️  Missing Bidirectional Links ({len(issues['missing_related'])}):")
        print("   (Page A references B, but B doesn't reference A back)")
        for item in issues["missing_related"][:3]:
            print(f"     - {item['page']} should back-reference: {item['should_reference']}")
        if len(issues["missing_related"]) > 3:
            print(f"     ... and {len(issues['missing_related']) - 3} more")
    
    if issues["stale_pages"]:
        print(f"\n⏰ Stale Pages ({len(issues['stale_pages'])}):")
        print("   (Not updated in 30+ days - verify accuracy)")
        for item in sorted(issues["stale_pages"], key=lambda x: x["days_since_update"], reverse=True)[:5]:
            print(f"     - {item['slug']}: {item['days_since_update']} days old")
        if len(issues["stale_pages"]) > 5:
            print(f"     ... and {len(issues['stale_pages']) - 5} more")
    
    if summary.get("total_issues", 0) == 0:
        print("\n✅ Wiki is healthy! All checks passed.")
    
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    issues = lint_wiki()
    print_lint_report(issues)
