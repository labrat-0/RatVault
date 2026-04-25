"""LLM prompt templates for RatVault enrichment."""


ENRICHMENT_SYSTEM = (
    "You are a knowledge vault assistant. You process raw notes and extract "
    "structured metadata. Respond ONLY with valid JSON, no markdown fences."
)

ENRICHMENT_USER = """Given this raw note, extract and return a JSON object with these exact keys:
- "title": concise descriptive title (max 80 chars)
- "summary": 2-3 sentence plain-text summary
- "tags": array of 5-10 lowercase kebab-case tags
- "category": one of: security, development, research, personal, reference, workflow
- "key_concepts": array of up to 5 key technical terms or concepts
- "questions_answered": array of 2-3 questions this note answers
- "difficulty": one of: beginner, intermediate, advanced

Raw note:
---
{content}
---"""


CROSS_REFS_SYSTEM = (
    "You are a knowledge vault assistant. You suggest related entries based on content. "
    "Respond ONLY with valid JSON, no markdown fences."
)

CROSS_REFS_USER = """Given this note's summary and tags, and these existing vault entries,
suggest 2-5 relevant entries to link using their exact titles. Return valid JSON:
{{"cross_refs": ["Title One", "Title Two"]}}

New note summary: {summary}
New note tags: {tags}

Existing vault entries (title, tags):
{existing_entries}

Return JSON object only."""
