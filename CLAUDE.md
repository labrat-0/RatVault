# RatVault: LLM Wiki Architecture

Following Andrej Karpathy's **persistent, compounding knowledge artifact** pattern.

## Three-Layer Architecture

### 1. Raw Sources (`inbox/`)
Immutable, unprocessed documents:
- `.md` files (articles, notes, research)
- Text extracts from PDFs, web pages
- Copies of external resources
- Always append-only, never modify

**Ingestion entry point**: `python ingest.py`

### 2. The Wiki (`Notes/`)
LLM-generated structured knowledge:
- **Entity pages** (topics, concepts, people, tools) - one per major concept
- **Concept pages** (detailed explanations, relationships)
- **Reference pages** (quick lookups, definitions)
- **Cross-references** (links between related pages)
- **Summaries** (auto-generated from sources)

**Structure per page**:
```yaml
---
title: "Entity/Concept Name"
slug: "entity-slug"
created: "2026-05-02"
ingested_at: "2026-05-02T..."
category: development|science|tools|reference
type: entity|concept|summary
tags: [tag1, tag2]
related: [slug1, slug2]  # Cross-references
---

# Title

## Definition / Overview
Core explanation (1-2 paragraphs)

## Key Properties / Concepts
- Property 1: Explanation
- Property 2: Explanation

## Related Concepts
- [Concept Name](concept-slug) - brief connection
- [Other Concept](other-slug) - brief connection

## Sources
- Source title and link
```

### 3. The Schema (`config.yaml` + this file)
Configuration & conventions:
- Provider settings (Ollama, OpenAI, OpenRouter, etc.)
- Temperature, model selection
- Wiki structure guidelines
- Ingest/Query/Lint rules
- Operational patterns

## Three Operations

### Ingest
Process new sources → integrate into wiki:

```bash
# Add .md files to inbox/
python ingest.py                    # Process inbox/
python ingest.py --dry-run          # Preview changes
python ingest.py --force            # Reprocess everything
python ingest.py --provider ollama  # Use specific provider
```

**Ingest workflow**:
1. Discover new files in `inbox/`
2. Parse frontmatter + content
3. Query LLM: Extract key entities, concepts, cross-references
4. **Update or create** entity pages in `Notes/`
5. **Add cross-references** to related existing pages
6. **Mark sources** with ingestion timestamp
7. Compute embeddings for semantic search

### Query
Search wiki + synthesize answers:

**In RatVault UI**:
- Type in Chat: Searches relevant Notes/ pages
- LLM synthesizes answer using vault as context
- Valuable results → convert to permanent wiki pages

**CLI** (future):
```bash
python ingest.py --query "what is X?"  # Search + answer
```

### Lint
Health-check wiki for consistency & gaps:

**Checks**:
- Orphaned pages (unreferenced entities)
- Broken cross-references (links to missing pages)
- Contradictions (conflicting definitions)
- Stale claims (ingested before, not updated)
- Missing tags or frontmatter
- Pages without related concepts

**Command** (future):
```bash
python ingest.py --lint             # Report issues
python ingest.py --lint --fix       # Auto-fix basic issues
```

## Key Design Principles

1. **Compilation, not retrieval**: The wiki is pre-computed once, kept current. Not re-derived on every query.

2. **Cross-references are persistent**: When you link Entity A to Entity B, that relationship survives. RAG systems re-derive these constantly.

3. **Human direction, LLM execution**: You decide what goes in `inbox/`, what entities matter. LLM handles summarization, linking, maintenance.

4. **Frontmatter is canonical**: Tags, categories, related pages live in frontmatter. The LLM updates these as it ingest sources.

5. **No stale ingestions**: Every ingest run either updates a page or leaves it alone. Pages know when they were last touched.

## File Structure

```
RatVault/
├── inbox/                 # Raw sources (append-only)
│   ├── article1.md
│   ├── research-notes.md
│   └── extracted-from-pdf.md
├── Notes/                 # The wiki (LLM-maintained)
│   ├── home.md            # Index/entry point
│   ├── entity-names.md    # Entity pages
│   ├── concept-name.md
│   └── reference-list.md
├── config.yaml            # Provider/model config (schema layer)
├── ingest.py              # Main pipeline
└── pipeline/
    ├── ingest.py          # Source processing
    ├── parser.py          # Frontmatter/content extraction
    ├── prompts.py         # LLM instructions
    ├── providers.py       # API clients (Ollama, OpenAI, etc.)
    ├── models.py          # Data structures
    └── writer.py          # Persist wiki updates
```

## Wiki Maintenance

**Weekly**:
- Run `ingest.py` to process new inbox items
- Review cross-reference suggestions
- Update related concepts on entity pages

**Monthly**:
- Run `lint` to find orphaned/broken pages
- Deprecate outdated claims
- Merge similar entities (consolidate)

**As needed**:
- Query to explore connections
- Add new sources to inbox/
- Manually refine entity definitions

## Example: Processing a New Source

1. **Raw source**: Save article to `inbox/learning-ml.md`
2. **Ingest runs**:
   - Extracts: "Machine Learning is..."
   - Creates/updates: `Notes/machine-learning.md`
   - Adds cross-ref: Links ML → Neural Networks, → Backprop, etc.
   - Updates existing: `Notes/neural-networks.md` now references ML
3. **Result**: Unified, interconnected wiki grows richer with every source

## Interaction Patterns

### Pattern: Explore a Topic
1. Query: "Tell me about transformers"
2. LLM searches `Notes/transformers.md`
3. Returns definition + related: attention, BERT, scaling laws
4. Follow links in the result to dive deeper

### Pattern: Find Connections
1. Query: "What's the relationship between neural scaling and compute?"
2. LLM finds pages linking both topics
3. Synthesizes connection, updates `Notes/scaling-laws.md` to strengthen the link

### Pattern: Ingest and Integrate
1. Read a paper on transformers
2. Copy key parts to `inbox/transformer-paper-2023.md`
3. Run ingest
4. LLM updates `Notes/transformers.md` with new findings
5. Cross-references are automatically updated
6. Next query about transformers gets latest info

## Configuration

See `config.yaml` for:
- `provider`: ollama | openai | anthropic | openrouter
- `model`: Model name/ID (can fetch available models in UI)
- `temperature`: 0.1-0.9 (lower = consistency, higher = creativity)
- `ollama_base_url`: http://localhost:11434 (if using local)
- API keys: Stored in config.yaml (see .env.example)

## Next Steps

- [ ] Implement full Lint operation
- [ ] Add entity disambiguation (same concept, multiple names)
- [ ] Auto-generate table of contents for Categories
- [ ] Semantic similarity clustering (find related pages)
- [ ] Git-based versioning for wiki changes
- [ ] Diff view: before/after ingest

---

**Inspired by**: [Karpathy's LLM Wiki](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)

Last updated: 2026-05-02
