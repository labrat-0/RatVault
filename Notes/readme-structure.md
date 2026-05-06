# RatVault Wiki Structure Guide

This document defines the structure and conventions for pages in the RatVault wiki.

## Page Organization

All pages go in `Notes/`. Use the template: `TEMPLATE-ENTITY.md`

### Frontmatter (Required)

Every page must have YAML frontmatter with:

```yaml
---
title: "Human-readable title"
slug: "lowercase-url-slug"  # Used for cross-references
created: "2026-05-02"  # ISO date
ingested_at: "2026-05-02T12:00:00Z"  # ISO datetime of last ingest
category: "development|science|tools|reference|concepts"
type: "entity|concept|reference|summary"
tags: ["tag1", "tag2"]  # 3-5 tags for categorization
related: ["slug1", "slug2"]  # Slugs of related pages
sources:
  - title: "Source name"
    date: "2026-05-01"
    note: "Optional: where info came from"
---
```

### Content Sections

**Required**:
- **Definition / Overview** — What is this?
- **Key Properties** — Bullet list of main attributes

**Optional (use as needed)**:
- **How It Works / Core Concepts** — Mechanics/explanation
- **Related Concepts** — Links to other wiki pages
- **Applications / Use Cases** — Real-world examples
- **Common Misconceptions** — What people get wrong
- **See Also** — Additional references

## Cross-References

Link between pages using markdown:

```markdown
[Page Title](page-slug)
```

**Rules**:
1. Always link to the page `slug`, not the filename
2. Put brief explanation after link: `[Title](slug) — explanation`
3. Keep related links grouped in "Related Concepts" section
4. Bidirectional: if A links to B, update B's `related:` frontmatter with A's slug

## Example: Neural Networks Page

```markdown
---
title: "Neural Networks"
slug: "neural-networks"
created: "2026-05-01"
ingested_at: "2026-05-02T10:30:00Z"
category: "science"
type: "entity"
tags: ["ml", "deep-learning", "neurons", "optimization"]
related: ["backpropagation", "transformers", "gradient-descent"]
sources:
  - title: "Deep Learning (Goodfellow et al.)"
    date: "2016"
---

# Neural Networks

## Definition
Neural networks are computational models inspired by biological neurons...

## Key Properties
- **Layers**: Input, hidden, output layers
- **Activation**: Non-linear functions enabling expressiveness
- **Parameters**: Weights and biases adjusted during training

## How They Work

### Forward Pass
Data flows through layers, transformed by weights and activations.

### Backpropagation
Errors propagate backward to adjust weights via gradient descent.

## Related Concepts
- [Backpropagation](backpropagation) — mechanism for training networks
- [Gradient Descent](gradient-descent) — optimization algorithm
- [Transformers](transformers) — modern architecture based on attention
- [Activation Functions](activation-functions) — introduce non-linearity

## Applications
- Image classification
- Natural language processing
- Game-playing (AlphaGo)

## See Also
- [Deep Learning](deep-learning) — broader field
- [Convolutional Networks](conv-nets) — variant for images
```

## Naming Conventions

| Type | Example | Slug |
|------|---------|------|
| Concept | "Backpropagation" | `backpropagation` |
| Tool | "PyTorch" | `pytorch` |
| Person | "Andrej Karpathy" | `andrej-karpathy` |
| Technique | "Transfer Learning" | `transfer-learning` |
| Field | "Machine Learning" | `machine-learning` |

Use lowercase, hyphens for spaces.

## Maintenance

**When ingesting a new source**:
1. Does an entity page exist for this topic? If not, create one.
2. Add the source to that page's `sources:` list
3. Update `ingested_at:` timestamp
4. Check if new cross-references should be added (update `related:`)
5. Update related pages that should reference this one

**Weekly lint**:
- Run `python ingest.py --lint` (when available)
- Check for orphaned pages (0 cross-references)
- Verify broken links (related: slugs that don't exist)

## Tips

1. **Be specific**: "Transformers" not "Neural Network Architecture"
2. **Link liberally**: If another page is relevant, link it
3. **Keep it current**: Update when new sources ingested
4. **One concept per page**: Avoid mega-pages; split complex topics
5. **Timestamps matter**: `ingested_at` shows when page was last updated

---

**Last updated**: 2026-05-02  
**Total pages**: [run `ls Notes/*.md | wc -l` to count]  
**Cross-references**: [run `grep -h "related:" Notes/*.md | wc -l` to count]  

