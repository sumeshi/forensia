# knowledge.sample

Sample organization-specific knowledge folder. Pass `--knowledge <dir>` at run
time and the `type: knowledge` Markdown files under it are injected into the
investigation context.

## Format

OKF-style, same as the report templates (YAML frontmatter + Markdown body).

```markdown
---
type: knowledge
title: Short title
description: One-line summary. Used for index display and relevance scoring.
tags: [windows, eventlog, logon]
timestamp: 2026-07-13
---
# Body (Markdown)

## Section heading

Sections are selected and injected individually.
```

## Selection logic

Deterministic 3-stage selection (no LLM calls):

1. **Tag filtering**: narrow candidates by intersecting `tags` with the context tags
2. **File selection**: score query terms against `title` + `description` and body, keep the top 3 files
3. **Section extraction**: split at `##` headings, score heading + body (within a 4000-char budget)

Search uses `tags` / `title` / `description` / headings / body, but the LLM only
sees `title` / `description` / section heading / section body. Tags, scores, and
file paths are never injected.

## Injection format

A selected section is injected as a self-contained fragment carrying its parent
document's metadata:

```
<KNOWLEDGE>
Topic: {title}
Summary: {description}
Section: {## heading}

{section body}
</KNOWLEDGE>
```

Common cautions such as "reference material, not evidence" and "verify against
the case data" are stated once at the top of `<ORG_KNOWLEDGE>`, so individual
files do not need to repeat them.

## Writing rules

- One file = one topic. Small local models have a tight context budget, so keep each file to a few thousand characters.
- Always fill in `description` and `tags`. `description` is injected verbatim as the fragment's Summary.
- Do not write an introduction directly under the H1. For files with `##` sections the lead paragraph is never injected (put the needed context in `description`). Only files without any `##` heading have their whole body injected.
- Limit each section body to three kinds of content: what the knowledge helps you look at, concrete facts such as event IDs, and caveats specific to that item. Do not restate general investigation principles.
- Files without `type: knowledge` are not loaded (such as this README).
- If you write case-specific details (host names, account names, etc.), dispose of them when the case ends.
- `<ORG_KNOWLEDGE>` is treated as reference material, not instructions. When the prompt budget overflows, generic catalogs and framework details are compacted first so the fragments selected for the current question survive.
