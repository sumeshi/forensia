# docs

A set of design documents objectively describing the current implementation of forensia. When you change code, update these in the same PR.

## Overview

| Document | Contents |
|---|---|
| [architecture.md](architecture.md) | Pipeline overview. Per-stage data flow, report generation, API snapshots, directory structure, configuration |
| [design-principles.md](design-principles.md) | Design principles. Three-layer state separation, LLM output handling, traceability, role granularity, SQL safety, conceptual model boundaries |

## Details

| Document | Contents |
|---|---|
| [data-model.md](data-model.md) | DuckDB tables, `memory/*.md` persistent memory, API DTO definitions |
| [code-map.md](code-map.md) | Responsibilities of each file in `src/forensia/**` |
| [llm-roles.md](llm-roles.md) | Timing, inputs, and output schemas of the 11 LLM roles |
| [report-pipeline.md](report-pipeline.md) | Details of report section filling. Template contracts, quality gates, internals of the hypothesis verification loop |
| [rules-and-profiles.md](rules-and-profiles.md) | Specifications for Rulepack / Profile / Allowlist. File listing of the declaration layer (`_schema/`) |

## Development

| Document | Contents |
|---|---|
| [development.md](development.md) | Development environment setup, testing policy, auxiliary scripts, CLI flags, UI details |
| [extending.md](extending.md) | Cookbook for adding artifacts, rules, questions, report blocks, tables, and quality gates |

## Publication and operational notes

| Document | Contents |
|---|---|
| [../SECURITY.md](../SECURITY.md) | Handling of sensitive forensic data, `.env`, case outputs, and vulnerability reporting |
