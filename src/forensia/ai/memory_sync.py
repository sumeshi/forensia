"""Apply checker memory_updates to case memory: facts, timeline, tasks, entities, hypothesis cards."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from forensia.ai.hypotheses.hypothesis_store import _render_hypothesis_memory
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.session import ENTITY_ROLES, Hypothesis
from forensia.core.textutil import token_set_similarity
from forensia.db.database import CaseDB

_HARD_CLAIM_WORDS = {
    "confirmed",
    "attack",
    "compromised",
    "breach",
    "intrusion",
    "exfiltration",
}


@dataclass(slots=True)
class _MemoryUpdateContext:
    memory: MemoryManager
    active_hypotheses: list[Hypothesis]
    resolved_hypotheses: list[Hypothesis]
    check_output: dict[str, Any]
    updates: dict[str, Any]
    verdict: str
    is_confirmed: bool
    provisional: bool
    current_hypothesis_id: str | None
    db: CaseDB | None
    query_id: str | None
    hypothesis_description: str | None


def _has_multi_source_evidence(evidence_ids: list[str], min_sources: int = 2) -> bool:
    """Check whether evidence IDs span at least min_sources different artifact source prefixes."""
    if not evidence_ids:
        return False
    sources: set[str] = set()
    for eid in evidence_ids:
        eid_str = str(eid).strip().lower()
        if eid_str.startswith("evtx"):
            sources.add("evtx")
        elif eid_str.startswith("mft"):
            sources.add("mft")
        elif eid_str.startswith("prefetch"):
            sources.add("prefetch")
        elif eid_str.startswith("file"):
            sources.add("file")
        elif eid_str.startswith("reg"):
            sources.add("registry")
        else:
            sources.add("other")
    return len(sources) >= min_sources


def _render_entity_memory(
    entity_type: str, name: str, notes: str, role: str = ""
) -> str:
    """Generate a Markdown entity memory block from type, name, role, and notes."""
    normalized_type = str(entity_type).strip().lower() or "entity"
    normalized_name = str(name).strip()
    lines = [
        f"# {normalized_type}: {normalized_name}",
        "",
        f"- type: {normalized_type}",
        f"- name: {normalized_name}",
    ]
    normalized_role = str(role).strip().lower()
    if normalized_role in ENTITY_ROLES and normalized_role != "unknown":
        lines.append(f"- role: {normalized_role}")
    note_text = str(notes).strip()
    if note_text:
        lines.append(f"- notes: {note_text}")
    return "\n".join(lines).rstrip() + "\n"


def _apply_fact_updates(ctx: _MemoryUpdateContext) -> None:
    for item in ctx.updates.get("facts") or []:
        if not isinstance(item, dict):
            continue
        fact_text = str(item.get("text") or "")
        evidence_ids = [str(e) for e in (item.get("evidence_ids") or [])]
        claim_type = str(item.get("claim_type") or "observation").strip().lower()
        is_interpretation = claim_type == "interpretation"
        fact_provisional = ctx.provisional or (
            is_interpretation and not _has_multi_source_evidence(evidence_ids)
        )
        ctx.memory.append_confirmed_fact(
            fact_text,
            evidence_ids,
            hypothesis_id=ctx.current_hypothesis_id,
            provisional=fact_provisional,
        )


def _apply_timeline_updates(ctx: _MemoryUpdateContext) -> None:
    for item in ctx.updates.get("timeline") or []:
        if not isinstance(item, dict):
            continue
        ctx.memory.append_timeline_anchor(
            str(item.get("timestamp") or ""),
            str(item.get("description") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
            hypothesis_id=ctx.current_hypothesis_id,
            provisional=ctx.provisional,
        )


def _apply_task_updates(ctx: _MemoryUpdateContext) -> None:
    for item in ctx.updates.get("tasks") or []:
        if not isinstance(item, dict):
            continue
        ctx.memory.append_task(
            str(item.get("text") or item.get("question") or ""),
            str(item.get("kind") or ""),
            hypothesis_id=ctx.current_hypothesis_id,
            provisional=ctx.provisional,
        )


def _has_new_nonobserved_entity(ctx: _MemoryUpdateContext) -> bool:
    for item in ctx.updates.get("entities") or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip().lower()
        if role == "observed_user":
            continue
        name = str(item.get("name") or "").strip()
        etype = str(item.get("entity_type") or "").strip()
        if name and etype:
            ent_path = ctx.memory._entity_path(etype, name)
            if ent_path and not ent_path.exists():
                return True
    return False


def _artifact_overview_families(ctx: _MemoryUpdateContext) -> set[str]:
    families: set[str] = set()
    for item in ctx.updates.get("facts") or []:
        if isinstance(item, dict):
            for eid in item.get("evidence_ids") or []:
                family = str(eid).split("-")[0] if "-" in str(eid) else str(eid)
                if family:
                    families.add(family)
    return families


def _has_new_artifact_family(ctx: _MemoryUpdateContext, families: set[str]) -> bool:
    if not families:
        return False
    facts_text = ""
    try:
        if ctx.memory.facts_path.exists():
            facts_text = ctx.memory.facts_path.read_text(encoding="utf-8")
    except Exception:
        facts_text = ""
    return any(f"evidence: {family}-" not in facts_text for family in families)


def _should_write_overview(ctx: _MemoryUpdateContext) -> bool:
    is_resolution = ctx.verdict in ("confirmed", "refuted", "untestable")
    families = _artifact_overview_families(ctx)
    return (
        is_resolution
        or _has_new_nonobserved_entity(ctx)
        or _has_new_artifact_family(ctx, families)
    )


def _append_overview_item(ctx: _MemoryUpdateContext, item: Any) -> None:
    item_str = str(item)
    item_lower = item_str.lower()
    if ctx.verdict == "refuted" and re.search(
        r"the hypothesis regarding .* was refuted", item_str, re.IGNORECASE
    ):
        _log("MEMORY", "R3-09: skipped refuted-template overview line")
        return
    has_hard_claim = any(w in item_lower for w in _HARD_CLAIM_WORDS)
    if has_hard_claim and not ctx.is_confirmed:
        ctx.memory.append_confirmed_fact(
            item_str,
            [],
            hypothesis_id=ctx.current_hypothesis_id,
            provisional=True,
        )
    elif (
        "could not be confirmed" in item_lower
        or "inconclusive" in item_lower
        or "no evidence" in item_lower
    ):
        ctx.memory.append_confirmed_fact(
            item_str,
            [],
            hypothesis_id=ctx.current_hypothesis_id,
            provisional=True,
        )
    elif _is_duplicate_overview_item(ctx.memory.load_overview(), item_str):
        _log("MEMORY", "overview dedup: skipped similar item")
    else:
        ctx.memory.append_overview(item_str)


def _is_duplicate_overview_item(overview_text: str, item_str: str) -> bool:
    recent_lines = [ln.strip() for ln in overview_text.split("\n") if ln.strip()]
    item_tokens = set(item_str.lower().split())
    if not item_tokens:
        return False
    for line in recent_lines:
        line_tokens = set(line.lower().split())
        if line_tokens:
            sim = token_set_similarity(item_str, line)
            if sim > 0.7:
                return True
    return False


def _apply_overview_updates(ctx: _MemoryUpdateContext) -> None:
    overview_items = ctx.updates.get("overview") or []
    if overview_items and _should_write_overview(ctx):
        for item in overview_items[:1]:
            _append_overview_item(ctx, item)


def _append_confirmed_hypothesis_fact(ctx: _MemoryUpdateContext) -> None:
    if not (ctx.is_confirmed and ctx.hypothesis_description and ctx.query_id):
        return
    evidence_ids: list[str] = []
    for item in ctx.updates.get("facts") or []:
        if isinstance(item, dict):
            evidence_ids.extend(
                str(e) for e in (item.get("evidence_ids") or []) if str(e).strip()
            )
    ctx.memory.append_confirmed_hypothesis_fact(
        hypothesis_description=ctx.hypothesis_description,
        verdict=ctx.verdict,
        query_id=ctx.query_id,
        evidence_ids=evidence_ids,
    )


def _apply_refuted_hypothesis_updates(ctx: _MemoryUpdateContext) -> None:
    for item in ctx.updates.get("refuted_hypotheses") or []:
        if not isinstance(item, dict):
            continue
        ctx.memory.append_refuted_hypothesis(
            str(item.get("hypothesis_id") or ""),
            str(item.get("description") or ""),
            str(item.get("reason") or ""),
        )


def _apply_resolved_gap_updates(ctx: _MemoryUpdateContext) -> None:
    for item in ctx.updates.get("resolved_gaps") or []:
        if not isinstance(item, dict):
            continue
        ctx.memory.append_resolved_gap(
            str(item.get("text") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )


def _apply_entity_updates(ctx: _MemoryUpdateContext) -> None:
    for item in ctx.updates.get("entities") or []:
        if not isinstance(item, dict):
            continue
        entity_type = str(item.get("entity_type") or "")
        entity_name = str(item.get("name") or "")
        entity_role = str(item.get("role") or "")
        notes = str(item.get("notes") or "")
        content = str(item.get("content") or "").strip() or _render_entity_memory(
            entity_type, entity_name, notes, entity_role
        )
        ctx.memory.upsert_entity(entity_type, entity_name, content)


def _rewrite_hypothesis_memories(ctx: _MemoryUpdateContext) -> None:
    for hypothesis in ctx.active_hypotheses:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(ctx.db, hypothesis)
        ctx.memory.upsert_hypothesis(hypothesis.id, slug, content)
    for hypothesis in ctx.resolved_hypotheses:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(None, hypothesis)
        ctx.memory.upsert_hypothesis(hypothesis.id, slug, content)


def _apply_memory_updates(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
    check_output: dict[str, Any],
    current_hypothesis_id: str | None = None,
    db: CaseDB | None = None,
    query_id: str | None = None,
    hypothesis_description: str | None = None,
) -> None:
    """Persist facts, timeline, tasks, entities, and hypothesis cards from a check output."""
    updates = check_output.get("memory_updates") or {}
    verdict = str(check_output.get("verdict") or "confirmed").strip().lower()
    is_confirmed = verdict == "confirmed"
    ctx = _MemoryUpdateContext(
        memory=memory,
        active_hypotheses=active_hypotheses,
        resolved_hypotheses=resolved_hypotheses,
        check_output=check_output,
        updates=updates,
        verdict=verdict,
        is_confirmed=is_confirmed,
        provisional=not is_confirmed,
        current_hypothesis_id=current_hypothesis_id,
        db=db,
        query_id=query_id,
        hypothesis_description=hypothesis_description,
    )
    _apply_fact_updates(ctx)
    _apply_timeline_updates(ctx)
    _apply_task_updates(ctx)
    _apply_overview_updates(ctx)
    _append_confirmed_hypothesis_fact(ctx)
    _apply_refuted_hypothesis_updates(ctx)
    _apply_resolved_gap_updates(ctx)
    _apply_entity_updates(ctx)
    memory.append_suspicious(check_output.get("suspicious_evidence") or [])
    _rewrite_hypothesis_memories(ctx)
