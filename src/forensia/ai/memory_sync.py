from __future__ import annotations

import re
from typing import Any

from forensia.ai.hypothesis_manager import _render_hypothesis_memory
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.session import ENTITY_ROLES, Hypothesis
from forensia.core.textutil import token_set_similarity
from forensia.db.database import CaseDB


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


def _render_entity_memory(entity_type: str, name: str, notes: str, role: str = "") -> str:
    """Generate a Markdown entity memory block from type, name, role, and notes."""
    normalized_type = str(entity_type).strip().lower() or "entity"
    normalized_name = str(name).strip()
    lines = [f"# {normalized_type}: {normalized_name}", "", f"- type: {normalized_type}", f"- name: {normalized_name}"]
    normalized_role = str(role).strip().lower()
    if normalized_role in ENTITY_ROLES and normalized_role != "unknown":
        lines.append(f"- role: {normalized_role}")
    note_text = str(notes).strip()
    if note_text:
        lines.append(f"- notes: {note_text}")
    return "\n".join(lines).rstrip() + "\n"


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
    _HARD_CLAIM_WORDS = {"confirmed", "attack", "compromised", "breach", "intrusion", "exfiltration"}

    updates = check_output.get("memory_updates") or {}
    verdict = str(check_output.get("verdict") or "confirmed").strip().lower()
    is_confirmed = verdict == "confirmed"
    provisional = not is_confirmed
    for item in updates.get("facts") or []:
        if not isinstance(item, dict):
            continue
        fact_text = str(item.get("text") or "")
        evidence_ids = [str(e) for e in (item.get("evidence_ids") or [])]
        claim_type = str(item.get("claim_type") or "observation").strip().lower()
        # R2-09: interpretation facts are stored as provisional (scratch)
        # unless the evidence spans >=2 different artifact sources.
        is_interpretation = claim_type == "interpretation"
        fact_provisional = provisional or (
            is_interpretation and not _has_multi_source_evidence(evidence_ids)
        )
        memory.append_confirmed_fact(
            fact_text,
            evidence_ids,
            hypothesis_id=current_hypothesis_id,
            provisional=fact_provisional,
        )

    for item in updates.get("timeline") or []:
        if not isinstance(item, dict):
            continue
        memory.append_timeline_anchor(
            str(item.get("timestamp") or ""),
            str(item.get("description") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
            hypothesis_id=current_hypothesis_id,
            provisional=provisional,
        )

    for item in updates.get("tasks") or []:
        if not isinstance(item, dict):
            continue
        memory.append_task(
            str(item.get("text") or item.get("question") or ""),
            str(item.get("kind") or ""),
            hypothesis_id=current_hypothesis_id,
            provisional=provisional,
        )

    # R2-10: Overview writes only on state transitions
    _is_resolution = verdict in ("confirmed", "refuted", "untestable")
    _has_new_nonobserved_entity = False
    _artifact_overview_families: set[str] = set()

    for item in updates.get("entities") or []:
        if isinstance(item, dict):
            role = str(item.get("role") or "").strip().lower()
            if role != "observed_user":
                name = str(item.get("name") or "").strip()
                etype = str(item.get("entity_type") or "").strip()
                if name and etype:
                    ent_path = memory._entity_path(etype, name)
                    if ent_path and not ent_path.exists():
                        _has_new_nonobserved_entity = True

    for item in updates.get("facts") or []:
        if isinstance(item, dict):
            for eid in (item.get("evidence_ids") or []):
                family = str(eid).split("-")[0] if "-" in str(eid) else str(eid)
                if family:
                    _artifact_overview_families.add(family)

    # "First finding of a new artifact family" must be judged against evidence
    # annotations already recorded in facts.md (`evidence: evtx-...`), not the
    # overview prose -- family tokens almost never appear in prose, which would
    # make every evidence-citing check pass the gate.
    _has_new_family = False
    if _artifact_overview_families:
        facts_text = ""
        try:
            if memory.facts_path.exists():
                facts_text = memory.facts_path.read_text(encoding="utf-8")
        except Exception:
            facts_text = ""
        for family in _artifact_overview_families:
            if f"evidence: {family}-" not in facts_text:
                _has_new_family = True
                break

    overview_items = updates.get("overview") or []
    if overview_items and (_is_resolution or _has_new_nonobserved_entity or _has_new_family):
        for item in overview_items[:1]:
            item_str = str(item)
            item_lower = item_str.lower()
            # R3-09: Skip refuted-template lines (already in archive/refuted.md)
            if verdict == "refuted" and re.search(r"the hypothesis regarding .* was refuted", item_str, re.IGNORECASE):
                _log("MEMORY", "R3-09: skipped refuted-template overview line")
                continue
            has_hard_claim = any(w in item_lower for w in _HARD_CLAIM_WORDS)
            if has_hard_claim and not is_confirmed:
                memory.append_confirmed_fact(
                    item_str, [],
                    hypothesis_id=current_hypothesis_id,
                    provisional=True,
                )
            elif "could not be confirmed" in item_lower or "inconclusive" in item_lower or "no evidence" in item_lower:
                memory.append_confirmed_fact(
                    item_str, [],
                    hypothesis_id=current_hypothesis_id,
                    provisional=True,
                )
            else:
                overview_text = memory.load_overview()
                recent_lines = [ln.strip() for ln in overview_text.split("\n") if ln.strip()][-20:]
                item_tokens = set(item_str.lower().split())
                is_duplicate = False
                if item_tokens:
                    for line in recent_lines:
                        line_tokens = set(line.lower().split())
                        if line_tokens:
                            sim = token_set_similarity(item_str, line)
                            if sim > 0.7:
                                is_duplicate = True
                                break
                if is_duplicate:
                    _log("MEMORY", "overview dedup: skipped similar item")
                else:
                    memory.append_overview(item_str)

    # T-18: When confirmed, write a deterministic fact line
    if is_confirmed and hypothesis_description and query_id:
        evidence_ids: list[str] = []
        for item in updates.get("facts") or []:
            if isinstance(item, dict):
                evidence_ids.extend(str(e) for e in (item.get("evidence_ids") or []) if str(e).strip())
        memory.append_confirmed_hypothesis_fact(
            hypothesis_description=hypothesis_description,
            verdict=verdict,
            query_id=query_id,
            evidence_ids=evidence_ids,
        )

    for item in updates.get("refuted_hypotheses") or []:
        if not isinstance(item, dict):
            continue
        memory.append_refuted_hypothesis(
            str(item.get("hypothesis_id") or ""),
            str(item.get("description") or ""),
            str(item.get("reason") or ""),
        )

    for item in updates.get("resolved_gaps") or []:
        if not isinstance(item, dict):
            continue
        memory.append_resolved_gap(
            str(item.get("text") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )

    for item in updates.get("entities") or []:
        if not isinstance(item, dict):
            continue
        entity_type = str(item.get("entity_type") or "")
        entity_name = str(item.get("name") or "")
        entity_role = str(item.get("role") or "")
        notes = str(item.get("notes") or "")
        content = str(item.get("content") or "").strip() or _render_entity_memory(entity_type, entity_name, notes, entity_role)
        memory.upsert_entity(
            entity_type,
            entity_name,
            content,
        )

    memory.append_suspicious(check_output.get("suspicious_evidence") or [])

    for hypothesis in active_hypotheses:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(db, hypothesis)
        memory.upsert_hypothesis(hypothesis.id, slug, content)
    for hypothesis in resolved_hypotheses:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(None, hypothesis)
        memory.upsert_hypothesis(hypothesis.id, slug, content)
