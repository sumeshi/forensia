"""Hypothesis matching, merging, similarity, and entity extraction."""

from __future__ import annotations

import functools
import hashlib
import re
from typing import Any

from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB

# ---------------------------------------------------------------------------
# Entity validation (moved here from investigator.py so the admission gate
# and the drafter parser can share one copy without circular imports)
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _known_db_columns() -> frozenset[str]:
    """Whitelist of valid DB column names sourced from rulepacks/_schema/*.yaml.

    Used to reject natural-language ``required_entities`` (e.g.
    'user_identity', 'computer_name') that pass the snake_case regex but
    are not real columns.
    """
    from forensia.ai.prompt_context import _load_schema_hints

    cols: set[str] = set()
    for hint in _load_schema_hints().values():
        for col in (hint.get("columns") or []) + (hint.get("core_columns") or []):
            cols.add(str(col).strip())
    # Augment with synonyms that drafter commonly emits and we accept as aliases
    cols.update(
        {
            "src_ip",
            "dst_ip",
            "target_user",
            "subject_user",
            "logon_type",
            "process_name",
            "file_path",
            "computer",
            "event_id",
            "timestamp",
            "command_line",
            "service_name",
        }
    )
    return frozenset(c for c in cols if c)


def _filter_valid_entities(raw: list[Any]) -> list[str]:
    """Keep only entries that are real DB columns from the rulepack schema cards.

    Drops natural-language phrases formatted as snake_case (e.g.
    'user_identity', 'computer_name', 'credential_usage') that the bare
    snake_case regex would otherwise accept.
    """
    known = _known_db_columns()
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        name = str(item or "").strip().lower()
        if name and name in known and name not in seen:
            seen.add(name)
            out.append(name)
    return out


# Hypothesis-construction helpers (moved from report_gap.py to break the
# report_gap <-> hypothesis_manager import cycle; report_gap re-imports them).
def _gap_hypothesis_id(description: str) -> str:
    """Generate a deterministic hypothesis ID from a gap description using SHA-1."""
    digest = hashlib.sha1(description.encode("utf-8")).hexdigest()[:10]
    return f"gap-{digest}"


def _extract_entities_from_text(text: str) -> list[str]:
    """Safety-net: Extract entity names from a gap description when LLM output is incomplete.

    This is a fallback for when the LLM did not provide required_entities.
    The LLM prompt already requires these fields; this should rarely be needed.
    """
    entities = []
    words = text.split()
    for word in words:
        word = word.strip(".,;:()[]{}\"'")
        # Skip obvious non-entities
        if word.lower() in {
            "the",
            "this",
            "that",
            "unknown",
            "cannot",
            "insufficient",
            "evidence",
        }:
            continue
        if len(word) > 3 and any(
            pattern in word.lower()
            for pattern in [
                "\\",
                "/",
                ".exe",
                ".dll",
                "service",
                "account",
                "user",
                "host",
                "computer",
                "ip",
            ]
        ):
            entities.append(word)
        elif len(word) > 2 and word[0].isupper() and word.isalnum():
            entities.append(word)
    return entities[:5]


def _propose_confirm_when(entities: list[str]) -> dict[str, Any]:
    """Safety-net: Propose confirmation criteria when LLM output is incomplete."""
    if not entities:
        return {"zero_rows": True}
    return {"co_observed_entity_names": entities, "same_host": False, "heuristic": True}


def _clean_confirm_when(
    confirm_when: dict[str, Any] | None, db: CaseDB | None = None
) -> dict[str, Any] | None:
    """Remove non-finding_id entries from confirm_when.co_observed_event_ids.

    Validates that each entry is either a valid finding_id (matching DB pattern)
    or a valid event_id (integer). Drops keypoint names, free text, etc.
    """
    if not confirm_when or not isinstance(confirm_when, dict):
        return confirm_when

    co_observed = confirm_when.get("co_observed_event_ids")
    if not co_observed or not isinstance(co_observed, list):
        return confirm_when

    cleaned: list[str] = []
    for entry in co_observed:
        entry_str = str(entry).strip()
        if not entry_str:
            continue
        # Keep valid finding_ids (pattern: windows-xxx-yyyy-xxxx-xxxx)
        if re.match(r"^[a-z]+-[a-z0-9]+-[0-9]+-[a-z0-9-]+$", entry_str):
            cleaned.append(entry_str)
            continue
        # Keep valid event_ids (pure integers)
        try:
            int(entry_str)
            cleaned.append(entry_str)
            continue
        except ValueError:
            pass
        # Skip everything else (keypoint names, free text, etc.)
        continue

    if not cleaned:
        confirm_when.pop("co_observed_event_ids", None)
    else:
        confirm_when["co_observed_event_ids"] = cleaned

    return confirm_when if any(confirm_when.values()) else None


def _normalize_hypothesis_description(description: str) -> str:
    return " ".join(str(description or "").lower().split())


def _merge_string_lists(*values: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value_list in values:
        for value in value_list:
            item = str(value or "").strip()
            if not item or item in seen:
                continue
            seen.add(item)
            merged.append(item)
    return merged


def _merge_hypothesis_fields(existing: Hypothesis, incoming: Hypothesis) -> Hypothesis:
    """Merge fields from an incoming hypothesis into an existing one, preserving existing status and verdict."""
    source_rule_ids = _merge_string_lists(
        existing.source_rule_ids, incoming.source_rule_ids
    )
    required_entities = _merge_string_lists(
        existing.required_entities, incoming.required_entities
    )
    confirm_when = existing.confirm_when or incoming.confirm_when
    if confirm_when:
        confirm_when = _clean_confirm_when(
            dict(confirm_when) if isinstance(confirm_when, dict) else confirm_when
        )
    return Hypothesis(
        id=existing.id,
        description=existing.description or incoming.description,
        status=existing.status,
        verdict=existing.verdict,
        summary=existing.summary or incoming.summary,
        source_rule_ids=source_rule_ids,
        source_decl_id=existing.source_decl_id or incoming.source_decl_id,
        required_entities=required_entities,
        confirm_when=confirm_when if isinstance(confirm_when, dict) else None,
        refute_when=existing.refute_when or incoming.refute_when,
        fallback_phase=existing.fallback_phase or incoming.fallback_phase,
        fallback_source_rule_id=existing.fallback_source_rule_id
        or incoming.fallback_source_rule_id,
        target_keypoint_id=existing.target_keypoint_id or incoming.target_keypoint_id,
    )


def _hypothesis_evidence_strength(hypothesis: Hypothesis) -> int:
    """Score the evidence footing of a hypothesis.

    Returns an integer score used for conflict resolution when a new
    hypothesis is similar to an already-resolved one:

    * 2 — rule-seeded AND has non-benign evidence (strongest)
    * 1 — rule-seeded only (moderate)
    * 0 — neither rule-seeded nor evidence-backed (weakest / LLM-speculated)

    ``rule-seeded`` means the hypothesis has at least one ``source_rule_ids``
    entry (originated from a declarative rule, not purely LLM-generated).

    ``non-benign evidence`` means the hypothesis carries a ``confirm_when`` or
    ``refute_when`` with meaningful criteria (not just the fallback
    ``{"zero_rows": True}`` placeholder).
    """
    if not hypothesis.source_rule_ids:
        return 0
    has_evidence = bool(
        hypothesis.confirm_when
        and hypothesis.confirm_when != {"zero_rows": True}
    ) or bool(hypothesis.refute_when)
    return 2 if has_evidence else 1


def _hypothesis_tokens(description: str) -> set[str]:
    return {
        token
        for token in re.findall(
            r"[a-z0-9]+", _normalize_hypothesis_description(description)
        )
        if token
    }


def _extract_semantic_triple(description: str) -> dict[str, str]:
    """Extract (actor, action, target) triple from a hypothesis description."""
    text = str(description or "").strip().casefold()
    actor = ""
    action = ""
    target = ""
    for pattern, group in [
        (r"(?:by|from|via)\s+(an?\s+)?([a-z0-9_-]+)", 2),
        (r"(external ip|attacker|user|admin|malicious|suspicious)", 1),
    ]:
        m = re.search(pattern, text)
        if m:
            actor = m.group(group)
            break
    for pattern in [
        r"(lateral movement|rdp|remote desktop|persistence|privilege escalation|defense evasion|credential access|discovery|exfiltration)",
        r"(create|install|deploy|modify|delete|clear|disable|bypass|elevat|escalat)",
        r"(execut|run|launch|invoke|schedule)",
    ]:
        m = re.search(pattern, text)
        if m:
            action = m.group(1)
            break
    # NOTE: each fallback pattern must contain a capturing group matching its
    # declared group index — (?:...) here previously caused "no such group".
    for pattern, group in [
        (r"(?:to|on|into|onto)\s+(an?\s+)?([a-z0-9_-]+)", 2),
        (
            r"(account|service|task|process|host|server|user|group|log|event|file|folder|key)",
            1,
        ),
    ]:
        m = re.search(pattern, text)
        if m:
            target = m.group(group)
            break
    return {
        "actor": actor or "unknown",
        "action": action or "unknown",
        "target": target or "unknown",
    }


def _semantic_hypothesis_similarity(left: str, right: str) -> float:
    """Compute similarity using (actor, action, target) triples."""
    left_triple = _extract_semantic_triple(left)
    right_triple = _extract_semantic_triple(right)
    matches = 0
    for key in ("actor", "action", "target"):
        lv = left_triple.get(key, "").strip().lower()
        rv = right_triple.get(key, "").strip().lower()
        if lv and rv:
            if lv == rv or lv in rv or rv in lv:
                matches += 1
        elif not lv and not rv:
            matches += 1
    return matches / 3


def _hypothesis_similarity(left: str, right: str) -> float:
    """Compute similarity between two hypothesis descriptions using token overlap and semantic triples."""
    left_tokens = _hypothesis_tokens(left)
    right_tokens = _hypothesis_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    union = left_tokens | right_tokens
    if not union:
        return 0.0
    surface_score = len(left_tokens & right_tokens) / len(union)
    semantic_score = _semantic_hypothesis_similarity(left, right)
    left_triple = _extract_semantic_triple(left)
    right_triple = _extract_semantic_triple(right)
    all_unknown = all(v == "unknown" for v in left_triple.values()) or all(
        v == "unknown" for v in right_triple.values()
    )
    if all_unknown:
        return surface_score
    return max(surface_score, semantic_score)


def _best_hypothesis_match(
    hypotheses: list[Hypothesis],
    description: str,
) -> tuple[Hypothesis | None, float]:
    """Find the best fuzzy match for a description among the given hypotheses."""
    best_hypothesis: Hypothesis | None = None
    best_score = 0.0
    for hypothesis in hypotheses:
        score = _hypothesis_similarity(hypothesis.description, description)
        if score > best_score:
            best_score = score
            best_hypothesis = hypothesis
    return best_hypothesis, best_score


# ---------------------------------------------------------------------------
# Unified hypothesis admission gate
# ---------------------------------------------------------------------------

def _extract_refuted_tokens(descriptions: list[str]) -> set[str]:
    """Extract key entity tokens from refuted hypothesis descriptions.

    Captures executable names, IPs, hostnames, registry keys, and other
    distinctive tokens so hypothesis text referencing refuted content can
    be detected even when the wording differs from the original description.

    Moved here from report_gap.py so all admission paths share one copy.
    """
    tokens: set[str] = set()
    # Executable / script file names (poqexec.exe, evil.dll, etc.)
    exe_pattern = re.compile(
        r"[A-Za-z0-9_\-\.]+\.(?:exe|dll|sys|bat|ps1|cmd|vbs|js|hta|scr|com)",
        re.IGNORECASE,
    )
    # IPv4 addresses
    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    # Registry key paths
    reg_pattern = re.compile(
        r"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\]]+", re.IGNORECASE
    )
    for desc in descriptions:
        if not desc:
            continue
        lowered = desc.lower()
        # File names
        for m in exe_pattern.finditer(lowered):
            tokens.add(m.group(0).lower())
        # IPs
        for m in ip_pattern.finditer(desc):
            tokens.add(m.group(0))
        # Registry keys (normalized lowercase)
        for m in reg_pattern.finditer(desc):
            tokens.add(m.group(0).lower())
    return tokens


def _gap_references_refuted(text: str, refuted_tokens: set[str]) -> bool:
    """Check whether *text* references content from refuted hypotheses.

    Returns True if *text* contains any token extracted from refuted
    hypothesis descriptions.

    Moved here from report_gap.py so all admission paths share one copy.
    """
    if not refuted_tokens:
        return False
    lowered = text.lower()
    for token in refuted_tokens:
        if token in lowered:
            return True
    return False

