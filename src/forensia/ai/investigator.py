from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import signal
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import re
from re import sub
from typing import Any
from uuid import uuid4

import httpx
import yaml
from rich import print
try:
    from sqlglot import exp, parse_one
    from sqlglot.optimizer.normalize_identifiers import normalize_identifiers
except ImportError:  # pragma: no cover - optional until dependency is installed
    exp = None
    parse_one = None
    normalize_identifiers = None

from forensia.ai.audit import LLMCallLogger
from forensia.ai.checker import check_query_result, summarize_query_result
from forensia.ai.hypothesis_manager import (
    _all_hypotheses,
    _hypothesis_similarity,
    _load_persisted_hypotheses,
    _merge_active_hypotheses,
    _render_hypothesis_memory,
    _resolve_hypothesis,
    _upsert_hypothesis,
)
from forensia.ai.json_response import request_llm_json
from forensia.ai.lmstudio import LLMServerUnavailableError, outage_wait_until_recovered
from forensia.ai.planner import _compute_uncovered_keypoints, plan_hypothesis_query
from forensia.ai.prompts import _slim_hypothesis_dump, build_gap_identifier_messages, build_hypothesis_drafter_messages, resolve_rule_context
from forensia.ai.report_gap import (
    _build_report_status,
    _guess_related_sections,
    _inject_gap_hypotheses,
    _overlay_report_status,
    _report_cycle_progress,
)
from forensia.ai.section_refresher import async_refresh_report_sections
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import ENTITY_ROLES, HistoryEntry, Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.writer import (
    REPORT_KEYPOINTS,
    _resolve_evidence_results,
    mark_report_sections_ai_exhausted,
    render_written_report,
)
from forensia.rules.engine import (
    execute_event_keyword_fallback_search,
    execute_fallback_search,
    generate_findings,
    run_rule,
    save_findings,
)
from forensia.rules.loader import _get_rule_cache, load_rule_by_id, load_rules_from_dir


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


_LOG_COLORS = {
    "PLAN": "bold cyan", "HYPOTHESIS": "bold magenta", "QUERY": "bold blue",
    "EXEC": "bold green", "CHECK": "bold yellow", "RESOLVE": "bold green",
    "REPORT": "bold white", "MEMORY": "dim", "FALLBACK": "bold yellow",
    "PIVOT": "dim",
}


def _log(tag: str, message: str) -> None:
    color = _LOG_COLORS.get(tag, "white")
    print(f"[{color}][{tag}][/{color}] {message}")


@dataclass
class _Ctx:
    """Mutable per-session state shared across investigate() helpers."""
    interrupted: bool = False
    report_status: dict = field(default_factory=dict)
    memory_overview: str = ""
    memory_plan: str = ""
    memory_check: str = ""
    current_hypothesis_id: str | None = None


_MAX_OUTAGE_RETRIES_PER_CALL = 3


async def _call_with_outage_recovery(
    call_fn,
    base_url: str,
    model: str,
    **kwargs,
):
    for attempt in range(1, _MAX_OUTAGE_RETRIES_PER_CALL + 1):
        try:
            if asyncio.iscoroutinefunction(call_fn):
                return await call_fn(base_url=base_url, model=model, **kwargs)
            else:
                return await asyncio.to_thread(call_fn, base_url=base_url, model=model, **kwargs)
        except LLMServerUnavailableError:
            if attempt >= _MAX_OUTAGE_RETRIES_PER_CALL:
                raise
            await outage_wait_until_recovered(base_url, model)
    raise LLMServerUnavailableError("Outage recovery failed")


def _ctx_get_report_status(
    ctx: "_Ctx",
    db: "CaseDB",
    *,
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
    refresh: bool = False,
) -> dict[str, Any]:
    """Return the current or refreshed report status, optionally filtered to specific sections."""
    if refresh:
        ctx.report_status = _build_report_status(db)
    return _overlay_report_status(ctx.report_status, current_section=current_section, focus_sections=focus_sections)


def _ctx_refresh_caches(
    ctx: "_Ctx",
    memory: "MemoryManager",
    base_url: str,
    model: str,
    current_hypothesis_id: str | None = None,
) -> None:
    """Reload memory context caches and compact overview if needed."""
    memory.compact_overview_if_needed(base_url=base_url, model=model)
    ctx.memory_overview = memory.load_compact_context(["overview.md"], max_bytes=memory.max_bytes)
    ctx.current_hypothesis_id = current_hypothesis_id
    ctx.memory_plan = memory.load_investigation_context(
        current_hypothesis_id,
        max_bytes=max(1024, memory.max_bytes // 3),
        include_overview=False,
    )
    ctx.memory_check = memory.load_investigation_context(
        current_hypothesis_id,
        max_bytes=max(1024, memory.max_bytes // 2),
        include_overview=False,
    )


def _query_fingerprint(sql: str | None) -> str:
    """Generate a fingerprint for a query to detect duplicates.

    Uses sqlglot AST normalization when available so semantically equivalent
    queries produce the same fingerprint regardless of formatting or aliasing.
    """
    sql = (sql or "").strip()
    if not sql:
        return "generic"

    if parse_one is None or exp is None:
        return hashlib.sha1(f"raw:{sql.lower()}".encode("utf-8")).hexdigest()[:8]

    try:
        expression = parse_one(sql, read="duckdb")
    except Exception:
        try:
            expression = parse_one(sql)
        except Exception:
            return hashlib.sha1(f"raw:{sql.lower()}".encode("utf-8")).hexdigest()[:8]

    if normalize_identifiers is not None:
        try:
            expression = normalize_identifiers(expression, dialect="duckdb")
        except Exception:
            pass

    def _column_name(node: Any) -> str | None:
        if isinstance(node, exp.Column):
            return node.name.lower()
        if isinstance(node, exp.Identifier):
            return node.name.lower()
        return None

    def _literal_value(node: Any) -> str | None:
        if isinstance(node, exp.Literal):
            value = str(node.this)
            if node.is_string:
                return value.lower()
            try:
                return str(int(value))
            except ValueError:
                return value.lower()
        if isinstance(node, exp.Cast):
            return _literal_value(node.this)
        if isinstance(node, exp.Paren):
            return _literal_value(node.this)
        if isinstance(node, exp.Neg):
            inner = _literal_value(node.this)
            return f"-{inner}" if inner is not None else None
        return None

    def _collect_terms(predicate: Any, column_name: str) -> list[str]:
        values: list[str] = []
        if isinstance(predicate, exp.EQ):
            left = _column_name(predicate.this)
            right = _column_name(predicate.expression)
            if left == column_name:
                value = _literal_value(predicate.expression)
                if value is not None:
                    values.append(value)
            elif right == column_name:
                value = _literal_value(predicate.this)
                if value is not None:
                    values.append(value)
        elif isinstance(predicate, exp.In) and _column_name(predicate.this) == column_name:
            for item in predicate.expressions:
                value = _literal_value(item)
                if value is not None:
                    values.append(value)
        return values

    event_ids: set[str] = set()
    computers: set[str] = set()
    for predicate in expression.find_all((exp.EQ, exp.In)):
        event_ids.update(_collect_terms(predicate, "event_id"))
        computers.update(_collect_terms(predicate, "computer"))

    parts: list[str] = []
    if event_ids:
        parts.append("ev:" + ",".join(sorted(event_ids)))
    if computers:
        parts.append("host:" + ",".join(sorted(computers)))
    if parts:
        return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:8]

    canonical_sql = expression.sql(dialect="duckdb", pretty=False)
    return hashlib.sha1(f"sql:{canonical_sql}".encode("utf-8")).hexdigest()[:8]


@dataclass(slots=True)
class HypothesisProgressTracker:
    """Tracks hypothesis investigation progress for auto-refute/auto-confirm decisions."""
    
    zero_row_inconclusive_count: int = 0
    query_fingerprints: list[str] = field(default_factory=list)
    _last_missing_signature: str = ""
    consecutive_same_missing: int = 0
    
    def record(self, query_fingerprint: str, verdict: str, row_count: int) -> None:
        """Record a query execution result."""
        self.query_fingerprints.append(query_fingerprint)
        if verdict == "inconclusive" and row_count == 0:
            self.zero_row_inconclusive_count += 1
        else:
            self.zero_row_inconclusive_count = 0
    
    def register_check(self, verdict: str, row_count: int, missing_signature: str = "") -> None:
        """Track consecutive same-missing checks for auto-refute detection."""
        if verdict == "inconclusive" and missing_signature:
            if missing_signature == self._last_missing_signature:
                self.consecutive_same_missing += 1
            else:
                self.consecutive_same_missing = 1
            self._last_missing_signature = missing_signature
        elif verdict != "inconclusive":
            self.consecutive_same_missing = 0
            self._last_missing_signature = ""
    
    def should_auto_refute_due_to_unobserved_events(self, threshold: int = 3) -> bool:
        """Return True after threshold consecutive same-missing inconclusive results."""
        return self.consecutive_same_missing >= threshold
    
    def should_auto_refute(self, consecutive_threshold: int = 3) -> bool:
        """Return True after consecutive_threshold consecutive 0-row inconclusive results."""
        return self.zero_row_inconclusive_count >= consecutive_threshold
    
    def should_pivot(self, threshold: int = 2) -> bool:
        """Detect if any query fingerprint appears >= threshold times."""
        fp_counts = Counter(self.query_fingerprints)
        most_common = fp_counts.most_common(1)
        if most_common and most_common[0][1] >= threshold:
            return True
        return False
    
    @staticmethod
    def _extract_observed_event_ids(rows: list[dict[str, Any]]) -> set[int]:
        """Extract unique event_ids from query result rows."""
        observed: set[int] = set()
        for row in rows:
            event_id = row.get("event_id")
            if event_id is not None:
                try:
                    observed.add(int(event_id))
                except (TypeError, ValueError):
                    pass
        return observed
    
    def _confirm_set_from(self, rule_context: Any, hypothesis: Any = None) -> set[int]:
        """Pull co_observed_event_ids from rule_context first, falling back to the
        hypothesis itself (broad_plan-derived hypotheses have no rule_context)."""
        confirm_when = None
        if rule_context is not None:
            confirm_when = getattr(rule_context, "confirm_when", None)
        if not confirm_when and hypothesis is not None:
            confirm_when = getattr(hypothesis, "confirm_when", None)
        if not confirm_when:
            return set()
        required_event_ids = confirm_when.get("co_observed_event_ids") if isinstance(confirm_when, dict) else None
        if not required_event_ids:
            return set()
        out: set[int] = set()
        for eid in required_event_ids:
            try:
                out.add(int(str(eid).strip()))
            except (TypeError, ValueError):
                continue
        return out

    def should_auto_confirm(self, rule_context: Any, rows: list[dict[str, Any]], hypothesis: Any = None) -> bool:
        """Return True if all co_observed_event_ids are present in query results.

        Accepts confirm_when from rule_context OR from the hypothesis itself so
        broad_plan-derived hypotheses (no source_rule_ids) can also auto-confirm.
        """
        required_set = self._confirm_set_from(rule_context, hypothesis)
        if not required_set:
            return False
        observed_event_ids = self._extract_observed_event_ids(rows)
        return required_set.issubset(observed_event_ids)

    def has_partial_confirm_signal(self, rule_context: Any, rows: list[dict[str, Any]], hypothesis: Any = None) -> bool:
        """Return True when some, but not all, confirm_when event IDs are present."""
        required_set = self._confirm_set_from(rule_context, hypothesis)
        if not required_set:
            return False
        observed_event_ids = self._extract_observed_event_ids(rows)
        return bool(required_set & observed_event_ids) and not required_set.issubset(observed_event_ids)


def _save_step(
    db: CaseDB,
    session_id: str,
    iteration: int,
    phase: str,
    hypothesis_id: str | None,
    input_json: Any,
    output_json: Any,
    suffix: str | None = None,
) -> None:
    """Persist an investigation step (input/output JSON) to the database."""
    step_id = f"{session_id}-{iteration:02d}-{phase}"
    if suffix:
        step_id = f"{step_id}-{suffix}"
    db.execute(
        """
        INSERT INTO investigation_steps (
            step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (step_id) DO UPDATE SET
            output_json = excluded.output_json,
            created_at = excluded.created_at
        """,
        (
            step_id,
            session_id,
            hypothesis_id,
            iteration,
            phase,
            _to_json(input_json),
            _to_json(output_json),
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )


def _reasoning_entry_id(
    hypothesis_id: str,
    iteration: int,
    phase: str,
    query_id: str | None,
) -> str:
    """Generate a deterministic SHA1-based ID for a reasoning entry."""
    body = f"{hypothesis_id}-{iteration}-{phase}-{query_id or '-'}"
    return hashlib.sha1(body.encode("utf-8")).hexdigest()[:16]


def _append_hypothesis_reasoning(
    db: CaseDB,
    hypothesis_id: str,
    session_id: str,
    iteration: int,
    phase: str,
    body: str,
    verdict: str | None = None,
    query_id: str | None = None,
) -> str | None:
    """Persist a free-text reasoning entry linked to a hypothesis and phase."""
    text = str(body).strip()
    if not hypothesis_id or not text:
        return None
    entry_id = _reasoning_entry_id(hypothesis_id, iteration, phase, query_id)
    db.execute(
        """
        INSERT INTO hypothesis_reasoning (
            entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (entry_id) DO NOTHING
        """,
        (
            entry_id,
            hypothesis_id,
            session_id,
            iteration,
            phase,
            verdict,
            query_id,
            text,
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )
    return entry_id


def _seed_findings(case: Case, db: CaseDB, profile: str) -> int:
    """Run all rules once to seed initial findings, unless already populated."""
    existing = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    if existing:
        return int(existing)

    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    rules_dir = Path(__file__).parent.parent / "rulepacks"
    rules = load_rules_from_dir(rules_dir, profile_path)
    total = 0
    for rule in rules:
        findings = generate_findings(rule, run_rule(db, rule))
        save_findings(case, db, findings)
        total += len(findings)
    return total


def _load_profile_config(profile: str) -> dict[str, Any]:
    """Load the YAML configuration for a given profile name."""
    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    if not profile_path.exists():
        return {}
    return yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}


def _initialize_overview(memory: MemoryManager, case: Case, profile_config: dict[str, Any] | None = None) -> None:
    """Create the initial investigation overview memory file if it doesn't exist yet."""
    objective = str((profile_config or {}).get("objective") or "").strip()
    if memory.has_overview():
        return
    output_language = str(get_llm_settings()["output_language"]).lower()
    open_question_seed = {
        "ja": "初回調査待ち",
        "en": "Awaiting initial investigation",
    }.get(output_language, "Awaiting initial investigation")
    objective_line = objective or {
        "ja": "証拠に基づいて事実関係を整理する",
        "en": "Establish the evidence-backed incident narrative.",
    }.get(output_language, "Establish the evidence-backed incident narrative.")
    memory.update_overview(
        (
            f"# Investigation Overview\n\n"
            f"Case: {case.path.name}\n\n"
            f"## Investigation Objective\n- {objective_line}\n\n"
            "## Memory Details\n"
            "- Detailed fact records can be stored under memory/details/fact-NNN.md and loaded on demand.\n\n"
            "## Case Scope\n- none\n\n"
            "## Key Findings\n- none\n\n"
            "## Investigation Policy\n- preserve evidence fidelity\n\n"
            f"## Active Tasks\n- {open_question_seed}\n"
        )
    )


def _ensure_profile_objective(memory: MemoryManager, profile_config: dict[str, Any] | None = None) -> None:
    """Patch the investigation objective from profile config into overview and tasks."""
    objective = str((profile_config or {}).get("objective") or "").strip()
    if not objective:
        return
    overview = memory.load_overview()
    if "## Investigation Objective" not in overview:
        memory.update_overview(
            overview.rstrip() + f"\n\n## Investigation Objective\n- {objective}\n"
        )
    elif objective not in overview:
        memory.update_overview(
            overview.replace("## Investigation Objective\n", f"## Investigation Objective\n- {objective}\n", 1)
            if "## Investigation Objective\n- " not in overview
            else overview
        )
    if memory.tasks_memory_path.exists():
        tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")
    else:
        tasks_text = ""
    objective_task = f"Investigation objective: {objective}"
    if objective_task not in tasks_text:
        memory.append_task(objective_task, "human_decision")


def _finding_snapshot(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    """Fetch the top findings ordered by confidence and recency."""
    return fetch_records(
        db,
        """
        SELECT finding_id, title, summary, severity, confidence, status, evidence
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )


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


def _keypoint_card_id(index: int) -> str:
    return f"KP-{index:04d}"


def _sync_keypoint_cards(memory: MemoryManager, findings_snapshot: list[dict[str, Any]]) -> None:
    """Reconcile findings → keypoint-memory cards, removing stale entries."""
    for index, finding in enumerate(findings_snapshot, start=1):
        evidence_ids: list[str] = []
        evidence = finding.get("evidence")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except json.JSONDecodeError:
                evidence = []
        if isinstance(evidence, list):
            for row in evidence:
                if not isinstance(row, dict):
                    continue
                evidence_id = str(row.get("evidence_id") or "").strip()
                if evidence_id:
                    evidence_ids.append(evidence_id)
        lines = [
            f"# {_keypoint_card_id(index)}",
            "",
            f"- finding_id: {finding.get('finding_id')}",
            f"- title: {finding.get('title')}",
            f"- severity: {finding.get('severity')}",
            f"- confidence: {finding.get('confidence')}",
            "",
            "## Summary",
            str(finding.get("summary") or "").strip() or "-",
            "",
            "## Evidence IDs",
        ]
        lines.extend([f"- {evidence_id}" for evidence_id in evidence_ids] or ["- none"])
        memory.upsert_keypoint(_keypoint_card_id(index), "\n".join(lines).rstrip() + "\n")
    active_ids = {_keypoint_card_id(index) for index in range(1, len(findings_snapshot) + 1)}
    for path in memory.keypoints_dir.glob("KP-*.md"):
        if path.stem not in active_ids:
            path.unlink(missing_ok=True)


def _sync_hypothesis_cards(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
) -> None:
    """Remove hypothesis memory files that no longer correspond to active or resolved hypotheses."""
    valid_ids = {
        sub(r"[^a-zA-Z0-9._-]+", "-", str(item.id).strip()).strip("-") or "unknown"
        for item in [*active_hypotheses, *resolved_hypotheses]
    }
    for path in memory.hypotheses_dir.glob("*.md"):
        if path.stem not in valid_ids:
            path.unlink(missing_ok=True)


def _matching_findings(snapshot: list[dict[str, Any]], hypothesis: Hypothesis | None) -> list[dict[str, Any]]:
    """Return findings whose title/summary/severity share tokens with the hypothesis description."""
    if hypothesis is None:
        return snapshot[:10]
    words = {token.lower() for token in hypothesis.description.split() if len(token) >= 3}
    if not words:
        return snapshot[:10]
    matched = []
    for finding in snapshot:
        haystack = " ".join(
            str(finding.get(key, "") or "")
            for key in ("title", "summary", "severity", "status")
        ).lower()
        if any(word in haystack for word in words):
            matched.append(finding)
    return matched[:10] if matched else snapshot[:10]


def _observed_keypoints_from_findings(snapshot: list[dict[str, Any]], limit: int = 20) -> list[str]:
    """Format findings as human-readable keypoint labels for LLM context."""
    keypoints: list[str] = []
    for item in snapshot[:limit]:
        title = str(item.get("title") or "").strip()
        finding_id = str(item.get("finding_id") or "").strip()
        if not title:
            continue
        if finding_id:
            keypoints.append(f"{finding_id}: {title}")
        else:
            keypoints.append(title)
    return keypoints


def _scan_report_keypoints(case: Case, db: CaseDB, *, limit: int = 80) -> list[dict[str, Any]]:
    """Run each report keypoint once and keep only the ones that produced rows."""
    observed: list[dict[str, Any]] = []
    for index, keypoint_name in enumerate(sorted(REPORT_KEYPOINTS.keys()), start=1):
        try:
            result = _resolve_evidence_results(case, db, keypoints=[keypoint_name])[0]
        except Exception as exc:
            _log("PIVOT", f"keypoint scan failed for {keypoint_name}: {exc}")
            continue
        row_count = int(result.get("row_count") or 0)
        if row_count <= 0:
            continue
        observed.append(
            {
                "keypoint": keypoint_name,
                "row_count": row_count,
                "description": str(result.get("description") or ""),
                "evidence_ids": list(result.get("evidence_ids") or []),
            }
        )
        if len(observed) >= limit:
            break
    return observed


def _normalize_hypothesis_tokens(text: str) -> set[str]:
    import re

    return {token for token in re.findall(r"[a-z0-9]+", str(text).lower()) if len(token) >= 3}


def _audit_broad_plan_hypotheses(
    state: SessionState,
    hypotheses: list[Hypothesis],
) -> list[dict[str, Any]]:
    """Classify each new hypothesis as new/duplicate/follow_up/related against existing ones."""
    audits: list[dict[str, Any]] = []
    existing = [*state.active_hypotheses, *state.resolved_hypotheses]
    for hyp in hypotheses:
        best_match: Hypothesis | None = None
        best_score = 0.0
        hyp_tokens = _normalize_hypothesis_tokens(hyp.description)
        for candidate in existing:
            candidate_tokens = _normalize_hypothesis_tokens(candidate.description)
            if not hyp_tokens or not candidate_tokens:
                continue
            union = hyp_tokens | candidate_tokens
            score = len(hyp_tokens & candidate_tokens) / len(union)
            if score > best_score:
                best_score = score
                best_match = candidate
        if best_match is None:
            relation = "new"
        elif best_score >= 0.75:
            relation = "duplicate"
        elif set(hyp.source_rule_ids) & set(best_match.source_rule_ids):
            relation = "follow_up"
        else:
            relation = "related"
        audits.append(
            {
                "hypothesis_id": hyp.id,
                "description": hyp.description,
                "relation": relation,
                "matched_hypothesis_id": best_match.id if best_match else None,
                "similarity": round(best_score, 3),
            }
        )
    return audits


def _hypothesis_focus_score(state: SessionState, hypothesis: Hypothesis) -> tuple[int, int, int]:
    """Rank hypotheses by a rough confidence proxy and recency."""
    recent_iteration = -1
    for entry in reversed(state.history):
        if entry.hypothesis_id == hypothesis.id:
            recent_iteration = int(entry.iteration)
            break
    confidence_proxy = len(hypothesis.source_rule_ids) + (1 if hypothesis.required_entities else 0)
    return (confidence_proxy, recent_iteration, -len(hypothesis.description))


def _select_focus_hypotheses(state: SessionState, max_items: int = 2) -> list[Hypothesis]:
    ranked = sorted(state.active_hypotheses, key=lambda item: _hypothesis_focus_score(state, item), reverse=True)
    return ranked[:max(1, max_items)] if ranked else []


def _final_summary(state: SessionState) -> str:
    """Build a human-readable summary of the investigation outcome."""
    if state.resolved_hypotheses:
        lines = []
        for item in state.resolved_hypotheses[-5:]:
            verdict = item.verdict or item.status
            lines.append(f"[{verdict}] {item.description}: {item.summary or 'summary unavailable'}")
        return "\n".join(lines)
    if state.history:
        return "\n".join(entry.summary for entry in state.history[-5:] if entry.summary)
    output_language = str(get_llm_settings()["output_language"]).lower()
    return {
        "ja": "調査中に追加の進展はありませんでした。",
        "en": "No additional progress was made during this investigation.",
    }.get(output_language, "No additional progress was made during this investigation.")


def _apply_memory_updates(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
    check_output: dict[str, Any],
    current_hypothesis_id: str | None = None,
    db: CaseDB | None = None,
) -> None:
    """Persist facts, timeline, tasks, entities, and hypothesis cards from a check output."""
    updates = check_output.get("memory_updates") or {}
    verdict = str(check_output.get("verdict") or "confirmed").strip().lower()
    provisional = verdict != "confirmed"
    for item in updates.get("facts") or []:
        if not isinstance(item, dict):
            continue
        memory.append_confirmed_fact(
            str(item.get("text") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
            hypothesis_id=current_hypothesis_id,
            provisional=provisional,
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

    for item in updates.get("overview") or []:
        memory.append_overview(str(item))

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


async def _investigate_one_hypothesis(
    hypothesis: Hypothesis,
    state: SessionState,
    ctx: _Ctx,
    memory: MemoryManager,
    db: CaseDB,
    base_url: str,
    model: str,
    plan_cycle: int,
    llm_logger: LLMCallLogger,
    session_id: str,
    max_queries_per_hypothesis: int,
    case: Case,
    query_limit: int | None = None,
    emit_fn: Callable[..., None] | None = None,
    llm_status_fn: Callable[[str], None] | None = None,
) -> tuple[bool, SessionState, dict[str, str]]:
    """Investigate a single hypothesis with full emit/save/memory lifecycle.
    Returns (cycle_progress, updated_state, focus_sections).
    """
    candidates = _matching_findings(state.findings_snapshot, hypothesis)
    tracker = HypothesisProgressTracker()
    cycle_progress = False
    focus_sections = _guess_related_sections(hypothesis.description)
    limit = query_limit if query_limit is not None else max_queries_per_hypothesis
    for query_index in range(1, limit + 1):
        state.focus_depth = query_index
        try:
            hypothesis_plan = await _call_with_outage_recovery(
                plan_hypothesis_query, base_url=base_url, model=model,
                state=state, hypothesis=hypothesis,
                memory=memory, db=db,
                overview_md=ctx.memory_overview, default_context_md=ctx.memory_plan,
                status_callback=llm_status_fn or (lambda msg: print(f"[yellow]{msg}[/yellow]")),
                audit_callback=lambda msgs, out, parsed, hid=hypothesis.id, qi=query_index: llm_logger.write(
                    iteration=plan_cycle, phase="plan-hypothesis", input_messages=msgs,
                    output=parsed, model=model, base_url=base_url, suffix=f"{hid}-{qi:02d}",
                ),
                query_index=query_index,
                time_range=case.time_range,
            )
        except Exception as exc:
            err_msg = f"[plan-hypothesis] LLM failed for {hypothesis.id}: {exc}"
            print(f"[red]{err_msg}[/red]")
            _append_hypothesis_reasoning(db=db, hypothesis_id=hypothesis.id, session_id=session_id,
                                         iteration=plan_cycle, phase="plan", body=err_msg)
            break
        _save_step(db=db, session_id=session_id, iteration=plan_cycle, phase="plan-hypothesis",
                   hypothesis_id=hypothesis.id,
                   input_json={"hypothesis": hypothesis.model_dump(), "query_index": query_index},
                   output_json=hypothesis_plan.raw_response, suffix=f"{hypothesis.id}-{query_index:02d}")
        if hypothesis_plan.hypothesis is not None:
            hypothesis = hypothesis_plan.hypothesis
            _upsert_hypothesis(db, hypothesis, origin="broad_plan", session_id=session_id)
        if not hypothesis_plan.query:
            if not hypothesis_plan.needs_more:
                break
            continue
        planned_query = hypothesis_plan.query
        reasoning_entry_id = _append_hypothesis_reasoning(
            db=db, hypothesis_id=hypothesis.id, session_id=session_id,
            iteration=plan_cycle, phase="plan", body=planned_query.purpose, query_id=planned_query.query_id,
        )
        _log("QUERY", f"{hypothesis.id} {planned_query.query_id} — {planned_query.purpose}")
        if emit_fn:
            emit_fn("investigate/do", f"[do] {planned_query.query_id}: {planned_query.purpose}",
                    iteration=plan_cycle, report_kw={"focus_sections": focus_sections},
                    current_query=planned_query.query_id, hypothesis_id=hypothesis.id,
                    reasoning_entry_id=reasoning_entry_id)
        query_fp = _query_fingerprint(planned_query.sql)
        try:
            rows = fetch_records(db, planned_query.sql)
            _log("EXEC", f"{hypothesis.id} {planned_query.query_id} — {len(rows)} rows")
            fallback_info = None
            if len(rows) == 0 and hypothesis.source_rule_ids:
                for source_rule_id in hypothesis.source_rule_ids:
                    rule = load_rule_by_id(source_rule_id)
                    if rule and rule.fallback_search:
                        for fallback in rule.fallback_search:
                            if isinstance(fallback, dict):
                                ph = fallback.get("phase")
                                if ph not in {"keyword_in_raw_json", "related_event_ids", "artifact_table"}:
                                    continue
                                fb_rows = execute_fallback_search(db, fallback)
                                if fb_rows:
                                    _log("FALLBACK", f"{hypothesis.id} — found {len(fb_rows)} rows via {ph}")
                                    for r in fb_rows[:20]:
                                        if isinstance(r, dict):
                                            r["_fallback_phase"] = ph
                                            r["_fallback_source_rule_id"] = source_rule_id
                                    rows = fb_rows[:20]
                                    fallback_info = {"phase": ph, "source_rule_id": source_rule_id}
                                    break
                        if fallback_info:
                            break
            if len(rows) == 0 and fallback_info is None:
                fb_rows, fb_info = execute_event_keyword_fallback_search(db, planned_query.sql)
                if fb_rows:
                    _log(
                        "FALLBACK",
                        f"{hypothesis.id} — found {len(fb_rows)} rows via keyword_in_raw_json"
                        + (
                            f" event_ids={fb_info.get('event_ids', [])} keywords={fb_info.get('keywords', [])}"
                            if fb_info
                            else ""
                        ),
                    )
                    for r in fb_rows[:20]:
                        if isinstance(r, dict):
                            r["_fallback_phase"] = "keyword_in_raw_json"
                            r["_fallback_source_rule_id"] = "event_id_schema"
                    rows = fb_rows[:20]
                    fallback_info = fb_info or {"phase": "keyword_in_raw_json", "source_rule_id": "event_id_schema"}
                    fallback_info["query_sql"] = planned_query.sql
        except Exception as exc:
            err_msg = str(exc)
            tracker.record(query_fp, verdict="exec_error", row_count=0)
            print(f"[red]SQL execution error — {planned_query.query_id}: {err_msg}[/red]")
            if emit_fn:
                emit_fn("investigate/do", f"[do] SQL execution error — {planned_query.query_id}: {err_msg}", iteration=plan_cycle, hypothesis_id=hypothesis.id)
            _append_hypothesis_reasoning(db=db, hypothesis_id=hypothesis.id, session_id=session_id,
                                         iteration=plan_cycle, phase="do", body=f"SQL execution error: {err_msg}",
                                         query_id=planned_query.query_id)
            state.last_execution_error = {
                "query_id": planned_query.query_id,
                "sql": planned_query.sql,
                "error": err_msg[:500],
            }
            continue
        result_summary = summarize_query_result(rows)
        _save_step(db=db, session_id=session_id, iteration=plan_cycle, phase="do",
                   hypothesis_id=hypothesis.id,
                   input_json={"planned_query": planned_query.model_dump(), "query_index": query_index},
                   output_json=result_summary, suffix=f"{planned_query.query_id}-{query_index:02d}")
        try:
            check_result = check_query_result(
                case=case, db=db, session_id=session_id,
                planned_query=planned_query, hypothesis=hypothesis,
                finding_candidates=candidates, result_summary=result_summary,
                memory=memory, base_url=base_url, model=model,
                overview_md=ctx.memory_overview, memory_context_md=ctx.memory_check,
                status_callback=llm_status_fn or (lambda msg: print(f"[yellow]{msg}[/yellow]")),
            )
        except Exception as exc:
            err_msg = f"[check] LLM failed for {hypothesis.id}/{planned_query.query_id}: {exc}"
            print(f"[red]{err_msg}[/red]")
            _append_hypothesis_reasoning(db=db, hypothesis_id=hypothesis.id, session_id=session_id,
                                         iteration=plan_cycle, phase="check", body=err_msg,
                                         query_id=planned_query.query_id)
            continue
        _save_step(db=db, session_id=session_id, iteration=plan_cycle, phase="check",
                   hypothesis_id=hypothesis.id,
                   input_json={"planned_query": planned_query.model_dump(),
                               "hypothesis": hypothesis.model_dump(), "result_summary": result_summary},
                   output_json=check_result.raw_response, suffix=f"{planned_query.query_id}-{query_index:02d}")
        reasoning_entry_id = _append_hypothesis_reasoning(
            db=db, hypothesis_id=hypothesis.id, session_id=session_id,
            iteration=plan_cycle, phase="check", body=check_result.report_text,
            verdict=check_result.verdict, query_id=planned_query.query_id,
        )
        chk_txt = (check_result.report_text or "").strip().replace("\n", " ")
        if len(chk_txt) > 120:
            chk_txt = chk_txt[:117] + "..."
        _log("CHECK", f"{hypothesis.id} {planned_query.query_id} — verdict={check_result.verdict}" + (f": {chk_txt}" if chk_txt else ""))
        if emit_fn:
            emit_fn("investigate/check", f"[check] {hypothesis.id}: verdict={check_result.verdict} query={planned_query.query_id}",
                    iteration=plan_cycle, report_kw={"focus_sections": focus_sections},
                    current_query=planned_query.query_id, hypothesis_id=hypothesis.id, reasoning_entry_id=reasoning_entry_id)
        state.history.append(HistoryEntry(
            iteration=plan_cycle, query_id=planned_query.query_id, hypothesis_id=hypothesis.id,
            verdict=check_result.verdict, summary=check_result.report_text,
            evidence_ids=result_summary.get("evidence_ids", []),
            template_id=planned_query.template_id,
            params=planned_query.params,
            purpose=planned_query.purpose,
        ))
        state.history = state.history[-50:]
        if check_result.new_hypotheses:
            state.active_hypotheses = _merge_active_hypotheses(
                db=db, current=state.active_hypotheses, updates=check_result.new_hypotheses,
                resolved=state.resolved_hypotheses, session_id=session_id, origin="check_new",
            )
        if check_result.verdict in {"confirmed", "refuted"}:
            _resolve_hypothesis(db=db, state=state, hypothesis_id=hypothesis.id,
                                verdict=check_result.verdict, summary=check_result.report_text,
                                session_id=session_id)
            _log("RESOLVE", f"{hypothesis.id} — {check_result.verdict} (resolved={len(state.resolved_hypotheses)})")
            cycle_progress = True
        elif check_result.verdict == "newlead" or check_result.progress:
            cycle_progress = True
            _upsert_hypothesis(db=db, hypothesis=Hypothesis(
                id=hypothesis.id, description=hypothesis.description,
                status="active", verdict=None, summary=check_result.report_text,
            ), origin="check_new", session_id=session_id)
        _apply_memory_updates(
            memory=memory, active_hypotheses=state.active_hypotheses,
            resolved_hypotheses=state.resolved_hypotheses,
            check_output={**check_result.raw_response, "memory_updates": check_result.memory_updates,
                          "suspicious_evidence": check_result.suspicious_evidence},
            current_hypothesis_id=hypothesis.id,
            db=db,
        )
        try:
            memory.compact_overview_if_needed(base_url=base_url, model=model)
            memory.compact_oversized_with_llm(base_url=base_url, model=model)
        except Exception as exc:
            print(f"[yellow][memory] compaction failed: {exc}[/yellow]")
        if check_result.verdict == "confirmed":
            memory.promote_hypothesis_scratch(hypothesis.id)
        elif check_result.verdict == "refuted":
            memory.archive_hypothesis_scratch(hypothesis.id)
        _ctx_refresh_caches(ctx, memory, base_url, model, current_hypothesis_id=hypothesis.id)
        _save_step(db=db, session_id=session_id, iteration=plan_cycle, phase="act",
                   hypothesis_id=hypothesis.id,
                   input_json={"hypothesis_id": hypothesis.id, "query_id": planned_query.query_id},
                   output_json={"verdict": check_result.verdict,
                                "active_hypotheses": [h.model_dump() for h in state.active_hypotheses],
                                "resolved_hypotheses": [h.model_dump() for h in state.resolved_hypotheses]},
                   suffix=f"{planned_query.query_id}-{query_index:02d}")
        if emit_fn:
            emit_fn("investigate/act", f"[act] {hypothesis.id}: verdict={check_result.verdict} resolved={len(state.resolved_hypotheses)}",
                    iteration=plan_cycle, report_kw={"focus_sections": focus_sections})
        if check_result.verdict in {"confirmed", "refuted"} or query_index >= max_queries_per_hypothesis:
            break
        row_count = int(result_summary.get("row_count") or 0)
        query_fp = _query_fingerprint(planned_query.sql)
        tracker.record(query_fp, check_result.verdict, row_count)
        def _rationale_signature(rationale: str) -> str:
            eids = sorted(set(re.findall(r"\b(?:event\s*id\s*)?(\d{3,5})\b", rationale.lower())))
            keywords = sorted(set(re.findall(r"\b(missing|requires|correlation|not\s+present|absent)\b", rationale.lower())))
            return "eid:" + ",".join(eids) + "|kw:" + ",".join(keywords)
        missing_checks_raw = check_result.raw_response.get("missing_questions") or check_result.raw_response.get("missing_checks") or []
        missing_signature = (
            "|".join(sorted(str(q).lower().strip() for q in missing_checks_raw if q))
            or _rationale_signature(str(check_result.report_text or check_result.raw_response.get("rationale", "")))
        )
        tracker.register_check(check_result.verdict, row_count, missing_signature)
        if tracker.should_pivot():
            _log("PIVOT", f"{hypothesis.id} — duplicate query fingerprint detected, auto-exhausted")
            break
        rule_context = resolve_rule_context(hypothesis)
        partial_confirm_signal = tracker.has_partial_confirm_signal(rule_context, rows, hypothesis)
        if tracker.should_auto_refute(consecutive_threshold=3) and not partial_confirm_signal:
            _log("RESOLVE", f"{hypothesis.id} — auto-refuted after 3+ consecutive 0-row inconclusive")
            _resolve_hypothesis(db=db, state=state, hypothesis_id=hypothesis.id, verdict="refuted",
                                summary="Auto-refuted: repeated 0-row inconclusive results indicate the hypothesis cannot be verified with available evidence.",
                                session_id=session_id)
            cycle_progress = True
            break
        if tracker.should_auto_refute_due_to_unobserved_events():
            _log("RESOLVE", f"{hypothesis.id} — auto-refuted after {tracker.consecutive_same_missing}+ consecutive same-missing checks")
            _resolve_hypothesis(db=db, state=state, hypothesis_id=hypothesis.id, verdict="refuted",
                                summary="hypothesis requires evidence not present in current dataset (3+ consecutive same-missing check)",
                                session_id=session_id)
            cycle_progress = True
            break
        if check_result.verdict == "inconclusive":
            if tracker.should_auto_confirm(rule_context, rows, hypothesis):
                _log("RESOLVE", f"{hypothesis.id} — auto-confirmed via co_observed_event_ids")
                _resolve_hypothesis(db=db, state=state, hypothesis_id=hypothesis.id, verdict="confirmed",
                                    summary="Auto-confirmed: all co_observed_event_ids from rule context were found in query results.",
                                    session_id=session_id)
                cycle_progress = True
                break

    return cycle_progress, state, focus_sections


def _hypothesis_actually_changed(original: Hypothesis, returned: Hypothesis) -> bool:
    """Detect a real planner update vs the LLM echoing the input hypothesis back."""
    if original.id != returned.id:
        return True
    if (original.description or "").strip() != (returned.description or "").strip():
        return True
    orig_cw = original.confirm_when or {}
    ret_cw = returned.confirm_when or {}
    if sorted(map(str, orig_cw.get("co_observed_event_ids", []) or [])) != sorted(map(str, ret_cw.get("co_observed_event_ids", []) or [])):
        return True
    if sorted(map(str, original.required_entities or [])) != sorted(map(str, returned.required_entities or [])):
        return True
    return False


def _fallback_planned_query_from_hypothesis(hypothesis: Hypothesis, query_index: int) -> PlannedQuery | None:
    """When the planner LLM fails to emit a runnable query, synthesize one from
    the hypothesis's confirm_when.co_observed_event_ids. This guarantees the
    check phase fires at least once per cycle instead of looping forever.
    """
    confirm_when = hypothesis.confirm_when or {}
    ids = confirm_when.get("co_observed_event_ids") or []
    event_ids: list[int] = []
    for entry in ids:
        try:
            event_ids.append(int(str(entry).strip()))
        except (TypeError, ValueError):
            continue
    if not event_ids:
        return None
    id_list = ", ".join(str(eid) for eid in event_ids)
    sql = (
        "SELECT event_id, timestamp, computer, channel, raw_json "
        f"FROM evtx_events WHERE event_id IN ({id_list}) "
        "ORDER BY timestamp LIMIT 500"
    )
    return PlannedQuery(
        query_id=f"Q-{hypothesis.id}-fb{query_index}",
        hypothesis_id=hypothesis.id,
        purpose=f"Fallback: enumerate evidence rows for event_ids {event_ids} (planner did not emit SQL).",
        template_id=None,
        params={},
        sql=sql,
    )


def _execute_query(db: CaseDB, planned_query: PlannedQuery, hypothesis: Hypothesis) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    """Execute SQL query and optional fallback. Returns (rows, fallback_info)."""
    try:
        rows = fetch_records(db, planned_query.sql)
        if not rows and hypothesis.source_rule_ids:
            for source_rule_id in hypothesis.source_rule_ids:
                rule = load_rule_by_id(source_rule_id)
                if rule and rule.fallback_search:
                    for fallback in rule.fallback_search:
                        if isinstance(fallback, dict):
                            rows = execute_fallback_search(db, fallback)
                            if rows:
                                return rows, {"phase": fallback.get("phase"), "source_rule_id": source_rule_id}
        if not rows:
            rows, fallback_info = execute_event_keyword_fallback_search(db, planned_query.sql)
            if rows:
                if fallback_info is None:
                    fallback_info = {"phase": "keyword_in_raw_json"}
                fallback_info["query_sql"] = planned_query.sql
                return rows, fallback_info
        return rows, None
    except Exception:
        return None, None


async def _check_query(
    planned_query: PlannedQuery,
    hypothesis: Hypothesis,
    result_summary: dict[str, Any],
    findings_snapshot: list[dict[str, Any]],
    memory: MemoryManager,
    base_url: str,
    model: str,
) -> CheckResult | None:
    """Execute check phase. Returns CheckResult or None on error."""
    try:
        return check_query_result(
            case=None,
            db=None,
            session_id="",
            planned_query=planned_query,
            hypothesis=hypothesis,
            finding_candidates=_matching_findings(findings_snapshot, hypothesis),
            result_summary=result_summary,
            memory=memory,
            base_url=base_url,
            model=model,
            overview_md=None,
            memory_context_md=None,
        )
    except Exception:
        return None


def _record_check_result(
    state: SessionState,
    hypothesis: Hypothesis,
    planned_query: PlannedQuery,
    check_result: CheckResult,
    result_summary: dict[str, Any],
    plan_cycle: int,
) -> None:
    """Record check outcome to history and state."""
    state.history.append(
        HistoryEntry(
            iteration=plan_cycle,
            query_id=planned_query.query_id,
            hypothesis_id=hypothesis.id,
            verdict=check_result.verdict,
            summary=check_result.report_text,
            evidence_ids=result_summary.get("evidence_ids", []),
            template_id=planned_query.template_id,
            params=planned_query.params,
            purpose=planned_query.purpose,
        )
    )
    state.history = state.history[-50:]


def _apply_outcome(
    state: SessionState,
    hypothesis: Hypothesis,
    check_result: CheckResult,
    session_id: str,
    db: CaseDB,
) -> None:
    """Apply check outcome to hypothesis state."""
    if check_result.verdict in {"confirmed", "refuted"}:
        _resolve_hypothesis(db, state, hypothesis.id, check_result.verdict, check_result.report_text, session_id)
    elif check_result.new_hypotheses:
        state.active_hypotheses = _merge_active_hypotheses(
            db=db,
            current=state.active_hypotheses,
            updates=check_result.new_hypotheses,
            resolved=state.resolved_hypotheses,
            session_id=session_id,
            origin="check_new",
        )


def _dedup_new_hypotheses(new_hypotheses: list[Hypothesis], active_hypotheses: list[Hypothesis], threshold: float = 0.85) -> list[Hypothesis]:
    """Filter out hypotheses that are too similar to existing active ones."""
    accepted = []
    for new_h in new_hypotheses:
        is_duplicate = False
        for existing in active_hypotheses:
            if _hypothesis_similarity(new_h.description, existing.description) > threshold:
                is_duplicate = True
                break
        if not is_duplicate:
            accepted.append(new_h)
    return accepted


@functools.lru_cache(maxsize=1)
def _known_db_columns() -> frozenset[str]:
    """Whitelist of valid DB column names sourced from rulepacks/_schema/*.yaml.

    Used to reject natural-language `required_entities` (e.g. 'user_identity',
    'computer_name') that pass the snake_case regex but are not real columns.
    """
    from forensia.ai.prompts import _load_schema_hints
    cols: set[str] = set()
    for hint in _load_schema_hints().values():
        for col in (hint.get("columns") or []) + (hint.get("core_columns") or []):
            cols.add(str(col).strip())
    # Augment with synonyms that drafter commonly emits and we accept as aliases
    cols.update({"src_ip", "dst_ip", "target_user", "subject_user", "logon_type", "process_name", "file_path", "computer", "event_id", "timestamp", "command_line", "service_name"})
    return frozenset(c for c in cols if c)


def _filter_valid_entities(raw: list[Any]) -> list[str]:
    """Keep only entries that are real DB columns from the rulepack schema cards.

    Drops natural-language phrases formatted as snake_case (e.g. 'user_identity',
    'computer_name', 'credential_usage') that the bare snake_case regex would
    otherwise accept.
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


def _parse_hypothesis_from_drafter(parsed: dict[str, Any]) -> Hypothesis | None:
    """Parse drafter LLM output into a Hypothesis object.

    The drafter returns ``{"hypothesis": {"description": "...", "required_entities": [...], "source_rule_ids": [...], "confirm_when": {...}, "refute_when": {...}}}``.
    Tolerates LLMs that return ``confirm_when`` / ``refute_when`` as strings by
    coercing to the schema's dict shape. Assigns a placeholder id that
    ``_merge_active_hypotheses`` will replace.
    """
    hyp_raw = parsed.get("hypothesis")
    if not isinstance(hyp_raw, dict):
        return None
    hyp_raw = dict(hyp_raw)
    hyp_raw.setdefault("id", "draft")
    hyp_raw.setdefault("source_rule_ids", [])
    # Coerce string confirm_when/refute_when (LLM drift) into the dict shape Pydantic expects.
    for key in ("confirm_when", "refute_when"):
        val = hyp_raw.get(key)
        if isinstance(val, str):
            hyp_raw[key] = {"_llm_note": val} if val.strip() else None
    entities = _filter_valid_entities(hyp_raw.get("required_entities") or [])
    if not entities:
        _log("PLAN", f"drafter output dropped: invalid required_entities {hyp_raw.get('required_entities')}")
        return None
    hyp_raw["required_entities"] = entities
    try:
        return Hypothesis.model_validate(hyp_raw)
    except Exception as exc:
        _log("PLAN", f"drafter output dropped (validation failed): {str(exc).splitlines()[0][:160]}")
        return None


async def _run_broad_plan_step(
    state: SessionState,
    db: CaseDB,
    session_id: str,
    base_url: str,
    model: str,
    llm_logger: LLMCallLogger,
    plan_cycle: int,
    observed_keypoints: list[dict[str, Any]],
    emit_fn: Callable[..., None] | None,
    llm_status_fn: Callable[[str], None],
) -> bool:
    """Execute broad planning step (2-stage: gap_identifier → hypothesis_drafter). Returns stop flag."""
    observed_keypoint_labels = [
        f"{item['keypoint']} (rows={item['row_count']})"
        for item in observed_keypoints
    ]
    plan_input = state.model_dump()
    try:
        # 1) gap_identifier — identify which keypoints lack hypothesis coverage
        observed_kp_strs = observed_keypoint_labels or _observed_keypoints_from_findings(state.findings_snapshot)
        uncovered_keypoints = _compute_uncovered_keypoints(observed_kp_strs, state.active_hypotheses, state.resolved_hypotheses)
        active_hypotheses_slim = [{"id": h.id, "description": h.description, "verdict": h.verdict} for h in state.active_hypotheses[:10]]
        gap_msgs, gap_schema = build_gap_identifier_messages(
            observed_keypoints=observed_keypoints,
            uncovered_keypoints=uncovered_keypoints,
            active_hypotheses_slim=active_hypotheses_slim,
        )
        gap_parsed = await _call_with_outage_recovery(
            request_llm_json, base_url=base_url, model=model,
            messages=gap_msgs,
            json_schema=gap_schema,
            status_callback=llm_status_fn,
            audit_callback=lambda msgs, out, parsed: llm_logger.write(
                iteration=plan_cycle, phase="plan-broad-gap", input_messages=msgs,
                output=parsed, model=model, base_url=base_url,
            ),
        )
        gap_areas = gap_parsed.get("gap_areas", [])
        valid_gap_areas = [g for g in gap_areas if g.get("keypoint_id") in REPORT_KEYPOINTS]
        if len(valid_gap_areas) < len(gap_areas):
            _log("PLAN", f"gap_identifier invented {len(gap_areas) - len(valid_gap_areas)} non-existent keypoint names, dropped")
        gap_areas = valid_gap_areas

        # 2) hypothesis_drafter — draft one hypothesis per gap area
        rule_cache = _get_rule_cache()
        available_rules = [rule.model_dump() for rule in rule_cache.values()]
        drafted_hypotheses: list[Hypothesis] = []
        for gap in gap_areas:
            h_msgs, h_schema = build_hypothesis_drafter_messages(gap, available_rules)
            h_parsed = await _call_with_outage_recovery(
                request_llm_json, base_url=base_url, model=model,
                messages=h_msgs,
                json_schema=h_schema,
                status_callback=llm_status_fn,
                audit_callback=lambda msgs, out, parsed: llm_logger.write(
                    iteration=plan_cycle, phase="plan-broad-draft", input_messages=msgs,
                    output=parsed, model=model, base_url=base_url,
                ),
            )
            hyp = _parse_hypothesis_from_drafter(h_parsed)
            if hyp:
                kpid = gap.get("keypoint_id", "")
                if kpid:
                    hyp.target_keypoint_id = kpid
                drafted_hypotheses.append(hyp)

        # 3) dedup + merge
        deduped = _dedup_new_hypotheses(drafted_hypotheses, state.active_hypotheses)
        state.active_hypotheses = _merge_active_hypotheses(
            db=db, current=state.active_hypotheses, updates=deduped,
            resolved=state.resolved_hypotheses, session_id=session_id, origin="broad_plan",
        )
        stop_flag = not bool(gap_areas)
        _save_step(db=db, session_id=session_id, iteration=plan_cycle, phase="plan-broad",
                   hypothesis_id=None, input_json=plan_input,
                   output_json={"gap_areas": gap_areas, "hypotheses": [h.model_dump() for h in drafted_hypotheses]})
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="plan-broad-audit",
            hypothesis_id=None,
            input_json={"hypotheses": [item.model_dump() for item in drafted_hypotheses]},
            output_json={"audits": _audit_broad_plan_hypotheses(state, drafted_hypotheses)},
        )
        _log("PLAN", f"+{len(drafted_hypotheses)} new hypotheses (active={len(state.active_hypotheses)}, stop={stop_flag})")
        if emit_fn:
            emit_fn("investigate/plan", f"[plan] new_hypotheses={len(drafted_hypotheses)} active={len(state.active_hypotheses)}", iteration=plan_cycle)
        return stop_flag
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code >= 500:
            raise
        err_msg = f"[plan-broad] LLM failed: {exc}"
        print(f"[red]{err_msg}[/red]")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        err_msg = f"[plan-broad] LLM server error: {exc}"
        print(f"[red]{err_msg}[/red]")
        raise
    except LLMServerUnavailableError:
        raise
    except Exception as exc:
        err_msg = f"[plan-broad] LLM failed: {exc}"
        print(f"[red]{err_msg}[/red]")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False


async def _run_cycle_body(
    *,
    state: "SessionState",
    ctx: "_Ctx",
    db: "CaseDB",
    case: "Case",
    session_id: str,
    base_url: str,
    model: str,
    memory: "MemoryManager",
    llm_logger: "LLMCallLogger",
    progress_callback: Callable[[dict[str, Any]], None] | None,
    max_queries_per_hypothesis: int,
    plan_cycle: int,
    report_only: bool,
) -> tuple[bool, bool, list[str], dict[str, Any]]:
    """Run one plan cycle: broad plan + hypothesis loop.

    Returns (broad_plan_stop, cycle_progress, focus_sections, report_before).
    """
    def _emit(stage: str, summary: str, *, report_kw: dict | None = None, iteration: int | None = None, **extras: Any) -> None:
        if not progress_callback:
            return
        payload = {
            "stage": stage, "status": "running",
            "iteration": state.iteration if iteration is None else iteration,
            "summary": summary, "focus_hypothesis_id": state.focus_hypothesis_id,
            "hypotheses": [h.model_dump() for h in _all_hypotheses(state)],
            "report_sections": _ctx_get_report_status(ctx, db, **(report_kw or {})),
        }
        payload.update(extras)
        progress_callback(payload)

    def llm_status(message: str) -> None:
        print(f"[yellow]{message}[/yellow]")
        _emit("investigate/llm", message, iteration=state.iteration)

    broad_plan_stop = False
    cycle_progress = False
    focus_sections: list[str] = []
    report_before = _ctx_get_report_status(ctx, db)
    observed_keypoints = _scan_report_keypoints(case, db)
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="plan-keypoint-scan",
        hypothesis_id=None,
        input_json={"keypoints": sorted(REPORT_KEYPOINTS.keys())},
        output_json={"observed_keypoints": observed_keypoints},
    )

    if not report_only:
        broad_plan_stop = await _call_with_outage_recovery(
            _run_broad_plan_step, base_url=base_url, model=model,
            state=state, db=db, session_id=session_id,
            llm_logger=llm_logger,
            plan_cycle=plan_cycle, observed_keypoints=observed_keypoints,
            emit_fn=_emit, llm_status_fn=llm_status,
        )
        focus_hypotheses = _select_focus_hypotheses(state, max_items=2)
        for hypothesis in focus_hypotheses:
            if ctx.interrupted:
                break
            state.focus_hypothesis_id = hypothesis.id
            state.focus_depth = 0
            _ctx_refresh_caches(ctx, memory, base_url, model, current_hypothesis_id=hypothesis.id)
            focus_sections = _guess_related_sections(hypothesis.description)
            _log("HYPOTHESIS", f"{hypothesis.id} — {hypothesis.description}")
            _emit("investigate/hypothesis", f"[hypothesis] {hypothesis.id}: {hypothesis.description}",
                  iteration=plan_cycle, report_kw={"focus_sections": focus_sections})
            progress, state, sections = await _investigate_one_hypothesis(
                hypothesis=hypothesis, state=state, ctx=ctx, memory=memory, db=db,
                base_url=base_url, model=model, plan_cycle=plan_cycle,
                llm_logger=llm_logger, session_id=session_id,
                max_queries_per_hypothesis=max_queries_per_hypothesis, case=case,
                query_limit=max(max_queries_per_hypothesis, 10),
                emit_fn=_emit, llm_status_fn=llm_status,
            )
            if progress:
                cycle_progress = True

    return broad_plan_stop, cycle_progress, focus_sections, report_before


async def _run_report_phase(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    plan_cycle: int,
    report_every_n_cycles: int,
    template_root: Path,
    base_url: str,
    model: str,
    llm_logger: "LLMCallLogger",
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str],
    report_max_queries_per_section: int,
    state: "SessionState",
    report_before: dict[str, Any],
    memory: "MemoryManager",
) -> tuple[dict[str, Any], bool]:
    """Run the report refresh phase. Returns (report_after, cycle_progress_from_report)."""
    cycle_progress = False
    if plan_cycle % max(1, report_every_n_cycles) != 0:
        return report_before, cycle_progress
    report_result: dict[str, Any] | None = None
    try:
        template_paths = sorted(template_root.glob("[0-9]*_*.md"))
        report_result = await async_refresh_report_sections(
            case=case, db=db, session_id=session_id, iteration=plan_cycle,
            base_url=base_url, model=model, template_paths=template_paths,
            llm_logger=llm_logger, progress_callback=progress_callback,
            focus_sections=focus_sections,
            max_queries_per_section=report_max_queries_per_section,
        )
    except Exception as exc:
        print(f"[red][report] section refresh failed: {exc}[/red]")
        if progress_callback:
            progress_callback({"stage": "investigate/report-cycle-done", "status": "running",
                               "iteration": plan_cycle, "summary": f"[report] refresh failed: {exc}"})
    if report_result is None:
        return report_before, cycle_progress
    report_after = report_result["report_status"]
    gap_new_hypotheses = _inject_gap_hypotheses(
        db=db, state=state, gaps=report_result["gaps"], session_id=session_id, memory=memory,
    )
    if gap_new_hypotheses:
        cycle_progress = True
    if _report_cycle_progress(report_before, report_after):
        cycle_progress = True
    render_written_report(case, db)
    return report_after, cycle_progress


def _check_termination(
    *,
    report_only: bool,
    broad_plan_stop: bool,
    active_hypotheses: list,
    db: CaseDB,
    report_after: dict[str, Any],
    no_progress_count: int,
    no_progress_limit: int,
    cycle_progress: bool,
) -> tuple[str | None, int]:
    """Check if the investigation loop should stop. Returns (terminal_status or None, updated_no_progress_count)."""
    if report_only:
        return "completed", no_progress_count
    unresolved_gap_count = int(report_after.get("total_gaps", 0))
    if broad_plan_stop and not active_hypotheses and unresolved_gap_count == 0:
        mark_report_sections_ai_exhausted(db)
        return "completed", no_progress_count
    no_progress_count = 0 if cycle_progress else no_progress_count + 1
    if no_progress_count >= no_progress_limit:
        return "completed", no_progress_count
    return None, no_progress_count


def _init_session(
    case: Case, db: CaseDB, profile: str, base_url: str, model: str,
    template_root: Path | None,
) -> tuple["SessionState", "_Ctx", "MemoryManager", "LLMCallLogger", str, datetime, Path]:
    """Initialize a new investigation session. Returns (state, ctx, memory, llm_logger, session_id, started_at, template_root)."""
    session_id = f"session-{uuid4().hex[:12]}"
    started_at = datetime.now(UTC).replace(tzinfo=None)
    memory = MemoryManager(case)
    profile_config = _load_profile_config(profile)
    if template_root is None:
        case.ensure_report_templates()
        template_root = case.report_template_dir
    _seed_findings(case, db, profile)
    _initialize_overview(memory, case, profile_config)
    _ensure_profile_objective(memory, profile_config)
    llm_logger = LLMCallLogger(case, session_id)
    active_hypotheses, resolved_hypotheses = _load_persisted_hypotheses(db)
    state = SessionState(
        session_id=session_id, iteration=0, findings_snapshot=_finding_snapshot(db),
        active_hypotheses=active_hypotheses, resolved_hypotheses=resolved_hypotheses,
    )
    _sync_keypoint_cards(memory, state.findings_snapshot)
    _sync_hypothesis_cards(memory, state.active_hypotheses, state.resolved_hypotheses)
    ctx = _Ctx(report_status=_build_report_status(db))
    _ctx_refresh_caches(ctx, memory, base_url, model)
    db.execute(
        "INSERT INTO investigation_sessions (session_id, started_at, finished_at, iterations, status) VALUES (?, ?, ?, ?, ?)",
        (session_id, started_at, None, 0, "running"),
    )
    return state, ctx, memory, llm_logger, session_id, started_at, template_root


async def investigate(
    case: Case,
    db: CaseDB,
    base_url: str,
    model: str,
    max_iter: int = 20,
    no_progress_limit: int = 3,
    profile: str = "windows-basic",
    max_queries_per_hypothesis: int = 5,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    report_every_n_cycles: int = 1,
    report_only: bool = False,
    template_root: Path | None = None,
    report_max_queries_per_section: int = 3,
    max_llm_calls: int = 200,
) -> dict[str, Any]:
    """Run the full investigation loop: broad plan → hypothesis loop → report refresh, with termination checks and LLM budget enforcement."""
    state, ctx, memory, llm_logger, session_id, started_at, template_root = _init_session(
        case, db, profile, base_url, model, template_root,
    )
    case.extract_time_range(db.conn)
    status = "running"
    no_progress_count = 0
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda signum, frame: setattr(ctx, "interrupted", True))

    def _check_llm_budget() -> None:
        if max_llm_calls > 0 and llm_logger.total_calls >= max_llm_calls:
            raise RuntimeError(
                f"LLM call budget exceeded: {llm_logger.total_calls} calls >= {max_llm_calls} max. "
                f"Per-phase: {llm_logger.count_by_phase()}. "
                "Increase --max-llm-calls (or pass 0 for unlimited) or investigate the cause of excessive calls."
            )

    try:
        for plan_cycle in range(1, max_iter + 1):
            _check_llm_budget()
            state.iteration = plan_cycle
            state.iteration = plan_cycle
            state.findings_snapshot = _finding_snapshot(db)
            _sync_keypoint_cards(memory, state.findings_snapshot)
            _log("PLAN", f"Cycle {plan_cycle}/{max_iter} — broad planning (active={len(state.active_hypotheses)} resolved={len(state.resolved_hypotheses)})")
            if ctx.interrupted:
                status = "stopped"
                break
            broad_plan_stop, cycle_progress, focus_sections, report_before = await _run_cycle_body(
                state=state, ctx=ctx, db=db, case=case, session_id=session_id,
                base_url=base_url, model=model, memory=memory, llm_logger=llm_logger,
                progress_callback=progress_callback,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                plan_cycle=plan_cycle, report_only=report_only,
            )
            if ctx.interrupted:
                status = "stopped"
                break
            report_after, report_cycle_progress = await _run_report_phase(
                case=case, db=db, session_id=session_id, plan_cycle=plan_cycle,
                report_every_n_cycles=report_every_n_cycles, template_root=template_root,
                base_url=base_url, model=model, llm_logger=llm_logger,
                progress_callback=progress_callback, focus_sections=focus_sections,
                report_max_queries_per_section=report_max_queries_per_section,
                state=state, report_before=report_before, memory=memory,
            )
            ctx.report_status = report_after
            cycle_progress = cycle_progress or report_cycle_progress
            terminal_status, no_progress_count = _check_termination(
                report_only=report_only, broad_plan_stop=broad_plan_stop,
                active_hypotheses=state.active_hypotheses, db=db,
                report_after=report_after, no_progress_count=no_progress_count,
                no_progress_limit=no_progress_limit, cycle_progress=cycle_progress,
            )
            if terminal_status is not None:
                status = terminal_status
                break
        else:
            status = "completed"
    except Exception:
        status = "failed"
        raise
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        finished_at = datetime.now(UTC).replace(tzinfo=None)
        db.execute(
            "UPDATE investigation_sessions SET finished_at = ?, iterations = ?, status = ? WHERE session_id = ?",
            (finished_at, state.iteration, status, session_id),
        )
    summary = _final_summary(state)
    return {
        "session_id": session_id, "status": status,
        "iteration": state.iteration, "depth": state.focus_depth,
        "focus_hypothesis_id": state.focus_hypothesis_id, "summary": summary,
        "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
        "report_sections": _ctx_get_report_status(ctx, db, refresh=True),
    }
