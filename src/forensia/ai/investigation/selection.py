"""Deterministic next-best hypothesis selection with priority scoring."""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import yaml

from forensia.db.database import CaseDB
from forensia.knowledge.coverage import infer_capabilities

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    "severity": 1.0,
    "report_relevance": 1.0,
    "goal_relevance": 1.0,
    "evidence_availability": 1.0,
    "observability": 1.0,
    "dependency_impact": 1.0,
    "related_hypotheses": 1.0,
    "information_gain_proxy": 1.0,
    "report_changeability": 1.0,
    "aging": 1.0,
    "execution_cost": 1.0,
    "retry_penalty": 1.0,
    "duplicate_penalty": 1.0,
    "repeated_inconclusive_penalty": 1.0,
}

COMPONENT_RANGES = {
    "severity": (0, 24),
    "report_relevance": (0, 12),
    "goal_relevance": (0, 10),
    "evidence_availability": (0, 8),
    "observability": (-25, 8),
    "dependency_impact": (0, 12),
    "related_hypotheses": (0, 5),
    "information_gain_proxy": (0, 10),
    "report_changeability": (0, 8),
    "aging": (0, 8),
    "execution_cost": (0, 10),
    "retry_penalty": (0, 24),
    "duplicate_penalty": (0, 20),
    "repeated_inconclusive_penalty": (0, 12),
}


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _count_consecutive_inconclusive(db: CaseDB, hypothesis_id: str) -> int:
    """Count consecutive inconclusive verdicts from recent reasoning."""
    rows = db.execute(
        "SELECT verdict FROM trace.hypothesis_reasoning "
        "WHERE hypothesis_id = ? AND phase = 'sufficiency' "
        "ORDER BY created_at DESC LIMIT 10",
        [hypothesis_id],
    ).fetchall()
    if not rows:
        rows = db.execute(
            "SELECT verdict FROM trace.hypothesis_reasoning "
            "WHERE hypothesis_id = ? AND phase = 'check' "
            "ORDER BY created_at DESC LIMIT 10",
            [hypothesis_id],
        ).fetchall()
    count = 0
    for r in rows:
        if r[0] == "inconclusive":
            count += 1
        else:
            break
    return count


def _tokenize(text: str) -> set[str]:
    """Lowercase tokenize for simple overlap checks."""
    return {w for w in text.lower().split() if len(w) > 2}


def _capabilities_for_hypothesis(hyp: dict[str, Any]) -> set[str]:
    """Infer the capabilities a hypothesis can actually consume."""
    text = json.dumps(hyp.get("confirm_when") or {}, ensure_ascii=False).lower()
    return set(infer_capabilities(text))


@dataclass
class PriorityComponent:
    name: str
    raw_value: float
    clamped: float
    weight: float
    weighted: float
    reason: str


@dataclass
class SelectionResult:
    hypothesis_id: str
    total_score: float
    components: list[PriorityComponent]
    eligible: bool
    block_reason: str = ""


@dataclass
class SelectionContext:
    """Context gathered from DB for scoring."""

    active_hypotheses: list[dict[str, Any]]
    relations: dict[str, list[dict[str, Any]]]
    coverage: dict[str, dict[str, str]]
    report_sections: dict[str, dict[str, Any]]
    open_gaps: list[dict[str, Any]]
    objective: str
    hypothesis_statuses: dict[str, str] | None = None
    open_tasks: list[dict[str, Any]] | None = None


def _json_value(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except TypeError, ValueError:
            return default
    return value


def _load_priority_weights() -> dict[str, float]:
    """Load priority weights from _schema/investigation_priority.yaml."""
    from forensia.knowledge.resources import schema_dir

    path = schema_dir() / "investigation_priority.yaml"
    if not path.exists():
        return dict(DEFAULT_WEIGHTS)
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        weights = data.get("weights", {})
        result = dict(DEFAULT_WEIGHTS)
        for k, v in weights.items():
            if k in result and isinstance(v, (int, float)):
                result[k] = float(v)
        return result
    except Exception:
        return dict(DEFAULT_WEIGHTS)


def gather_selection_context(db: CaseDB) -> SelectionContext:
    """Gather all context needed for priority scoring."""
    active = db.execute(
        "SELECT hypothesis_id, description, status, verdict, summary, origin, "
        "source_rule_ids, source_decl_id, required_entities, confirm_when, "
        "source_gap_id, selection_count, last_selected_at, next_eligible_at, "
        "blocked_reason, sufficiency_status, sufficiency_score "
        "FROM hypotheses WHERE status = 'active'"
    ).fetchall()

    active_hypotheses = []
    for r in active:
        active_hypotheses.append(
            {
                "hypothesis_id": r[0],
                "description": r[1] or "",
                "status": r[2],
                "verdict": r[3],
                "summary": r[4] or "",
                "origin": r[5] or "",
                "source_rule_ids": _json_value(r[6], []) if r[6] else [],
                "source_decl_id": r[7] or "",
                "required_entities": _json_value(r[8], []) if r[8] else [],
                "confirm_when": _json_value(r[9], {}) if r[9] else {},
                "source_gap_id": r[10] or "",
                "selection_count": r[11] or 0,
                "last_selected_at": r[12],
                "next_eligible_at": r[13],
                "blocked_reason": r[14] or "",
                "sufficiency_status": r[15] or "",
                "sufficiency_score": r[16] or 0.0,
            }
        )

    relations: dict[str, list[dict[str, Any]]] = {}
    rel_rows = db.execute(
        "SELECT from_hypothesis_id, to_hypothesis_id, relation_type, origin, confidence "
        "FROM hypothesis_relations"
    ).fetchall()
    for r in rel_rows:
        for hid in (r[0], r[1]):
            relations.setdefault(hid, []).append(
                {
                    "from_hypothesis_id": r[0],
                    "to_hypothesis_id": r[1],
                    "relation_type": r[2],
                    "origin": r[3],
                    "confidence": r[4],
                }
            )

    cov_rows = db.execute(
        "SELECT capability, state, reason_code, source_family FROM evidence_coverage"
    ).fetchall()
    coverage = {}
    for r in cov_rows:
        key = f"{r[3]}:{r[0]}"
        coverage[key] = {"state": r[1], "reason": r[2] or "", "family": r[3]}

    sections = db.execute(
        "SELECT section_key, title, status, confidence, gaps, stale FROM report_sections"
    ).fetchall()
    report_sections = {}
    for r in sections:
        report_sections[r[0]] = {
            "title": r[1] or "",
            "status": r[2] or "draft",
            "confidence": r[3] or 0.0,
            "gaps": _json_value(r[4], []) if r[4] else [],
            "stale": bool(r[5]),
        }

    gaps = db.execute(
        "SELECT gap_id, section_key, description, kind, status, hypothesis_id "
        "FROM report_gaps WHERE status = 'open'"
    ).fetchall()
    open_gaps = [
        {
            "gap_id": r[0],
            "section_key": r[1],
            "description": r[2],
            "kind": r[3],
            "status": r[4],
            "hypothesis_id": r[5] or "",
        }
        for r in gaps
    ]

    statuses = {
        str(row[0]): str(row[1] or "active")
        for row in db.execute("SELECT hypothesis_id, status FROM hypotheses").fetchall()
    }
    task_rows = db.execute(
        "SELECT task_id, hypothesis_id, required_capability, kind "
        "FROM investigation_tasks WHERE status = 'open'"
    ).fetchall()
    open_tasks = [
        {
            "task_id": row[0],
            "hypothesis_id": row[1] or "",
            "required_capability": row[2] or "",
            "kind": row[3] or "",
        }
        for row in task_rows
    ]

    objective_row = db.execute(
        "SELECT objective FROM investigation_state WHERE state_id = 'case'"
    ).fetchone()
    objective = objective_row[0] if objective_row and objective_row[0] else ""

    return SelectionContext(
        active_hypotheses=active_hypotheses,
        relations=relations,
        coverage=coverage,
        report_sections=report_sections,
        open_gaps=open_gaps,
        objective=objective,
        hypothesis_statuses=statuses,
        open_tasks=open_tasks,
    )


def _compute_severity(hyp: dict[str, Any], findings_snapshot: Any) -> float:
    """Compute severity component from source rule findings."""
    source_rules = hyp.get("source_rule_ids", [])
    if not source_rules or not findings_snapshot:
        return 4.0
    max_sev = "low"
    values = (
        findings_snapshot.values()
        if isinstance(findings_snapshot, dict)
        else findings_snapshot
    )
    for f in values:
        if f.get("rule_id") in source_rules:
            sev = f.get("severity", "low")
            if sev == "critical":
                return 24.0
            elif sev == "high" and max_sev != "critical":
                max_sev = "high"
            elif sev == "medium" and max_sev not in ("high", "critical"):
                max_sev = "medium"
    return {"critical": 24, "high": 16, "medium": 8, "low": 0}.get(max_sev, 0)


def _compute_report_relevance(hyp: dict[str, Any], ctx: SelectionContext) -> float:
    """How relevant is this hypothesis to report gaps/stale sections."""
    score = 0.0
    hid = hyp["hypothesis_id"]
    for gap in ctx.open_gaps:
        if gap.get("hypothesis_id") == hid or gap.get("gap_id") == hyp.get(
            "source_gap_id"
        ):
            score += 4.0
    hyp_tokens = _tokenize(hyp.get("description", ""))
    for sec in ctx.report_sections.values():
        section_tokens = _tokenize(
            " ".join(str(item) for item in [sec.get("title", ""), *sec.get("gaps", [])])
        )
        if sec.get("stale") and hyp_tokens & section_tokens:
            score += 2.0
    return min(score, 12.0)


def _compute_aging(hyp: dict[str, Any]) -> float:
    """Compute aging bonus from last_selected_at."""
    last = hyp.get("last_selected_at")
    if last is None:
        return 8.0
    if isinstance(last, str):
        try:
            last = datetime.fromisoformat(last)
        except ValueError:
            return 8.0
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    delta = (datetime.now(UTC) - last).total_seconds() / 3600.0
    return min(delta / 24.0 * 2.0, 8.0)


def compute_priority_score(
    hyp: dict[str, Any],
    ctx: SelectionContext,
    findings_snapshot: dict[str, Any] | None = None,
    db: CaseDB | None = None,
) -> tuple[float, list[PriorityComponent]]:
    """Compute deterministic priority score for a hypothesis."""
    weights = _load_priority_weights()
    components: list[PriorityComponent] = []
    findings = findings_snapshot or {}
    hyp_id = hyp["hypothesis_id"]

    raw = _compute_severity(hyp, findings)
    clamped = _clamp(raw, *COMPONENT_RANGES["severity"])
    components.append(
        PriorityComponent(
            "severity",
            raw,
            clamped,
            weights["severity"],
            clamped * weights["severity"],
            f"max finding severity from {len(hyp.get('source_rule_ids', []))} rules",
        )
    )

    raw = _compute_report_relevance(hyp, ctx)
    clamped = _clamp(raw, *COMPONENT_RANGES["report_relevance"])
    components.append(
        PriorityComponent(
            "report_relevance",
            raw,
            clamped,
            weights["report_relevance"],
            clamped * weights["report_relevance"],
            f"{len(ctx.open_gaps)} open gaps",
        )
    )

    # goal_relevance: token overlap with objective
    if ctx.objective:
        obj_tokens = _tokenize(ctx.objective)
        hyp_text = (
            hyp.get("description", "") + " " + " ".join(hyp.get("source_rule_ids", []))
        )
        hyp_tokens = _tokenize(hyp_text)
        if obj_tokens:
            overlap = len(obj_tokens & hyp_tokens) / len(obj_tokens)
            raw = 2.0 + overlap * 8.0  # 2-10 range
            reason = (
                f"{len(obj_tokens & hyp_tokens)}/{len(obj_tokens)} objective tokens"
            )
        else:
            raw = 5.0
            reason = "objective has no tokens"
    else:
        raw = 0.0
        reason = "no objective set"
    clamped = _clamp(raw, *COMPONENT_RANGES["goal_relevance"])
    components.append(
        PriorityComponent(
            "goal_relevance",
            raw,
            clamped,
            weights["goal_relevance"],
            clamped * weights["goal_relevance"],
            reason,
        )
    )

    relevant_capabilities = _capabilities_for_hypothesis(hyp)
    relevant_coverage = {
        key: cov
        for key, cov in ctx.coverage.items()
        if not relevant_capabilities or key.split(":", 1)[-1] in relevant_capabilities
    }

    # evidence_availability: check coverage for relevant capabilities
    if relevant_coverage:
        relevant_states = []
        for cov in relevant_coverage.values():
            relevant_states.append(cov.get("state", "unavailable"))
        if relevant_states:
            avail_count = sum(1 for s in relevant_states if s == "available")
            ratio = avail_count / len(relevant_states)
            if ratio == 1.0:
                raw = 8.0
                reason = "all capabilities available"
            elif ratio == 0.0:
                raw = 0.0
                reason = "no capabilities available"
            else:
                raw = 4.0 + ratio * 2.0  # 4-6 range
                reason = f"{avail_count}/{len(relevant_states)} available"
        else:
            raw = 4.0
            reason = "default (no coverage data)"
    else:
        raw = 4.0
        reason = "default (no coverage data)"
    clamped = _clamp(raw, *COMPONENT_RANGES["evidence_availability"])
    components.append(
        PriorityComponent(
            "evidence_availability",
            raw,
            clamped,
            weights["evidence_availability"],
            clamped * weights["evidence_availability"],
            reason,
        )
    )

    # observability: penalty for unavailable required capabilities
    if relevant_coverage:
        unavail = [
            cov for cov in relevant_coverage.values() if cov.get("state") != "available"
        ]
        if unavail:
            unavail_ratio = len(unavail) / len(relevant_coverage)
            if unavail_ratio > 0.7:
                raw = -25.0
                reason = f"{len(unavail)} capabilities unavailable (>70%)"
            elif unavail_ratio > 0.3:
                raw = -15.0
                reason = f"{len(unavail)} capabilities unavailable (30-70%)"
            else:
                raw = -5.0
                reason = f"{len(unavail)} capabilities unavailable (<30%)"
        else:
            raw = 0.0
            reason = "all capabilities observable"
    else:
        raw = 0.0
        reason = "default (no coverage data)"
    clamped = _clamp(raw, *COMPONENT_RANGES["observability"])
    components.append(
        PriorityComponent(
            "observability",
            raw,
            clamped,
            weights["observability"],
            clamped * weights["observability"],
            reason,
        )
    )

    rels = ctx.relations.get(hyp_id, [])
    raw = min(len(rels) * 3.0, 12.0)
    clamped = _clamp(raw, *COMPONENT_RANGES["dependency_impact"])
    components.append(
        PriorityComponent(
            "dependency_impact",
            raw,
            clamped,
            weights["dependency_impact"],
            clamped * weights["dependency_impact"],
            f"{len(rels)} relations",
        )
    )

    raw = min(len(rels) * 1.0, 5.0)
    clamped = _clamp(raw, *COMPONENT_RANGES["related_hypotheses"])
    components.append(
        PriorityComponent(
            "related_hypotheses",
            raw,
            clamped,
            weights["related_hypotheses"],
            clamped * weights["related_hypotheses"],
            f"{len(rels)} related",
        )
    )

    # information_gain_proxy: competing alternatives + weak section targeting
    alternatives = sum(1 for r in rels if r.get("relation_type") == "alternative_to")
    weak_sections = sum(
        1 for s in ctx.report_sections.values() if s.get("confidence", 0) < 0.5
    )
    raw = 3.0 + alternatives * 2.0 + min(weak_sections, 2) * 2.0
    raw = min(raw, 10.0)
    reason = f"{alternatives} alternatives, {weak_sections} weak sections"
    clamped = _clamp(raw, *COMPONENT_RANGES["information_gain_proxy"])
    components.append(
        PriorityComponent(
            "information_gain_proxy",
            raw,
            clamped,
            weights["information_gain_proxy"],
            clamped * weights["information_gain_proxy"],
            reason,
        )
    )

    raw = 4.0 if any(s.get("stale") for s in ctx.report_sections.values()) else 0.0
    clamped = _clamp(raw, *COMPONENT_RANGES["report_changeability"])
    components.append(
        PriorityComponent(
            "report_changeability",
            raw,
            clamped,
            weights["report_changeability"],
            clamped * weights["report_changeability"],
            "default",
        )
    )

    raw = _compute_aging(hyp)
    clamped = _clamp(raw, *COMPONENT_RANGES["aging"])
    components.append(
        PriorityComponent(
            "aging",
            raw,
            clamped,
            weights["aging"],
            clamped * weights["aging"],
            "default",
        )
    )

    # execution_cost: based on confirm_when complexity
    confirm = hyp.get("confirm_when") or {}
    if confirm:
        query_count = len(confirm.get("queries", []))
        has_fallback = confirm.get("fallback") is not None
        if query_count > 2 or has_fallback:
            raw = 6.0
            reason = (
                f"complex confirm_when ({query_count} queries, fallback={has_fallback})"
            )
        elif query_count > 0:
            raw = 3.0
            reason = f"multi-table confirm_when ({query_count} queries)"
        else:
            raw = 1.0
            reason = "simple confirm_when"
    else:
        raw = 1.0
        reason = "no confirm_when (default low cost)"
    clamped = _clamp(raw, *COMPONENT_RANGES["execution_cost"])
    components.append(
        PriorityComponent(
            "execution_cost",
            raw,
            clamped,
            weights["execution_cost"],
            -clamped * weights["execution_cost"],
            reason,
        )
    )

    sel_count = hyp.get("selection_count", 0) or 0
    raw = min(sel_count * 3.0, 24.0)
    clamped = _clamp(raw, *COMPONENT_RANGES["retry_penalty"])
    components.append(
        PriorityComponent(
            "retry_penalty",
            raw,
            clamped,
            weights["retry_penalty"],
            -clamped * weights["retry_penalty"],
            f"selected {sel_count} times",
        )
    )

    # duplicate_penalty: cross-session repeat selection
    raw = min(sel_count * 4.0, 20.0)
    clamped = _clamp(raw, *COMPONENT_RANGES["duplicate_penalty"])
    components.append(
        PriorityComponent(
            "duplicate_penalty",
            raw,
            clamped,
            weights["duplicate_penalty"],
            -clamped * weights["duplicate_penalty"],
            f"selected {sel_count} times (cross-session)",
        )
    )

    # repeated_inconclusive_penalty: consecutive inconclusive verdicts
    if db:
        inconclusive_count = _count_consecutive_inconclusive(db, hyp_id)
        raw = min(inconclusive_count * 3.0, 12.0)
        reason = f"{inconclusive_count} consecutive inconclusive"
    else:
        raw = 0.0
        reason = "no db access"
    clamped = _clamp(raw, *COMPONENT_RANGES["repeated_inconclusive_penalty"])
    components.append(
        PriorityComponent(
            "repeated_inconclusive_penalty",
            raw,
            clamped,
            weights["repeated_inconclusive_penalty"],
            -clamped * weights["repeated_inconclusive_penalty"],
            reason,
        )
    )

    total = sum(c.weighted for c in components)
    return total, components


def check_eligibility(
    hyp: dict[str, Any],
    now: datetime | None = None,
    *,
    ctx: SelectionContext | None = None,
    db: CaseDB | None = None,
) -> tuple[bool, str]:
    """Check if a hypothesis is eligible for selection."""
    now = now or datetime.now(UTC)

    if hyp.get("status") not in ("active",):
        return False, f"status={hyp.get('status')}"

    next_eligible = hyp.get("next_eligible_at")
    if next_eligible:
        if isinstance(next_eligible, str):
            try:
                next_eligible = datetime.fromisoformat(next_eligible)
            except ValueError:
                next_eligible = None
        if next_eligible and now < next_eligible:
            return False, f"blocked until {next_eligible}"

    if hyp.get("blocked_reason"):
        return False, f"blocked: {hyp['blocked_reason']}"

    if (hyp.get("selection_count", 0) or 0) >= 8:
        return False, "retry budget exhausted"

    if (
        db is not None
        and _count_consecutive_inconclusive(db, hyp.get("hypothesis_id", "")) >= 4
    ):
        return False, "repeated inconclusive limit"

    if ctx is not None:
        statuses = ctx.hypothesis_statuses or {}
        for relation in ctx.relations.get(hyp.get("hypothesis_id", ""), []):
            if relation.get("relation_type") == "prerequisite_for" and relation.get(
                "to_hypothesis_id"
            ) == hyp.get("hypothesis_id"):
                prerequisite = str(relation.get("from_hypothesis_id") or "")
                if statuses.get(prerequisite) != "confirmed":
                    return False, f"waiting for prerequisite {prerequisite}"

        if any(
            task.get("hypothesis_id") == hyp.get("hypothesis_id")
            and task.get("kind")
            in {"human_decision", "external_lookup", "evidence_acquisition"}
            for task in (ctx.open_tasks or [])
        ):
            return False, "waiting for external investigation task"

        capabilities = _capabilities_for_hypothesis(hyp)
        if capabilities:
            relevant = [
                cov
                for key, cov in ctx.coverage.items()
                if key.split(":", 1)[-1] in capabilities
            ]
            if relevant and not any(
                cov.get("state") == "available" for cov in relevant
            ):
                return False, "required evidence capability unavailable"

    return True, ""


def select_focus_hypotheses(
    db: CaseDB,
    *,
    limit: int = 2,
    findings_snapshot: dict[str, Any] | None = None,
    session_id: str = "",
    iteration: int = 0,
) -> list[SelectionResult]:
    """Select the next best hypotheses to investigate.

    Returns up to `limit` hypotheses, with 1 slot reserved for
    never-investigated or most-stale eligible hypothesis.
    """
    ctx = gather_selection_context(db)
    now = datetime.now(UTC)

    scored: list[tuple[float, list[PriorityComponent], dict[str, Any], bool, str]] = []

    for hyp in ctx.active_hypotheses:
        eligible, block_reason = check_eligibility(hyp, now, ctx=ctx, db=db)
        if eligible:
            total, components = compute_priority_score(
                hyp, ctx, findings_snapshot, db=db
            )
        else:
            total, components = 0.0, []
        scored.append((total, components, hyp, eligible, block_reason))

    scored.sort(
        key=lambda x: (
            0 if x[3] else 1,
            -x[0],
            -(1 if x[2].get("selection_count", 0) == 0 else 0),
            x[2].get("last_selected_at") or datetime.min,
            x[2].get("created_at") or datetime.min,
            x[2].get("hypothesis_id", ""),
        )
    )

    eligible_rows = [row for row in scored if row[3]]
    chosen = eligible_rows[:1]
    chosen_ids = {row[2]["hypothesis_id"] for row in chosen}
    if limit > 1:
        fairness = next(
            (
                row
                for row in eligible_rows
                if row[2]["hypothesis_id"] not in chosen_ids
                and row[2].get("selection_count", 0) == 0
            ),
            None,
        )
        if fairness is not None:
            chosen.append(fairness)
            chosen_ids.add(fairness[2]["hypothesis_id"])
    for row in eligible_rows:
        if len(chosen) >= limit:
            break
        if row[2]["hypothesis_id"] not in chosen_ids:
            chosen.append(row)
            chosen_ids.add(row[2]["hypothesis_id"])

    results = [
        SelectionResult(
            hypothesis_id=hyp["hypothesis_id"],
            total_score=total,
            components=components,
            eligible=True,
        )
        for total, components, hyp, _, _ in chosen
    ]
    results.extend(
        SelectionResult(
            hypothesis_id=hyp["hypothesis_id"],
            total_score=total,
            components=components,
            eligible=False,
            block_reason=block_reason,
        )
        for total, components, hyp, eligible, block_reason in scored
        if not eligible
    )

    selected_ids = {r.hypothesis_id for r in results if r.eligible}
    for rid in selected_ids:
        db.execute(
            "UPDATE hypotheses SET selection_count = COALESCE(selection_count, 0) + 1, "
            "last_selected_at = now() WHERE hypothesis_id = ?",
            [rid],
        )

    if results:
        step_payload = {
            "phase": "select",
            "candidates": [
                {
                    "hypothesis_id": r.hypothesis_id,
                    "score": r.total_score,
                    "eligible": r.eligible,
                    "block_reason": r.block_reason,
                    "components": [
                        {
                            "name": c.name,
                            "raw": c.raw_value,
                            "clamped": c.clamped,
                            "weighted": c.weighted,
                            "reason": c.reason,
                        }
                        for c in r.components
                    ],
                }
                for r in results
            ],
            "selected": [r.hypothesis_id for r in results if r.eligible],
        }
        db.execute(
            "INSERT INTO trace.investigation_steps (step_id, session_id, hypothesis_id, "
            "iteration, phase, input_json, output_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, now())",
            [
                str(uuid.uuid4()),
                session_id,
                "",
                iteration,
                "select",
                json.dumps({}),
                json.dumps(step_payload),
            ],
        )

    return results
