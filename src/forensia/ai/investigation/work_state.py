"""Authoritative Gap, Task, hypothesis, and termination state transitions."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.knowledge.coverage import infer_capabilities

_OBJECTIVE_GAP_TEXT = "Investigation objective not configured"
_TERMINAL_CLASSIFICATIONS = {"deferred", "blocked", "needs_review", "untestable"}


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    return f"{prefix}-{digest}"


def ensure_objective_gap(db: CaseDB, objective: str) -> str:
    """Open the configuration gap only while the case objective is empty."""
    gap_id = _stable_id("GAP", _OBJECTIVE_GAP_TEXT)
    if objective.strip():
        db.execute(
            "UPDATE report_gaps SET status = 'resolved', updated_at = now() "
            "WHERE gap_id = ? AND origin = 'configuration'",
            [gap_id],
        )
        return gap_id
    db.execute(
        """
        INSERT INTO report_gaps (
            gap_id, description, kind, status, origin, created_at, updated_at
        ) VALUES (?, ?, 'configuration', 'open', 'configuration', now(), now())
        ON CONFLICT (gap_id) DO UPDATE SET
            status = 'open', origin = 'configuration', updated_at = now()
        """,
        [gap_id, _OBJECTIVE_GAP_TEXT],
    )
    return gap_id


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _required_capabilities(
    db: CaseDB, hypothesis_id: str, description: str
) -> list[str]:
    row = db.execute(
        "SELECT confirm_when, evidence_requirements FROM hypotheses "
        "WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchone()
    parts = [description]
    if row:
        parts.extend(
            json.dumps(_json_object(value), sort_keys=True) for value in row if value
        )
    return sorted(set(infer_capabilities(" ".join(parts))))


def _coverage_state(db: CaseDB, capabilities: list[str]) -> tuple[list[str], list[str]]:
    """Return unavailable capabilities and their source families."""
    if not capabilities:
        return [], []
    placeholders = ", ".join("?" for _ in capabilities)
    rows = db.execute(
        f"SELECT capability, state, source_family FROM evidence_coverage "
        f"WHERE capability IN ({placeholders})",
        capabilities,
    ).fetchall()
    states: dict[str, list[str]] = {capability: [] for capability in capabilities}
    families: dict[str, set[str]] = {capability: set() for capability in capabilities}
    for capability, state, family in rows:
        key = str(capability)
        states.setdefault(key, []).append(str(state or "unavailable"))
        if family:
            families.setdefault(key, set()).add(str(family))
    unavailable = [
        capability
        for capability in capabilities
        if not states.get(capability)
        or all(state in {"unavailable", "degraded"} for state in states[capability])
    ]
    required_sources = sorted(
        {
            family
            for capability in capabilities
            for family in families.get(capability, set())
        }
    )
    return unavailable, required_sources


def _classification_for(
    *,
    reasoning_count: int,
    evidence_count: int,
    sufficiency_status: str,
    blocked_reason: str,
    required_capabilities: list[str],
    unavailable_capabilities: list[str],
) -> str:
    if sufficiency_status == "unobservable" or (
        required_capabilities
        and len(unavailable_capabilities) == len(required_capabilities)
    ):
        return "untestable"
    if blocked_reason or unavailable_capabilities:
        return "blocked"
    if reasoning_count == 0:
        return "deferred"
    if evidence_count == 0 or sufficiency_status in {
        "insufficient",
        "partial",
        "needs_review",
        "unknown",
        "",
    }:
        return "needs_review"
    return "needs_review"


def _upsert_terminal_work(
    db: CaseDB,
    *,
    hypothesis_id: str,
    description: str,
    classification: str,
    reason: str,
) -> None:
    """Create or refresh the authoritative Task/Gap pair for a terminal hypothesis."""
    required_capabilities = _required_capabilities(db, hypothesis_id, description)
    unavailable_capabilities, required_sources = _coverage_state(
        db, required_capabilities
    )
    if unavailable_capabilities and not any(
        capability in reason for capability in unavailable_capabilities
    ):
        reason += ": " + ", ".join(unavailable_capabilities)

    task_id = _stable_id("TASK-STOP", hypothesis_id)
    gap_id = _stable_id("GAP-STOP", hypothesis_id)
    retry_condition = (
        "required_capability_available"
        if classification in {"blocked", "untestable"}
        else "new_evidence_or_human_review"
        if classification == "needs_review"
        else "new_evidence_or_manual_resume"
    )
    db.execute(
        """
        INSERT INTO investigation_tasks (
            task_id, kind, description, status, gap_id, hypothesis_id,
            required_capability, required_source, owner_phase,
            retry_condition, blocked_reason, reason, created_at, updated_at
        ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, 'termination', ?, ?, ?, now(), now())
        ON CONFLICT (task_id) DO UPDATE SET
            kind = EXCLUDED.kind, description = EXCLUDED.description,
            status = 'open', gap_id = EXCLUDED.gap_id,
            required_capability = EXCLUDED.required_capability,
            required_source = EXCLUDED.required_source,
            owner_phase = EXCLUDED.owner_phase,
            retry_condition = EXCLUDED.retry_condition,
            blocked_reason = EXCLUDED.blocked_reason,
            reason = EXCLUDED.reason, updated_at = now()
        """,
        [
            task_id,
            classification,
            description[:200],
            gap_id,
            hypothesis_id,
            ",".join(required_capabilities),
            ",".join(required_sources),
            retry_condition,
            reason,
            reason,
        ],
    )
    db.execute(
        """
        INSERT INTO report_gaps (
            gap_id, description, kind, status, hypothesis_id, task_id,
            coverage_reason, origin, created_at, updated_at
        ) VALUES (?, ?, ?, 'open', ?, ?, ?, 'termination', now(), now())
        ON CONFLICT (gap_id) DO UPDATE SET
            description = EXCLUDED.description, kind = EXCLUDED.kind,
            status = 'open', hypothesis_id = EXCLUDED.hypothesis_id,
            task_id = EXCLUDED.task_id,
            coverage_reason = EXCLUDED.coverage_reason,
            origin = 'termination', updated_at = now()
        """,
        [
            gap_id,
            description[:200],
            classification,
            hypothesis_id,
            task_id,
            reason,
        ],
    )


def classify_active_hypotheses_on_stop(
    db: CaseDB,
    active_hypotheses: list[Hypothesis],
    stop_reason_code: str,
) -> dict[str, int]:
    """Atomically classify every active hypothesis and create linked work."""
    counts = {classification: 0 for classification in sorted(_TERMINAL_CLASSIFICATIONS)}
    with db.transaction():
        for hypothesis in active_hypotheses:
            hypothesis_id = hypothesis.id
            row = db.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM hypothesis_reasoning WHERE hypothesis_id = ?),
                    (SELECT COUNT(*) FROM hypothesis_evidence WHERE hypothesis_id = ?),
                    sufficiency_status, blocked_reason
                FROM hypotheses WHERE hypothesis_id = ?
                """,
                [hypothesis_id, hypothesis_id, hypothesis_id],
            ).fetchone()
            reasoning_count = int(row[0] or 0) if row else 0
            evidence_count = int(row[1] or 0) if row else 0
            sufficiency_status = str(row[2] or "") if row else ""
            prior_blocked_reason = str(row[3] or "") if row else ""
            required_capabilities = _required_capabilities(
                db, hypothesis_id, hypothesis.description
            )
            unavailable_capabilities, required_sources = _coverage_state(
                db, required_capabilities
            )
            classification = _classification_for(
                reasoning_count=reasoning_count,
                evidence_count=evidence_count,
                sufficiency_status=sufficiency_status,
                blocked_reason=prior_blocked_reason,
                required_capabilities=required_capabilities,
                unavailable_capabilities=unavailable_capabilities,
            )
            counts[classification] += 1
            reason = {
                "deferred": f"Not investigated before {stop_reason_code}",
                "blocked": f"Blocked before {stop_reason_code}",
                "needs_review": f"Human review or more evidence required after {stop_reason_code}",
                "untestable": f"Required telemetry unavailable at {stop_reason_code}",
            }[classification]
            if unavailable_capabilities:
                reason += ": " + ", ".join(unavailable_capabilities)

            hypothesis.status = classification
            db.execute(
                "UPDATE hypotheses SET status = ?, blocked_reason = ?, "
                "updated_at = now() WHERE hypothesis_id = ? AND status IN ('active', 'needs_review')",
                [classification, reason, hypothesis_id],
            )

            _upsert_terminal_work(
                db,
                hypothesis_id=hypothesis_id,
                description=hypothesis.description,
                classification=classification,
                reason=reason,
            )

        # A hypothesis may become terminal before the stop transition (for
        # example, repeated missing telemetry can mark it untestable). Such a
        # hypothesis is absent from ``active_hypotheses`` but still needs the
        # same authoritative Task/Gap pair.
        missing_terminal_work = db.execute(
            """
            SELECT h.hypothesis_id, h.description, h.status, h.blocked_reason
            FROM hypotheses h
            LEFT JOIN investigation_tasks t
              ON t.hypothesis_id = h.hypothesis_id
             AND t.status IN ('open', 'in_progress')
            WHERE h.status IN ('deferred', 'blocked', 'needs_review', 'untestable')
              AND t.task_id IS NULL
            """
        ).fetchall()
        for (
            hypothesis_id,
            description,
            classification,
            blocked_reason,
        ) in missing_terminal_work:
            reason = (
                str(blocked_reason or "").strip()
                or {
                    "deferred": f"Not investigated before {stop_reason_code}",
                    "blocked": f"Blocked before {stop_reason_code}",
                    "needs_review": (
                        f"Human review or more evidence required after {stop_reason_code}"
                    ),
                    "untestable": f"Required telemetry unavailable at {stop_reason_code}",
                }[str(classification)]
            )
            _upsert_terminal_work(
                db,
                hypothesis_id=str(hypothesis_id),
                description=str(description or hypothesis_id),
                classification=str(classification),
                reason=reason,
            )
    return counts


def reopen_retryable_work(db: CaseDB) -> list[str]:
    """Reactivate only hypotheses whose persisted retry condition became true."""
    coverage = db.execute("SELECT capability, state FROM evidence_coverage").fetchall()
    available_capabilities = {
        str(capability)
        for capability, state in coverage
        if state in {"available", "partial"}
    }
    reopened: list[str] = []
    rows = db.execute(
        """
        SELECT task_id, gap_id, hypothesis_id, kind, required_capability,
               required_source, created_at
        FROM investigation_tasks
        WHERE status = 'open' AND kind IN ('deferred', 'blocked', 'needs_review', 'untestable')
          AND hypothesis_id IS NOT NULL
        """
    ).fetchall()
    with db.transaction():
        for (
            task_id,
            gap_id,
            hypothesis_id,
            kind,
            raw_caps,
            raw_sources,
            created_at,
        ) in rows:
            capabilities = {item for item in str(raw_caps or "").split(",") if item}
            sources = {item for item in str(raw_sources or "").split(",") if item}
            capability_ready = (
                bool(capabilities) and capabilities <= available_capabilities
            )
            source_query = (
                "SELECT 1 FROM evidence_sources WHERE updated_at > ? "
                "AND ingest_status IN ('normalized', 'parsed')"
            )
            params: list[Any] = [created_at]
            if sources:
                placeholders = ", ".join("?" for _ in sources)
                source_query += f" AND artifact_family IN ({placeholders})"
                params.extend(sorted(sources))
            new_evidence = db.execute(source_query + " LIMIT 1", params).fetchone()
            should_reopen = (
                capability_ready
                if kind in {"blocked", "untestable"}
                else bool(new_evidence)
            )
            if not should_reopen:
                continue
            db.execute(
                "UPDATE hypotheses SET status = 'active', verdict = NULL, "
                "resolved_session = NULL, blocked_reason = NULL, updated_at = now() "
                "WHERE hypothesis_id = ? AND status IN ('deferred', 'blocked', 'needs_review', 'untestable')",
                [hypothesis_id],
            )
            db.execute(
                "UPDATE investigation_tasks SET status = 'in_progress', "
                "blocked_reason = NULL, updated_at = now() WHERE task_id = ?",
                [task_id],
            )
            db.execute(
                "UPDATE report_gaps SET status = 'in_progress', updated_at = now() "
                "WHERE gap_id = ?",
                [gap_id],
            )
            reopened.append(str(hypothesis_id))
    return reopened


def resolve_linked_work(db: CaseDB, hypothesis_id: str) -> None:
    """Close the Task and Gap satisfied by a conclusive hypothesis verdict."""
    db.execute(
        "UPDATE investigation_tasks SET status = 'resolved', blocked_reason = NULL, "
        "updated_at = now() WHERE hypothesis_id = ? "
        "AND status IN ('open', 'in_progress')",
        [hypothesis_id],
    )
    db.execute(
        "UPDATE report_gaps SET status = 'resolved', updated_at = now() "
        "WHERE hypothesis_id = ? AND status IN ('open', 'in_progress')",
        [hypothesis_id],
    )


def stop_summary(db: CaseDB, active_count: int = 0) -> dict[str, int]:
    """Return machine-readable terminal hypothesis counts."""
    rows = db.execute(
        "SELECT status, COUNT(*) FROM hypotheses GROUP BY status"
    ).fetchall()
    counts = {str(status): int(count) for status, count in rows}
    return {
        "active": int(counts.get("active", active_count)),
        "resolved": int(counts.get("confirmed", 0) + counts.get("refuted", 0)),
        "deferred": int(counts.get("deferred", 0)),
        "blocked": int(counts.get("blocked", 0)),
        "needs_review": int(counts.get("needs_review", 0)),
        "untestable": int(counts.get("untestable", 0)),
    }


def format_stop_reason(status: str, code: str, summary: dict[str, int]) -> str:
    details = ", ".join(f"{key}={value}" for key, value in summary.items())
    return f"Investigation {status}: {code or 'unspecified'} ({details})"
