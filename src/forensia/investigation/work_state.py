"""Authoritative Gap, Task, hypothesis, and termination state transitions.

Write owner of the stop → terminal-classification → Gap/Task transition and of
reopen.  All readiness inputs (required capabilities, Coverage readiness,
derived retry condition, blocker owners) are read from the shared judgment in
``work_judgment.py``; this module owns the writes that persist them.
"""

from __future__ import annotations

import hashlib
from typing import Any

from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.investigation.work_judgment import (
    OBSERVATION_INFEASIBLE_CODES,
    coverage_readiness,
    judge_work,
)

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


# Default reopen condition per stop classification; the shared judgment
# overrides it whenever the current Case State derives a more specific one.
_CLASSIFICATION_RETRY_CONDITIONS = {
    "untestable": "required_capability_available",
    "blocked": "required_capability_available",
    "needs_review": "new_evidence_or_human_review",
    "deferred": "new_evidence_or_manual_resume",
}


def _classification_for(
    *,
    reasoning_count: int,
    evidence_count: int,
    sufficiency_status: str,
    blocked_reason: str,
    required_capabilities: list[str],
    unavailable_capabilities: list[str],
    external_task_ids: tuple[str, ...],
    observation_infeasible: bool = False,
) -> str:
    if observation_infeasible:
        return "blocked"
    if sufficiency_status == "unobservable" or (
        required_capabilities
        and len(unavailable_capabilities) == len(required_capabilities)
    ):
        return "untestable"
    if blocked_reason or unavailable_capabilities or external_task_ids:
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
    """Create or refresh the authoritative Task/Gap pair for a terminal hypothesis.

    Blockers, owners and the persisted retry condition all come from the one
    judgment; the per-classification default only fills what the Case State
    cannot derive (e.g. manual resume after deferral).
    """
    judgment = judge_work(db, [hypothesis_id])[hypothesis_id]
    required_capabilities = list(judgment.capabilities)
    unavailable_capabilities = list(judgment.unavailable_capabilities)
    if unavailable_capabilities and not any(
        capability in reason for capability in unavailable_capabilities
    ):
        reason += ": " + ", ".join(unavailable_capabilities)
    _, required_sources = coverage_readiness(db, required_capabilities)

    task_id = _stable_id("TASK-STOP", hypothesis_id)
    gap_id = _stable_id("GAP-STOP", hypothesis_id)
    retry_condition = (
        judgment.retry_condition or _CLASSIFICATION_RETRY_CONDITIONS[classification]
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
                    (SELECT COUNT(*) FROM trace.hypothesis_reasoning WHERE hypothesis_id = ?),
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
            judgment = judge_work(db, [hypothesis_id])[hypothesis_id]
            classification = _classification_for(
                reasoning_count=reasoning_count,
                evidence_count=evidence_count,
                sufficiency_status=sufficiency_status,
                blocked_reason=prior_blocked_reason,
                required_capabilities=list(judgment.capabilities),
                unavailable_capabilities=list(judgment.unavailable_capabilities),
                external_task_ids=judgment.external_task_ids,
                observation_infeasible=any(
                    blocker.code in OBSERVATION_INFEASIBLE_CODES
                    for blocker in judgment.blockers
                ),
            )
            counts[classification] += 1
            observation_blockers = [
                blocker.owner
                for blocker in judgment.blockers
                if blocker.code in OBSERVATION_INFEASIBLE_CODES
            ]
            reason = {
                "deferred": f"Not investigated before {stop_reason_code}",
                "blocked": f"Blocked before {stop_reason_code}",
                "needs_review": f"Human review or more evidence required after {stop_reason_code}",
                "untestable": f"Required telemetry unavailable at {stop_reason_code}",
            }[classification]
            if observation_blockers:
                reason = "typed-observation-infeasible: " + "; ".join(
                    observation_blockers
                )
            if judgment.unavailable_capabilities or judgment.external_task_ids:
                owners = list(judgment.unavailable_capabilities)
                if judgment.external_task_ids:
                    owners.append("open external task " + judgment.external_task_ids[0])
                reason += ": " + ", ".join(owners)

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

        # Report-admitted external/human work may have no hypothesis; the stop
        # still persists its blocker (owner already on the Task) so the stop
        # record never looks completed while runnable work is zero.
        db.execute(
            """
            UPDATE investigation_tasks SET reason =
                CASE kind
                    WHEN 'human_decision' THEN
                        'human decision required; no runnable work at stop'
                    ELSE 'external result required; no runnable work at stop'
                END,
                updated_at = now()
            WHERE status IN ('open', 'in_progress')
              AND kind IN ('human_decision', 'external_lookup', 'evidence_acquisition')
              AND (reason IS NULL OR reason = '')
            """
        )
    return counts


def reopen_retryable_work(db: CaseDB, *, manual_resume: bool = False) -> list[str]:
    """Reactivate only work whose persisted retry condition became true.

    The saved ``retry_condition`` is the reopen contract and is checked, not
    re-derived from ``kind`` (V2-03): ``required_capability_available`` is
    evaluated over the Task's persisted ``required_capability`` — which the
    same judgment wrote at stop — with the shared ready rule: every required
    capability must have an ``available``/``partial`` Coverage row.  The
    ``new_evidence_*`` conditions need a normalized source newer than the
    Task's last stop update, so the same source cannot reopen it twice.
    ``new_evidence_or_manual_resume`` also accepts an explicit manual resume.
    Unrecognized or ``human_or_external_result``
    conditions never auto-reopen; their Task is resolved by its own owner.
    """
    reopened: list[str] = []
    rows = db.execute(
        """
        SELECT task_id, gap_id, hypothesis_id, retry_condition,
               required_capability, required_source, updated_at
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
            retry_condition,
            raw_caps,
            raw_sources,
            updated_at,
        ) in rows:
            hypothesis_id = str(hypothesis_id)
            condition = str(retry_condition or "").strip()
            if condition == "required_capability_available":
                capabilities = [item for item in str(raw_caps or "").split(",") if item]
                not_ready, _ = coverage_readiness(db, capabilities)
                should_reopen = bool(capabilities) and not not_ready
            elif condition in {
                "new_evidence_or_coverage",
                "new_evidence_or_human_review",
                "new_evidence_or_manual_resume",
            }:
                sources = {item for item in str(raw_sources or "").split(",") if item}
                source_query = (
                    "SELECT 1 FROM evidence_sources WHERE updated_at > ? "
                    "AND ingest_status IN ('normalized', 'parsed')"
                )
                params: list[Any] = [updated_at]
                if sources:
                    placeholders = ", ".join("?" for _ in sources)
                    source_query += f" AND artifact_family IN ({placeholders})"
                    params.extend(sorted(sources))
                should_reopen = (
                    manual_resume and condition == "new_evidence_or_manual_resume"
                )
                should_reopen = should_reopen or (
                    db.execute(source_query + " LIMIT 1", params).fetchone() is not None
                )
            else:
                should_reopen = False
            if should_reopen:
                judgment = judge_work(db, [hypothesis_id]).get(hypothesis_id)
                if judgment is not None:
                    should_reopen = not any(
                        blocker.code in OBSERVATION_INFEASIBLE_CODES
                        for blocker in judgment.blockers
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


def stop_summary(db: CaseDB) -> dict[str, int]:
    """Return machine-readable terminal hypothesis counts."""
    rows = db.execute(
        "SELECT status, COUNT(*) FROM hypotheses GROUP BY status"
    ).fetchall()
    counts = {str(status): int(count) for status, count in rows}
    return {
        "active": int(counts.get("active", 0)),
        "resolved": int(counts.get("confirmed", 0) + counts.get("refuted", 0)),
        "deferred": int(counts.get("deferred", 0)),
        "blocked": int(counts.get("blocked", 0)),
        "needs_review": int(counts.get("needs_review", 0)),
        "untestable": int(counts.get("untestable", 0)),
    }


def format_stop_reason(status: str, code: str, summary: dict[str, int]) -> str:
    details = ", ".join(f"{key}={value}" for key, value in summary.items())
    return f"Investigation {status}: {code or 'unspecified'} ({details})"


# Structured terminal reasons for an investigation session (T-12). These are
# written to ``investigation_sessions.terminal_reason`` so a session always
# carries a human-readable cause even when the harness did not emit one.
_SESSION_TERMINAL_REASONS = {
    "completed": "completed: investigation loop finished normally",
    "stopped": "stopped: user/operator halted the investigation",
    "failed": "failed: investigation terminated on an unhandled exception",
    "cancelled": "cancelled: investigation cancelled before completion",
    "abandoned": "abandoned: process terminated without a terminal receipt",
}


def format_terminal_reason(status: str, *, cause: str = "") -> str:
    """Return a structured, human-readable terminal reason for a session."""
    base = _SESSION_TERMINAL_REASONS.get(status, f"unknown: terminal status '{status}'")
    cause = (cause or "").strip()
    return f"{base} ({cause})" if cause else base
