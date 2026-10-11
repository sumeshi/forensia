"""Invariants of the durable semantic trace event feed."""

from __future__ import annotations

import tempfile

import pytest

from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import list_progress_events, record_progress_event
from forensia.db.views import case_events, case_snapshot


def test_progress_events_append_page_and_preserve_structured_fields() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            first = record_progress_event(
                db,
                progress_event(
                    "finding.created",
                    "completed",
                    session_id="session-a",
                    severity="success",
                    reason="rule_match",
                    refs={"finding_ids": ["F-1"], "evidence_ids": ["E-1"]},
                    summary="Finding created",
                    rule_id="R-1",
                ),
            )
            second = record_progress_event(
                db,
                progress_event(
                    "investigation.stopped",
                    "stopped",
                    session_id="session-b",
                    reason="operator_stop",
                    summary="Stopped at a safe boundary",
                ),
            )
            assert second == first + 1

            page = list_progress_events(db, after_index=first - 1, limit=1)
            assert len(page) == 1
            assert page[0]["event_index"] == first
            assert page[0]["session_id"] == "session-a"
            assert page[0]["kind"] == "finding.created"
            assert page[0]["severity"] == "success"
            assert page[0]["status"] == "completed"
            assert page[0]["reason"] == "rule_match"
            assert page[0]["refs"] == {
                "finding_ids": ["F-1"],
                "evidence_ids": ["E-1"],
            }
            assert page[0]["payload"] == {"rule_id": "R-1"}
            assert page[0]["created_at"]
            assert (
                list_progress_events(db, after_index=first, limit=10)[0]["event_index"]
                == second
            )


def test_progress_events_are_not_pruned_after_one_thousand_rows() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            db.execute(
                """
                INSERT INTO trace.progress_events (
                    event_index, kind, status, severity, refs, payload, summary
                ) SELECT i, 'pipeline.stage', 'completed', 'info', '{}', '{}',
                         'stage ' || CAST(i AS VARCHAR)
                  FROM range(1, 1002) AS r(i)
                """
            )
            record_progress_event(
                db,
                progress_event(
                    "pipeline.stage.completed",
                    "completed",
                    session_id="session-b",
                    summary="after the seeded history",
                ),
            )
            count = db.execute("SELECT COUNT(*) FROM trace.progress_events").fetchone()[
                0
            ]
            assert count == 1002
            first = list_progress_events(db, limit=1)[0]
            assert first["event_index"] == 1
            assert first["summary"] == "stage 1"


def test_storage_rejects_unknown_event_vocabulary() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            with pytest.raises(ValueError, match="status"):
                record_progress_event(
                    db,
                    {
                        "kind": "investigation.error",
                        "status": "error",
                        "severity": "error",
                    },  # type: ignore[arg-type]
                )


def test_case_snapshot_is_a_bounded_projection_at_event_highwater() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            record_progress_event(
                db,
                progress_event(
                    "finding.created", "completed", summary="Finding created"
                ),
            )
            db.execute(
                "INSERT INTO findings (finding_id, title, status) VALUES ('F-1', 'Finding', 'accepted')"
            )
            db.execute(
                "INSERT INTO hypotheses (hypothesis_id, description, status) VALUES ('H-1', 'Hypothesis', 'open')"
            )
            db.execute(
                "INSERT INTO investigation_tasks (task_id, description, status) VALUES ('T-1', 'Investigate', 'open')"
            )
            db.execute(
                "INSERT INTO investigation_tasks (task_id, description, status) VALUES ('T-2', 'Resolved', 'resolved')"
            )
            db.execute(
                "INSERT INTO trace.investigation_sessions (session_id, started_at, status, terminal_reason) VALUES ('S-1', now(), 'running', NULL)"
            )
            db.execute(
                "INSERT INTO trace.investigation_steps (step_id, session_id, hypothesis_id, phase, created_at) VALUES ('step-1', 'S-1', 'H-1', 'search', now())"
            )

            snapshot = case_snapshot(case, db)

            assert snapshot["case_name"] == case.path.name
            assert snapshot["counts"] == {
                "findings": 1,
                "hypotheses": 1,
                "hypothesis_statuses": {"open": 1},
                "open_tasks": 1,
            }
            assert snapshot["session"]["status"] == "running"
            assert snapshot["current_work"] == {
                "phase": "search",
                "hypothesis_id": "H-1",
                "iteration": None,
            }
            assert snapshot["budget_usage"] is None
            assert snapshot["event_highwater"] == 1
            assert snapshot["generated_at"]
            assert snapshot["authoritative"] is False
            assert case_events(db, after_index=0, limit=1)[0]["event_index"] == 1


def test_case_snapshot_reports_ingest_work_elapsed_and_remaining_llm_budget() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO hypotheses (hypothesis_id, status) VALUES ('H-1', 'active'), ('H-2', 'confirmed')"
            )
            db.execute(
                "INSERT INTO trace.investigation_sessions (session_id, started_at, status) VALUES ('S-1', now() - INTERVAL 5 SECOND, 'running')"
            )
            db.execute(
                "INSERT INTO trace.investigation_sessions (session_id, started_at, status, phase) VALUES ('I-1', now() + INTERVAL 1 DAY, 'completed', 'human_intervention')"
            )
            db.execute(
                "INSERT INTO trace.investigation_steps (step_id, session_id, phase, output_json, created_at) VALUES ('settings-1', 'S-1', 'session-settings', '{\"max_llm_calls\": 10}', now()), ('stale-step', 'S-1', 'plan', '{}', now())"
            )
            db.execute(
                "INSERT INTO trace.llm_logical_calls (logical_call_id, session_id) VALUES ('L-1', 'S-1'), ('L-2', 'S-1')"
            )
            db.execute(
                "INSERT INTO trace.llm_provider_attempts "
                "(attempt_id, session_id, input_tokens, input_tokens_source) VALUES "
                "('actual', 'S-1', 12, 'provider_actual'), "
                "('estimate', 'S-1', 7, 'local_estimate'), "
                "('unknown', 'S-1', NULL, 'unknown')"
            )
            record_progress_event(
                db,
                progress_event(
                    "pipeline.ingest",
                    "running",
                    stage="ingest",
                    summary="Scanning input files",
                ),
            )
            snapshot = case_snapshot(case, db)
        assert snapshot["counts"]["hypothesis_statuses"] == {
            "active": 1,
            "confirmed": 1,
        }
        assert snapshot["session"]["session_id"] == "S-1"
        assert snapshot["current_work"]["summary"] == "Scanning input files"
        assert snapshot["elapsed_seconds"] is not None
        assert snapshot["budget_remaining_llm_calls"] == 8
        assert snapshot["budget_usage"]["actual_input_tokens"] == 12
        assert snapshot["budget_usage"]["estimated_input_tokens"] == 7
        assert snapshot["budget_usage"]["unknown_input_usage_attempts"] == 1
