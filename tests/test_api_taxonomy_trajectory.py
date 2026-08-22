"""Focused tests for T-12 / T-50 / T-51 backend: canonical taxonomy, the
9/1/1 contradiction fix, stale-session reconciliation, finding aggregates +
pagination, and the session trajectory (logical calls / attempts) endpoints.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from forensia.ai.llm_telemetry import LLMTelemetry
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.web.app import create_app


def _insert_hypotheses(db: CaseDB, specs: list[tuple[str, str]]) -> None:
    """specs: list of (hypothesis_id, status)."""
    now = datetime.now(UTC).replace(tzinfo=None)
    for hid, status in specs:
        db.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, description, status, verdict, summary, origin,
                created_session, resolved_session, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hid,
                f"Hypothesis {hid}",
                status,
                None,
                "",
                "broad_plan",
                "S-1",
                None,
                now,
                now,
            ),
        )


class TestContradictionReconciliation(unittest.TestCase):
    """DB 8 needs_review + 1 untestable must reconcile to the same revision
    across /api/hypotheses, /api/stats, and the snapshot metadata (T-50.3)."""

    def test_mixed_status_reconciles_exactly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                for i in range(8):
                    _insert_hypotheses(db, [(f"H-{i}", "needs_review")])
                _insert_hypotheses(db, [("H-U", "untestable")])
                db.execute(
                    """
                    INSERT INTO investigation_sessions (
                        session_id, started_at, finished_at, iterations, status, terminal_reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "S-1",
                        now,
                        now,
                        1,
                        "completed",
                        "completed: investigation loop finished normally",
                    ),
                )

            client = TestClient(create_app(case))

            hypotheses = client.get("/api/hypotheses").json()
            self.assertEqual(len(hypotheses["active"]), 0)
            self.assertEqual(len(hypotheses["resolved"]), 9)

            stats = client.get("/api/stats").json()
            self.assertEqual(stats["active_hypotheses"], 0)
            self.assertEqual(stats["resolved_hypotheses"], 9)
            self.assertEqual(stats["needs_review_hypotheses"], 8)
            self.assertEqual(stats["untestable_hypotheses"], 1)
            self.assertEqual(stats["confirmed_hypotheses"], 0)
            self.assertEqual(stats["refuted_hypotheses"], 0)

            # All three views derive from the same state revision.
            meta = client.get("/api/snapshot-metadata").json()
            self.assertEqual(meta["state_revision"], meta["generation_revision"])
            self.assertEqual(meta["timezone"], "UTC")
            self.assertIn("+00:00", meta["authoritative_updated_at"])

            # The taxonomy endpoint documents the same partition.
            tax = client.get("/api/hypotheses/taxonomy").json()
            self.assertIn("needs_review", tax["hypothesis"]["values"])
            self.assertIn("blocked", tax["hypothesis"]["values"])
            self.assertIn("untestable", tax["hypothesis"]["groups"]["resolved"])


class TestStaleSessionReconciliation(unittest.TestCase):
    def test_session_list_is_read_only_for_running_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            started = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO investigation_sessions (
                        session_id, started_at, finished_at, iterations, status
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    ("S-STALE", started, None, 3, "running"),
                )
                # A later step proves wall time should not collapse to started_at.
                later = started + timedelta(minutes=42)
                db.execute(
                    """
                    INSERT INTO investigation_steps (
                        step_id, session_id, iteration, phase, input_json, output_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("S-STALE-01-plan", "S-STALE", 1, "plan", "{}", "{}", later),
                )

            client = TestClient(create_app(case))
            sessions = {s["session_id"]: s for s in client.get("/api/sessions").json()}
            self.assertIn("S-STALE", sessions)
            stale = sessions["S-STALE"]
            self.assertEqual(stale["status"], "running")
            self.assertIsNone(stale["finished_at"])
            with CaseDB(case) as db:
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM investigation_sessions WHERE session_id = ?",
                        ("S-STALE",),
                    ).fetchone()[0],
                    "running",
                )


class TestFindingAggregatesAndPagination(unittest.TestCase):
    def _insert_findings(self, db: CaseDB, specs: list[tuple[str, str, str, str]]) -> None:
        """specs: (finding_id, rule_id, severity, status)."""
        now = datetime.now(UTC).replace(tzinfo=None)
        for fid, rule, severity, status in specs:
            db.execute(
                """
                INSERT INTO findings (
                    finding_id, rule_id, title, summary, severity, confidence, status,
                    tags, attack, evidence, ai_summary, missing_checks, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fid,
                    rule,
                    f"Finding {fid}",
                    "summary",
                    severity,
                    0.9,
                    status,
                    "[]",
                    "[]",
                    "[]",
                    "",
                    "[]",
                    now,
                ),
            )

    def test_aggregates_cover_whole_table_not_a_sample(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert_findings(
                    db,
                    [
                        ("F-1", "rule-a", "high", "accepted"),
                        ("F-2", "rule-a", "high", "accepted"),
                        ("F-3", "rule-b", "medium", "accepted"),
                        ("F-4", "rule-c", "low", "suppressed"),
                    ],
                )

            client = TestClient(create_app(case))
            agg = client.get("/api/findings/aggregates").json()
            self.assertEqual(agg["total"], 4)
            self.assertEqual(agg["accepted"], 3)
            self.assertEqual(agg["suppressed"], 1)
            self.assertEqual(agg["severity_counts"].get("high"), 2)
            self.assertEqual(agg["severity_counts"].get("medium"), 1)
            self.assertNotIn("low", agg["severity_counts"])
            self.assertEqual(len(agg["top_rules"]), 2)
            self.assertEqual(agg["top_rules"][0]["rule_id"], "rule-a")

    def test_page_metadata_is_sample_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for i in range(15):
                    self._insert_findings(db, [(f"F-{i}", "rule-a", "high", "accepted")])

            client = TestClient(create_app(case))
            page = client.get("/api/findings/page?limit=10&offset=0").json()
            self.assertEqual(page["total"], 15)
            self.assertEqual(len(page["items"]), 10)
            self.assertTrue(page["is_sample"])
            self.assertIn("aggregates", page)

            page2 = client.get("/api/findings/page?limit=10&offset=10").json()
            self.assertEqual(len(page2["items"]), 5)
            self.assertFalse(page2["is_sample"])

            filtered = client.get("/api/findings/page?status=accepted&limit=10").json()
            self.assertEqual(filtered["total"], 15)


class TestSessionTrajectory(unittest.TestCase):
    def test_trajectory_aggregates_and_paged_logical_calls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            started = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO investigation_sessions (
                        session_id, started_at, finished_at, iterations, status, terminal_reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "S-TRAJ",
                        started,
                        started + timedelta(minutes=10),
                        2,
                        "completed",
                        "completed: investigation loop finished normally",
                    ),
                )
                telemetry = LLMTelemetry(db, "S-TRAJ")
                lc1 = telemetry.begin_logical_call(phase="plan", iteration=1, hypothesis_id="H-1")
                telemetry.close_logical_call(logical_call_id=lc1, status="success")
                attempt = telemetry.begin_attempt(
                    logical_call_id=lc1,
                    endpoint="http://x",
                    provider="p",
                    model="m",
                    schema_mode="json",
                    request_fingerprint="fp",
                    configured_output_limit=4096,
                    reasoning_reserve_tokens=0,
                    known_context_limit=None,
                    effective_output_limit=4096,
                    requested_output_limit=4096,
                    input_chars=100,
                    phase="plan",
                    request_body={"messages": [{"role": "user", "content": "why"}]},
                )
                telemetry.record_attempt_response(
                    attempt_id=attempt,
                    response_body='{"choices":[{"message":{"content":"because"}}]}',
                )
                telemetry.finalize_attempt(
                    attempt_id=attempt,
                    status="success",
                    duration_ms=1234,
                    input_tokens=10,
                    output_tokens=20,
                    input_tokens_source="provider_actual",
                    output_tokens_source="provider_actual",
                )
                telemetry.record_deterministic_op(
                    phase="report", op_type="render", target="section", duration_ms=500
                )

            client = TestClient(create_app(case))

            traj = client.get("/api/sessions/S-TRAJ/trajectory").json()
            self.assertEqual(traj["session_id"], "S-TRAJ")
            self.assertEqual(traj["status"], "completed")
            self.assertEqual(traj["terminal_reason"], "completed: investigation loop finished normally")
            self.assertEqual(traj["timezone"], "UTC")
            self.assertIsNotNone(traj["wall_time_ms"])
            agg = traj["aggregates"]
            self.assertEqual(agg["logical_call_count"], 1)
            self.assertEqual(agg["provider_attempt_count"], 1)
            self.assertEqual(agg["deterministic_op_count"], 1)
            self.assertEqual(agg["actual_input_tokens"], 10)
            self.assertEqual(agg["actual_output_tokens"], 20)
            self.assertEqual(traj["latency_by_phase"].get("plan"), 1234)
            self.assertEqual(traj["explained_time_ms"], 1234 + 500)
            self.assertIsNotNone(traj["unexplained_wall_time_ms"])
            self.assertEqual(len(traj["deterministic_operations"]), 1)

            calls = client.get("/api/sessions/S-TRAJ/logical-calls").json()
            self.assertEqual(calls["total"], 1)
            self.assertEqual(calls["items"][0]["logical_call_id"], lc1)
            self.assertEqual(calls["items"][0]["attempt_count"], 1)

            filtered_calls = client.get(
                "/api/sessions/S-TRAJ/logical-calls?phase=plan&status=success"
            ).json()
            self.assertEqual(filtered_calls["total"], 1)

            attempts = client.get(
                f"/api/logical-calls/{lc1}/attempts"
            ).json()
            self.assertEqual(attempts["total"], 1)
            self.assertEqual(attempts["items"][0]["attempt_id"], attempt)
            self.assertEqual(attempts["items"][0]["duration_ms"], 1234)
            self.assertEqual(attempts["items"][0]["input_tokens"], 10)
            self.assertEqual(attempts["items"][0]["output_tokens"], 20)
            self.assertEqual(
                attempts["items"][0]["request_body"]["messages"][0]["content"],
                "why",
            )
            self.assertIn("because", attempts["items"][0]["response_body"])


if __name__ == "__main__":
    unittest.main()
