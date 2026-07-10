from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from forensia.ai.checking.check_apply import _insert_investigation_finding
from forensia.ai.hypotheses.hypothesis_manager import _merge_active_hypotheses
from forensia.ai.hypotheses.hypothesis_store import _load_persisted_hypotheses
from forensia.ai.investigation_session import _append_hypothesis_reasoning
from forensia.ai.investigator import _final_summary
from forensia.ai.report_gap import (
    _classify_gap_kind,
    _gap_hypothesis_id,
    _inject_gap_hypotheses,
    _report_cycle_progress,
)
from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.report.section_quality import collect_gaps, section_confidence
from forensia.report.section_store import extract_claim_texts


def _agent_plan_router(*_args, **kwargs):
    """Route section_agent.request_llm_json by which messages were sent.

    Plan messages → "write" short-circuit (no SQL).
    Check messages → "sufficient" so the loop exits cleanly.
    Used to avoid hitting a real LLM in unit tests.
    """
    messages = kwargs.get("messages")
    if messages is None and _args:
        messages = _args[0]
    system_content = ""
    if messages:
        system_content = str(messages[0].get("content", "")).lower()
    if "section-check" in system_content:
        return {"verdict": "sufficient", "fact_updates": []}
    return {"action": "write", "enough_to_write": True}


async def _async_agent_plan_router(*args, **kwargs):
    return _agent_plan_router(*args, **kwargs)


class PersistenceTests(unittest.TestCase):
    """Investigation-state persistence: reasoning rows, hypothesis merge/gap injection."""

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def setUp(self) -> None:
        # llm_gateway is the single seam for LLM JSON calls; patch here.
        llm_json_patch = patch(
            "forensia.ai.llm.llm_gateway.request_llm_json",
            side_effect=_agent_plan_router,
        )
        llm_json_patch.start()
        self.addCleanup(llm_json_patch.stop)
        # The async report-refresh path uses async_request_llm_json; mock it too
        # so async tests don't hit the real LLM.
        self._async_llm_json_patch = patch(
            "forensia.ai.llm.llm_gateway.async_request_llm_json",
            side_effect=_async_agent_plan_router,
        )
        self._async_llm_json_patch.start()
        self.addCleanup(self._async_llm_json_patch.stop)

    def test_collect_gaps_supports_english_and_japanese_placeholders(self) -> None:
        self.assertEqual(
            ["no logon data"],
            collect_gaps({"sec": "[INSUFFICIENT EVIDENCE: no logon data]"}),
        )
        self.assertEqual(
            ["no logon records"],
            collect_gaps({"sec": "[INSUFFICIENT EVIDENCE: no logon records]"}),
        )

    def test_collect_gaps_preserves_order_while_deduplicating(self) -> None:
        self.assertEqual(
            ["gap one", "gap two"],
            collect_gaps(
                {
                    "a": "[INSUFFICIENT EVIDENCE: gap one]\n[INSUFFICIENT EVIDENCE: gap two]",
                    "b": "[INSUFFICIENT EVIDENCE: gap one]",
                }
            ),
        )

    def testsection_confidence_and_claim_extraction_respect_english_gap_placeholder(
        self,
    ) -> None:
        self.assertEqual(1.0, section_confidence("no gaps here"))
        self.assertLess(section_confidence("[INSUFFICIENT EVIDENCE: x]"), 1.0)
        self.assertEqual(
            [], extract_claim_texts("[INSUFFICIENT EVIDENCE: missing evidence]")
        )
        self.assertEqual(
            ["same claim"], extract_claim_texts("same claim\n\nsame claim")
        )

    def test_append_hypothesis_reasoning_is_idempotent_per_query_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                first = _append_hypothesis_reasoning(
                    db=db,
                    hypothesis_id="H-1",
                    session_id="S-1",
                    iteration=1,
                    phase="plan",
                    query_id="q-1",
                    body="look for 4625 burst",
                )
                second = _append_hypothesis_reasoning(
                    db=db,
                    hypothesis_id="H-1",
                    session_id="S-1",
                    iteration=1,
                    phase="plan",
                    query_id="q-1",
                    body="look for 4625 burst",
                )
                count = db.execute(
                    "SELECT COUNT(*) FROM hypothesis_reasoning WHERE hypothesis_id = 'H-1'"
                ).fetchone()[0]

            self.assertEqual(first, second)
            self.assertEqual(1, count)

    def test_load_persisted_hypotheses_restores_resolved_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "H-1",
                        "suspicious lateral movement confirmed",
                        "confirmed",
                        "confirmed",
                        "resolved in prior session",
                        "broad_plan",
                        "session-old",
                        "session-old",
                        now,
                        now,
                    ),
                )
                active, resolved = _load_persisted_hypotheses(db)

            self.assertEqual(0, len(active))
            self.assertEqual(1, len(resolved))
            self.assertEqual("H-1", resolved[0].id)
            self.assertEqual("confirmed", resolved[0].status)

    def test_merge_active_hypotheses_assigns_sequential_ids_and_dedupes_description(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES
                        ('H-001', 'existing active hypothesis', 'active', NULL, '', 'broad_plan', 'S-1', NULL, now(), now(), '["rule-1"]', '["host"]', NULL),
                        ('H-002', 'resolved reference hypothesis', 'confirmed', 'confirmed', 'done', 'broad_plan', 'S-1', 'S-2', now(), now(), '["rule-2"]', '["user"]', NULL)
                    """
                )
                current = [
                    Hypothesis(
                        id="H-001",
                        description="existing active hypothesis",
                        status="active",
                        summary="",
                        source_rule_ids=["rule-1"],
                        required_entities=["host"],
                    ),
                ]
                updates = [
                    Hypothesis(
                        id="H-new",
                        description="existing active hypothesis",
                        status="active",
                        summary="",
                        source_rule_ids=["rule-3"],
                        required_entities=["computer"],
                    ),
                    Hypothesis(
                        id="H-new-2",
                        description="brand new hypothesis",
                        status="active",
                        summary="",
                        source_rule_ids=["rule-4"],
                        required_entities=["service"],
                    ),
                    Hypothesis(
                        id="H-new-3",
                        description="resolved reference hypothesis",
                        status="active",
                        summary="",
                        source_rule_ids=["rule-5"],
                        required_entities=["user"],
                    ),
                ]
                resolved = [
                    Hypothesis(
                        id="H-002",
                        description="resolved reference hypothesis",
                        status="confirmed",
                        verdict="confirmed",
                        summary="done",
                    ),
                ]
                merged = _merge_active_hypotheses(
                    db=db,
                    current=current,
                    updates=updates,
                    resolved=resolved,
                    session_id="session-test",
                    origin="broad_plan",
                )
                rows = db.execute(
                    "SELECT hypothesis_id, description, status, source_rule_ids FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()

            ids = [row[0] for row in rows]
            self.assertEqual(["H-001", "H-002", "H-003"], ids)
            self.assertEqual(2, len(merged))
            self.assertEqual({"H-001", "H-003"}, {item.id for item in merged})
            self.assertIn("rule-3", str(rows[0][3]))
            self.assertEqual("H-003", rows[2][0])

    def test_merge_active_hypotheses_dedup_by_similarity_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES
                        ('H-010', 'RDP lateral movement to deploy service', 'active', NULL, '', 'broad_plan', 'S-1', NULL, now(), now(), '["rule-1"]', '["host"]', NULL)
                    """
                )
                merged = _merge_active_hypotheses(
                    db=db,
                    current=[
                        Hypothesis(
                            id="H-010",
                            description="RDP lateral movement to deploy service",
                            status="active",
                            source_rule_ids=["rule-1"],
                            required_entities=["host"],
                        )
                    ],
                    updates=[
                        Hypothesis(
                            id="H-new",
                            description="RDP lateral movement used to deploy service",
                            status="active",
                            source_rule_ids=["rule-2"],
                            required_entities=["host"],
                        ),
                    ],
                    resolved=[],
                    session_id="session-test",
                    origin="broad_plan",
                )
                rows = db.execute(
                    "SELECT hypothesis_id, description, source_rule_ids FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()
                self.assertEqual(1, len(merged))
                self.assertEqual("H-010", merged[0].id)
                self.assertIn("rule-2", str(rows[0][2]))

    def test_report_cycle_progress_can_be_true_from_gap_reduction_alone(self) -> None:
        self.assertTrue(
            _report_cycle_progress(
                {"total_gaps": 3, "total_body_chars": 120},
                {"total_gaps": 2, "total_body_chars": 120},
            )
        )
        self.assertFalse(
            _report_cycle_progress(
                {"total_gaps": 2, "total_body_chars": 120},
                {"total_gaps": 2, "total_body_chars": 120},
            )
        )

    def test_gap_hypotheses_are_injected_once_for_new_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="session-test")
                added = _inject_gap_hypotheses(
                    db, state, ["foo bar"], session_id="session-test"
                )
                duplicate = _inject_gap_hypotheses(
                    db, state, ["foo bar"], session_id="session-test"
                )
                rows = db.execute(
                    "SELECT hypothesis_id, origin, status, description FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()

            self.assertEqual(1, added)
            self.assertEqual(0, duplicate)
            self.assertEqual(1, len(state.active_hypotheses))
            self.assertEqual(
                _gap_hypothesis_id("foo bar"), state.active_hypotheses[0].id
            )
            self.assertEqual(
                [(_gap_hypothesis_id("foo bar"), "report_gap", "active", "foo bar")],
                rows,
            )

    def test_external_or_human_gaps_do_not_become_hypotheses(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db:
                state = SessionState(session_id="session-test")
                added = _inject_gap_hypotheses(
                    db,
                    state,
                    ["Check src_ip ownership", "Manager interview needed"],
                    session_id="session-test",
                    memory=memory,
                )
                row_count = db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]

            self.assertEqual(
                "external_lookup", _classify_gap_kind("Check src_ip ownership")
            )
            self.assertEqual(
                "human_decision", _classify_gap_kind("Manager interview needed")
            )
            self.assertEqual(0, added)
            self.assertEqual(0, row_count)
            self.assertIn(
                "ownership",
                memory.tasks_memory_path.read_text(encoding="utf-8").lower(),
            )

    def test_gap_classification_supports_english_external_and_human_keywords(
        self,
    ) -> None:
        for phrase in (
            "Need ip reputation check for this address",
            "Perform geo lookup for the source IP",
            "This requires external internet confirmation",
        ):
            self.assertEqual("external_lookup", _classify_gap_kind(phrase))
        for phrase in (
            "Need manager approval before concluding",
            "Confirm with the business owner",
            "Schedule a stakeholder hearing for this finding",
        ):
            self.assertEqual("human_decision", _classify_gap_kind(phrase))

    def test_final_summary_fallback_follows_output_language(self) -> None:
        with patch.dict("os.environ", {"LLM_OUTPUT_LANGUAGE": "en"}):
            reload_settings()
            self.assertEqual(
                "No additional progress was made during this investigation.",
                _final_summary(SessionState(session_id="S-1")),
            )
            reload_settings()

    def test_investigation_finding_title_prefix_follows_output_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            planned_query = PlannedQuery(
                query_id="Q-1",
                hypothesis_id="H-1",
                purpose="host triage",
                sql="SELECT 1",
            )
            with patch.dict("os.environ", {"LLM_OUTPUT_LANGUAGE": "ja"}):
                reload_settings()
                with CaseDB(case) as db:
                    finding_id = _insert_investigation_finding(
                        db=db,
                        session_id="S-1",
                        planned_query=planned_query,
                        result_summary={"sample_rows": []},
                        report_text="body",
                    )
                    title = db.execute(
                        "SELECT title FROM findings WHERE finding_id = ?", (finding_id,)
                    ).fetchone()[0]
            self.assertEqual("Investigation: host triage", title)
            reload_settings()


if __name__ == "__main__":
    unittest.main()
