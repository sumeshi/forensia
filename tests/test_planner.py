from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from forensia.ai.checking.check_normalize import parse_new_hypotheses
from forensia.ai.investigation.investigation_cycle import select_focus_hypotheses
from forensia.ai.investigation.planner import (
    normalize_query_intent_action,
    plan_hypothesis_query,
    request_with_optional_context,
    validate_select_sql,
)
from forensia.ai.investigation.progress import (
    HypothesisProgressTracker,
    query_fingerprint,
)
from forensia.ai.prompts.sql_schema import build_investigation_framework
from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.session import HistoryEntry, Hypothesis, SessionState
from forensia.db.database import CaseDB


class _MemoryStub:
    max_bytes = 16384

    def load_overview(self) -> str:
        return "# overview"

    def load_context(self, files: list[str]) -> str:
        return ""

    def load_compact_context(
        self, files: list[str], max_bytes: int | None = None
    ) -> str:
        return "# facts.md\n\n- fact\n\n# tasks.md\n\n- question"


def _llm_base_url() -> str:
    return resolve_llm_config()[0] or "http://test-llm.invalid"


class PlannerRetryTests(unittest.TestCase):
    """Query planning, SQL templates/validation, retry, and fingerprint behavior."""

    def tearDown(self) -> None:
        reload_settings()

    def test_auto_confirm_requires_all_co_observed_event_ids(self) -> None:
        tracker = HypothesisProgressTracker()
        hypothesis = Hypothesis(
            id="H-confirm",
            description="RDP followed by PowerShell",
            source_rule_ids=["windows-rdp-lsm-21-logon"],
            confirm_when={
                "co_observed_event_ids": [4624, 4104],
                "event_contexts": [
                    {
                        "event_id": 4104,
                        "channel": "Microsoft-Windows-PowerShell/Operational",
                        "provider": "Microsoft-Windows-PowerShell",
                    }
                ],
            },
        )

        self.assertFalse(
            tracker.should_auto_confirm(
                None,
                [{"event_id": 4624}],
                hypothesis,
            )
        )
        self.assertTrue(
            tracker.has_partial_confirm_signal(
                None,
                [{"event_id": 4624}],
                hypothesis,
            )
        )
        self.assertTrue(
            tracker.should_auto_confirm(
                None,
                [
                    {"event_id": 4624},
                    {
                        "event_id": 4104,
                        "channel": "Microsoft-Windows-PowerShell/Operational",
                        "raw_json": {
                            "winlog": {
                                "provider": {"name": "Microsoft-Windows-PowerShell"}
                            }
                        },
                    },
                ],
                hypothesis,
            )
        )
        self.assertFalse(
            tracker.should_auto_confirm(
                None,
                [
                    {"event_id": 4624},
                    {
                        "event_id": 4104,
                        "channel": "Application",
                        "raw_json": {
                            "winlog": {
                                "provider": {"name": "Microsoft-Windows-Winlogon"}
                            }
                        },
                    },
                ],
                hypothesis,
            )
        )

    def test_select_focus_hypotheses_prioritizes_uninvestigated_items(self) -> None:
        state = SessionState(
            session_id="S-1",
            active_hypotheses=[
                Hypothesis(
                    id="H-001",
                    description="Repeatedly investigated high confidence hypothesis",
                    source_rule_ids=["r1", "r2", "r3"],
                    required_entities=["computer", "target_user"],
                ),
                Hypothesis(
                    id="H-002",
                    description="Newly drafted hypothesis with no reasoning yet",
                    source_rule_ids=["r4"],
                ),
            ],
        )
        state.history.append(
            HistoryEntry(
                iteration=10,
                query_id="H-001-q1",
                hypothesis_id="H-001",
                verdict="inconclusive",
                summary="still inconclusive",
            )
        )

        selected = select_focus_hypotheses(state, max_items=1)

        self.assertEqual(["H-002"], [item.id for item in selected])

    def test_validate_select_sql_allows_investigation_state_tables(self) -> None:
        for sql in (
            "SELECT * FROM hypotheses",
            "SELECT * FROM report_sections",
            "SELECT * FROM claims",
            "SELECT * FROM prefetch_executions",
            "SELECT * FROM mft_entries",
        ):
            self.assertEqual(sql, validate_select_sql(sql))

    def test_checker_parses_new_hypotheses_leniently(self) -> None:
        hypotheses = parse_new_hypotheses(
            [
                {
                    "id": "H-new",
                    "description": "follow this lead",
                    "status": "active",
                    "verdict": "inconclusive",
                }
            ]
        )
        self.assertEqual(1, len(hypotheses))
        self.assertIsNone(hypotheses[0].verdict)

    def test_materializes_query_template_into_sql(self) -> None:
        state = SessionState(session_id="session-template", iteration=1)
        hypothesis = Hypothesis(id="H0", description="failed logon burst")
        responses = [
            {
                "read_more": [],
                "intent": "Find failed logon events grouped by source IP",
                "target_table": "evtx_events",
                "filters_required": ["event_id = 4625"],
                "time_window": "case time range",
                "expected_row_shape": "event_id, timestamp, src_ip",
                "template_id": "q_failed_logon_by_ip_window",
                "params": {"hours": 24, "threshold": 5},
                "purpose": "failed logons by src_ip",
            },
        ]

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=responses
        ):
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertIsNotNone(result.query)
        self.assertEqual("q_failed_logon_by_ip_window", result.query.template_id)
        self.assertIn("GROUP BY src_ip", result.query.sql)

    def test_materializes_explicit_nested_sql_action(self) -> None:
        """The typed nested action, rather than its response wrapper, is materialized."""
        state = SessionState(session_id="session-nested-action", iteration=1)
        hypothesis = Hypothesis(id="H-nested", description="inspect events")
        response = {
            "action": {
                "type": "sql.query",
                "intent": "inspect events",
                "target_table": "evtx_events",
                "sql": "SELECT event_id FROM evtx_events LIMIT 1",
            },
        }
        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", return_value=response
        ):
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertIsNotNone(result.query)
        self.assertEqual(
            "SELECT event_id FROM evtx_events LIMIT 1", result.query.sql
        )

    def test_action_gate_accepts_explicit_sql_and_legacy_intent(self) -> None:
        explicit, explicit_error = normalize_query_intent_action(
            {
                "action": {
                    "type": "sql.query",
                    "intent": "inspect events",
                    "target_table": "evtx_events",
                },
            }
        )
        legacy, legacy_error = normalize_query_intent_action(
            {
                "read_more": [],
                "intent": "inspect events",
                "target_table": "evtx_events",
            }
        )
        self.assertEqual("sql.query", explicit.type if explicit else None)
        self.assertIsNone(explicit_error)
        self.assertEqual("sql.query", legacy.type if legacy else None)
        self.assertIsNone(legacy_error)

    def test_planner_validation_feedback_is_consumed_by_next_call(self) -> None:
        state = SessionState(
            session_id="session-validation-feedback",
            iteration=1,
            last_planner_error={
                "hypothesis_id": "H-feedback",
                "reason": "invalid_action: Unknown table",
            },
        )
        hypothesis = Hypothesis(id="H-feedback", description="inspect events")
        seen_messages: list[list[dict[str, str]]] = []

        def respond(**kwargs):
            seen_messages.append(kwargs["messages"])
            return {
                "action": {
                    "type": "sql.query",
                    "intent": "inspect events",
                    "target_table": "evtx_events",
                    "sql": "SELECT event_id FROM evtx_events LIMIT 1",
                }
            }

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=respond
        ):
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertIsNotNone(result.query)
        self.assertIsNone(state.last_planner_error)
        prompt = "\n".join(message["content"] for message in seen_messages[0])
        self.assertIn("<PLANNER_VALIDATION_ERROR>", prompt)
        self.assertIn("Unknown table", prompt)

        other_state = SessionState(
            session_id="session-validation-feedback-other",
            iteration=1,
            last_planner_error={"hypothesis_id": "H-feedback", "reason": "secret"},
        )
        other_messages: list[list[dict[str, str]]] = []

        def respond_other(**kwargs):
            other_messages.append(kwargs["messages"])
            return {
                "action": {
                    "type": "sql.query",
                    "intent": "inspect events",
                    "target_table": "evtx_events",
                    "sql": "SELECT event_id FROM evtx_events LIMIT 1",
                }
            }

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=respond_other
        ):
            plan_hypothesis_query(
                state=other_state,
                hypothesis=Hypothesis(id="H-other", description="other question"),
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )
        other_prompt = "\n".join(m["content"] for m in other_messages[0])
        self.assertNotIn("<PLANNER_VALIDATION_ERROR>", other_prompt)
        self.assertIsNotNone(other_state.last_planner_error)

    def test_unknown_action_stops_before_sql_composition(self) -> None:
        state = SessionState(session_id="session-action", iteration=1)
        hypothesis = Hypothesis(id="H-action", description="test hypothesis")
        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json",
            return_value={
                "action": {"type": "knowledge.retrieve"},
                "intent": "inspect events",
                "target_table": "evtx_events",
            },
        ) as request:
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )
        self.assertIsNone(result.query)
        self.assertFalse(result.needs_more)
        self.assertIn("unknown or malformed action", result.stop_reason or "")
        request.assert_called_once()

    def test_repeated_memory_action_is_ineligible_after_expansion(self) -> None:
        state = SessionState(session_id="session-action", iteration=1)
        hypothesis = Hypothesis(id="H-action", description="test hypothesis")
        responses = [
            {
                "action": {
                    "type": "memory.read_more",
                    "paths": ["archive/refuted.md"],
                }
            },
            {
                "action": {
                    "type": "memory.read_more",
                    "paths": ["facts.md"],
                }
            },
        ]
        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=responses
        ) as request:
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )
        self.assertIsNone(result.query)
        self.assertFalse(result.needs_more)
        self.assertIn("not eligible", result.stop_reason or "")
        self.assertEqual(2, request.call_count)

    def test_query_intent_exposes_current_and_peer_active_hypotheses(self) -> None:
        current = Hypothesis(id="H-A", description="gap alpha current question")
        other = Hypothesis(id="H-B", description="gap beta peer hypothesis")
        state = SessionState(
            session_id="session-scope",
            iteration=1,
            active_hypotheses=[current, other],
        )
        responses = [
            {
                "read_more": [],
                "intent": "inspect alpha",
                "target_table": "evtx_events",
                "filters_required": [],
                "time_window": "case range",
                "expected_row_shape": "event_id",
            },
            {
                "template_id": None,
                "sql": "SELECT event_id FROM evtx_events LIMIT 1",
                "params": {},
                "purpose": "inspect alpha",
            },
        ]
        seen_messages: list[list[dict[str, str]]] = []

        def respond(**kwargs):
            seen_messages.append(kwargs["messages"])
            return responses[len(seen_messages) - 1]

        with patch("forensia.ai.llm.llm_gateway.request_llm_json", side_effect=respond):
            plan_hypothesis_query(
                state=state,
                hypothesis=current,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        intent_prompt = "\n".join(message["content"] for message in seen_messages[0])
        self.assertIn("gap alpha current question", intent_prompt)
        self.assertIn("gap beta peer hypothesis", intent_prompt)

    def test_rejects_invalid_sql_without_another_llm_call(self) -> None:
        state = SessionState(session_id="session-1", iteration=1)
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        responses = [
            {
                "read_more": [],
                "intent": "test intent",
                "target_table": "evtx_events",
                "filters_required": [],
                "time_window": "All",
                "expected_row_shape": "cols",
                "template_id": None,
                "sql": "SELECT * FROM nope",
                "params": {},
                "purpose": "test",
            },
        ]

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=responses
        ) as mock_request:
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertEqual(1, mock_request.call_count)
        self.assertIsNone(result.query)
        self.assertIn("invalid_action: Unknown table", result.stop_reason or "")

    def test_plan_hypothesis_query_dry_runs_columns_in_host(self) -> None:
        state = SessionState(session_id="session-1", iteration=1)
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        responses = [
            {
                "read_more": [],
                "intent": "test intent",
                "target_table": "evtx_events",
                "filters_required": [],
                "time_window": "All",
                "expected_row_shape": "cols",
                "template_id": None,
                "sql": "SELECT nonexistent_column FROM evtx_events LIMIT 1",
                "params": {},
                "purpose": "broken",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ),
                self.assertLogs(
                    "forensia.ai.investigation.planner", level="DEBUG"
                ) as logs,
            ):
                result = plan_hypothesis_query(
                    state=state,
                    hypothesis=hypothesis,
                    memory=_MemoryStub(),
                    base_url=_llm_base_url(),
                    model="test-model",
                    db=db,
                )

        self.assertIsNone(result.query)
        self.assertIn("invalid_action: Binder Error", result.stop_reason or "")
        self.assertTrue(
            any("planned SQL rejected by host validation" in line for line in logs.output)
        )

    def test_plan_hypothesis_query_includes_recent_db_history_on_resume(self) -> None:
        state = SessionState(session_id="session-db", iteration=2)
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        responses = [
            {"read_more": [], "intent": "test", "target_table": "evtx_events"},
            {"sql": "SELECT 1", "purpose": "test"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H1', 'S-1', 1, 'check', 'inconclusive', 'Q-old', 'already tested', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-2', 'H1', 'S-1', 1, 'sufficiency', 'inconclusive', 'Q-old', 'missing required capability', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-3', 'H1', 'S-1', 1, 'settlement', 'inconclusive', 'Q-old', 'host settlement gate blocked confirmation', now())
                    """
                )
                with patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ) as mock_request:
                    plan_hypothesis_query(
                        state=state,
                        hypothesis=hypothesis,
                        memory=_MemoryStub(),
                        base_url=_llm_base_url(),
                        model="test-model",
                        db=db,
                    )

        # Check the intent-phase call (first call) for DB history
        first_call_system = mock_request.call_args_list[0].kwargs["messages"][0][
            "content"
        ]
        self.assertIn("query_id=Q-old", first_call_system)
        first_call_user = mock_request.call_args_list[0].kwargs["messages"][1][
            "content"
        ]
        self.assertIn("[sufficiency] missing required capability", first_call_user)
        self.assertIn(
            "[settlement] host settlement gate blocked confirmation", first_call_user
        )

    def test_plan_hypothesis_query_dedupes_local_and_db_query_ids(self) -> None:
        state = SessionState(
            session_id="session-db",
            iteration=2,
            history=[
                HistoryEntry(
                    query_id="Q-local",
                    hypothesis_id="H1",
                    iteration=1,
                    verdict="inconclusive",
                    summary="already tested",
                    evidence_ids=[],
                )
            ],
        )
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        responses = [
            {"read_more": [], "intent": "test", "target_table": "evtx_events"},
            {"sql": "SELECT 1", "purpose": "test"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H1', 'S-1', 1, 'check', 'inconclusive', 'Q-local', 'duplicate row', now())
                    """
                )
                with patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ) as mock_request:
                    plan_hypothesis_query(
                        state=state,
                        hypothesis=hypothesis,
                        memory=_MemoryStub(),
                        base_url=_llm_base_url(),
                        model="test-model",
                        db=db,
                    )

        # Check the intent-phase call (first call) for deduplication
        first_call_system = mock_request.call_args_list[0].kwargs["messages"][0][
            "content"
        ]
        # Exactly one attempt line for Q-local: the DB reasoning row sharing
        # the same query_id must merge with the local history entry, not
        # appear as a second attempt.
        self.assertEqual(1, first_call_system.count("query_id=Q-local"))

    def test_investigation_framework_lists_missing_columns(self) -> None:
        framework = build_investigation_framework()
        self.assertIn(
            "evtx_events columns: evidence_id, source_file, channel, event_id, record_id, timestamp",
            framework,
        )
        self.assertIn(
            "hypotheses columns: hypothesis_id, description, status, verdict, summary, origin",
            framework,
        )
        self.assertIn("event_id = 4624 AND logon_type IN ('2','10')", framework)
        self.assertIn("4728/4732", framework)

    def test_returns_none_when_retry_is_still_invalid(self) -> None:
        state = SessionState(session_id="session-2", iteration=1)
        hypothesis = Hypothesis(id="H2", description="test hypothesis")
        responses = [
            {
                "read_more": [],
                "intent": "test intent",
                "target_table": "evtx_events",
                "filters_required": [],
                "time_window": "All",
                "expected_row_shape": "cols",
            },
            {
                "template_id": None,
                "sql": "SELECT * FROM nope",
                "params": {},
                "purpose": "test",
            },
            {
                "template_id": None,
                "sql": "DELETE FROM findings",
                "params": {},
                "purpose": "retry1",
            },
            {
                "template_id": None,
                "sql": "DELETE FROM findings",
                "params": {},
                "purpose": "retry2",
            },
        ]

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=responses
        ):
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertIsNone(result.query)

    def test_route_trace_write_skips_regex_for_select(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch("forensia.db.database.re.search") as mock_search,
            ):
                routed = db._route_trace_write("SELECT * FROM progress_events")
        self.assertEqual("SELECT * FROM progress_events", routed)
        mock_search.assert_not_called()

    def test_request_with_optional_context_starts_with_default_memory(self) -> None:
        seen: list[str] = []

        def builder(extra_context: str) -> list[dict[str, str]]:
            seen.append(extra_context)
            return [{"role": "user", "content": extra_context}]

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json",
            return_value={"read_more": []},
        ):
            request_with_optional_context(
                memory=_MemoryStub(),
                messages_builder=builder,
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertEqual(1, len(seen))
        self.assertIn("facts.md", seen[0])
        self.assertIn("tasks.md", seen[0])

    def test_request_with_optional_context_uses_compact_context_for_read_more(
        self,
    ) -> None:
        memory = _MemoryStub()
        seen: list[str] = []
        with (
            patch.object(
                memory, "load_compact_context", return_value="# compact extra"
            ) as mock_compact,
            patch(
                "forensia.ai.llm.llm_gateway.request_llm_json",
                side_effect=[{"read_more": ["archive/refuted.md"]}, {"read_more": []}],
            ),
        ):
            request_with_optional_context(
                memory=memory,
                messages_builder=lambda extra: (
                    seen.append(extra) or [{"role": "user", "content": extra}]
                ),
                base_url=_llm_base_url(),
                model="test-model",
            )

        mock_compact.assert_any_call(["archive/refuted.md"], max_bytes=memory.max_bytes)
        self.assertEqual(2, len(seen))
        self.assertIn(seen[0], seen[1])
        self.assertIn("# compact extra", seen[1])

    def test_request_with_optional_context_enforces_hypothesis_scope(self) -> None:
        case_dir = tempfile.TemporaryDirectory()
        self.addCleanup(case_dir.cleanup)
        from forensia.core.memory import MemoryManager

        memory = MemoryManager(Case.init(case_dir.name))
        events: list[dict] = []
        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json",
            return_value={"read_more": ["scratch/H-B/tasks.md"]},
        ) as request:
            result = request_with_optional_context(
                memory=memory,
                messages_builder=lambda extra: [{"role": "user", "content": extra}],
                base_url=_llm_base_url(),
                model="test-model",
                hypothesis_id="H-A",
                retrieval_callback=events.append,
            )

        self.assertEqual([], result["read_more"])
        self.assertEqual(1, request.call_count)
        self.assertEqual(["scratch/H-B/tasks.md"], events[0]["rejected_refs"])
        self.assertEqual("rejected", events[0]["scope_status"])
        self.assertEqual("invalid", events[0]["retrieval_evaluation"]["outcome"])

    def test_query_fingerprint_normalizes_equivalent_ast_forms(self) -> None:
        left = query_fingerprint(
            "SELECT * FROM evtx_events WHERE event_id = 4624 AND computer = 'HOST1'"
        )
        right = query_fingerprint(
            "select * from evtx_events as e where computer = 'host1' and event_id in (4624)"
        )

        self.assertEqual(left, right)

    def test_query_fingerprint_changes_for_different_event_scope(self) -> None:
        left = query_fingerprint(
            "SELECT * FROM evtx_events WHERE event_id = 4624 AND computer = 'HOST1'"
        )
        right = query_fingerprint(
            "SELECT * FROM evtx_events WHERE event_id = 4634 AND computer = 'HOST1'"
        )

        self.assertNotEqual(left, right)

    def test_single_llm_decision_skips_schema_self_check_call(self) -> None:
        """T-20: the second 'schema-readiness' LLM call must be gone.

        The SQL path is one bounded action decision; the host validates it
        deterministically without a readiness or composer call.
        """
        state = SessionState(session_id="session-single", iteration=1)
        hypothesis = Hypothesis(id="H-single", description="test hypothesis")
        responses = [
            {
                "read_more": [],
                "intent": "test intent",
                "target_table": "evtx_events",
                "filters_required": [],
                "time_window": "All",
                "expected_row_shape": "cols",
                "template_id": None,
                "sql": "SELECT event_id FROM findings LIMIT 1",
                "params": {},
                "purpose": "test",
            },
        ]

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=responses
        ) as mock_request:
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        # One bounded SQL decision — no readiness/composer/self-check call.
        self.assertEqual(1, mock_request.call_count)
        self.assertIsNotNone(result.query)
        for call in mock_request.call_args_list:
            for message in call.kwargs["messages"]:
                self.assertNotIn("ready_to_compose", str(message.get("content")))

if __name__ == "__main__":
    unittest.main()
