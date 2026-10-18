from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import load_event_class_definitions
from forensia.report.answers.answer_registry import build_structured_answer
from forensia.report.answers.keypoint_catalog import resolve_evidence_results
from forensia.report.sections.quality_gates import (
    GateContext,
    check_citation_token_no_finding_id,
    check_hedge_no_citation,
)
from forensia.report.sections.section_finalize import (
    validate_section_evidence_ids,
)
from forensia.report.sections.section_quality import validate_body_evidence_ids


class QuestionAnswerTests(unittest.TestCase):
    """Structured question/keypoint SQL answers and evidence-id validation."""

    def test_unassessed_candidates_export_and_render_separately(self) -> None:
        import csv
        from unittest.mock import patch

        from forensia.report.answers import answer_store
        from forensia.report.render.html import render_markdown_fragment

        candidates = [
            {
                "executable_name": f"C:\\Tools\\tool-{index}.exe",
                "last_exec_time": None
                if index == 2
                else f"2044-02-0{index + 1} 08:00:00",
                "candidate_state": "unassessed",
                "evidence_id": f"prefetch-unrelated-{index}",
                "discovery_step_id": "discovery-test-001",
            }
            for index in range(3)
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case):
                answer = answer_store._structured_answer(
                    case,
                    answer_id="Q12",
                    section_key="timeline",
                    block_heading="Q12. Execution records",
                    rows=[],
                    columns=["executable_name", "last_exec_time", "evidence_id"],
                    queries_run=[],
                    status="insufficient_evidence",
                    missing_reason=["assessment has not completed"],
                    source="investigation",
                    unassessed_candidates=candidates,
                    candidate_search={
                        "discovery_step_id": "discovery-test-001",
                        "contract_id": "contract-test",
                        "sql": "SELECT evidence_id FROM prefetch_executions",
                        "query_truncated": True,
                    },
                )
                self.assertEqual([], answer["answer"])
                self.assertEqual(3, len(answer["unassessed_candidates"]))
                candidate_csv = (
                    case.reports_dir / answer["unassessed_candidates_csv_path"]
                )
                with candidate_csv.open(encoding="utf-8", newline="") as handle:
                    exported = list(csv.DictReader(handle))
                self.assertEqual(3, len(exported))
                self.assertTrue(
                    all(row["candidate_state"] == "unassessed" for row in exported)
                )
                self.assertTrue(
                    all(
                        row["discovery_step_id"] == "discovery-test-001"
                        for row in exported
                    )
                )
                self.assertEqual("", exported[2]["last_exec_time"])

                with patch.object(answer_store, "_resolve_max_rows", return_value=1):
                    markdown = answer_store._render_structured_answer_markdown(
                        answer, "Q12. Execution records"
                    )
                self.assertIn("### Unassessed search candidates", markdown)
                self.assertIn(
                    "have not completed assessment for this question", markdown
                )
                self.assertIn(
                    "search was incomplete because it reached the result limit",
                    markdown,
                )
                self.assertIn("discovery-test-001", markdown)
                self.assertIn("Showing 1 of 3 rows", markdown)
                self.assertIn(answer["unassessed_candidates_csv_path"], markdown)
                html = str(render_markdown_fragment(markdown))
                self.assertIn("Unassessed search candidates", html)
                self.assertIn("prefetch-unrelated-0", html)

                exported_json = json.loads(
                    (case.reports_dir / answer["json_path"]).read_text(encoding="utf-8")
                )
                self.assertEqual([], exported_json["answer"])
                self.assertEqual(3, len(exported_json["unassessed_candidates"]))
                self.assertEqual(
                    "discovery-test-001",
                    exported_json["unassessed_candidates"][0]["discovery_step_id"],
                )

                answer_store._write_structured_answer_export(
                    case, answer | {"unassessed_candidates": []}
                )
                self.assertFalse(candidate_csv.exists())

    def test_removing_candidates_preserves_same_id_answer_csv(self) -> None:
        from forensia.report.answers import answer_store

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case):
                answer = answer_store._structured_answer(
                    case,
                    answer_id="inventory.candidates",
                    section_key="timeline",
                    block_heading="Inventory candidates",
                    rows=[{"evidence_id": "evtx-test"}],
                    columns=["evidence_id"],
                    queries_run=[],
                    unassessed_candidates=[
                        {"evidence_id": "evtx-test", "candidate_state": "unassessed"}
                    ],
                    candidate_search={"discovery_step_id": "step-1", "sql": "SELECT 1"},
                )
                answer_csv = case.reports_dir / answer["csv_path"]
                self.assertTrue(answer_csv.exists())
                answer_store._write_structured_answer_export(
                    case, answer | {"unassessed_candidates": []}
                )
                self.assertTrue(answer_csv.exists())

    def test_timestamp_coverage_reason_does_not_mask_gap_reason(self) -> None:
        from forensia.core.identifiers import report_gap_id
        from forensia.report.answers.answer_registry import (
            _build_investigated_question_answer,
        )

        question = "Identify all timestamps related to unrelated.docx."
        section = "timeline"
        heading = "File timestamps"
        gap_id = report_gap_id(question, section_key=section, block_heading=heading)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, block_heading, "
                    "description, kind, status, coverage_reason) "
                    "VALUES (?, ?, ?, ?, 'question', 'open', ?)",
                    [gap_id, section, heading, question, "Discovery returned no rows."],
                )
                answer = _build_investigated_question_answer(
                    case,
                    db,
                    answer_id="Q28",
                    section_key=section,
                    block_heading=heading,
                    question_text=question,
                )
                self.assertEqual(
                    "Discovery returned no rows.", answer["missing_reason"][0]
                )
                self.assertIn(
                    "timestamp coverage is incomplete", answer["missing_reason"][1]
                )

    def test_typed_gap_failure_is_projected_without_erasing_coverage_reason(
        self,
    ) -> None:
        from types import SimpleNamespace

        from forensia.core.identifiers import report_gap_id
        from forensia.investigation.investigation_cycle import (
            _persisted_gap_drafts,
            _select_gap_drafts,
        )
        from forensia.investigation.prompts import build_hypothesis_drafter_messages
        from forensia.knowledge.questions import gap_operational_reason
        from forensia.report.answers.answer_store import (
            _render_structured_answer_markdown,
        )
        from forensia.report.render.html import render_markdown_fragment
        from forensia.report.sections.prompts import build_paragraph_narrate_messages

        question = "Which startup records were observed?"
        section = "timeline"
        heading = "Startup records"
        gap_id = report_gap_id(question, section_key=section, block_heading=heading)
        coverage_reason = "The required event channel was not collected."
        raw_error = "[Errno 104] Connection reset by peer"
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, block_heading, "
                    "description, kind, status, coverage_reason, origin) "
                    "VALUES (?, ?, ?, ?, 'question', 'open', ?, 'section')",
                    [gap_id, section, heading, question, raw_error],
                )
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, phase, input_json, output_json, created_at) "
                    "VALUES ('failed', 'plan-broad-candidate', ?, ?, "
                    "TIMESTAMP '2026-01-01 00:00:00')",
                    [
                        json.dumps(
                            {"gap_id": gap_id, "candidate_ref": f"gap-{gap_id}"}
                        ),
                        json.dumps(
                            {
                                "status": "failed",
                                "error_type": "ReadError",
                                "reason": raw_error,
                            }
                        ),
                    ],
                )
                self.assertEqual(
                    "investigation_attempt_failed",
                    gap_operational_reason(db, gap_id),
                )
                ctx = SimpleNamespace(
                    db=db, observed_keypoint_labels=[], case_policy=None
                )
                gaps = _persisted_gap_drafts(ctx)
                selected, _ = _select_gap_drafts(ctx, gaps, 1)
                self.assertEqual(
                    "investigation_attempt_failed", selected[0]["candidate"]["summary"]
                )
                self.assertNotIn(raw_error, repr(gaps))
                planner_messages, _ = build_hypothesis_drafter_messages(
                    selected[0]["candidate"], available_rules=[]
                )
                self.assertNotIn(raw_error, repr(planner_messages))
                failed_answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="question",
                    answer_id="Q1",
                    section_key=section,
                    block_heading=heading,
                    question_text=question,
                )
                self.assertEqual(
                    [
                        "The investigation attempt failed; the requested evidence remains unresolved."
                    ],
                    failed_answer["missing_reason"],
                )
                answer_markdown = _render_structured_answer_markdown(
                    failed_answer, heading
                )
                narrator_messages, _ = build_paragraph_narrate_messages(
                    heading=heading,
                    key_points=[],
                    evidence_rows=[],
                    template_body="",
                    structured_digest=answer_markdown,
                    db=db,
                    session_id="operational-projection-test",
                )
                answer_html = str(render_markdown_fragment(answer_markdown))
                self.assertNotIn(raw_error, answer_markdown)
                self.assertNotIn(raw_error, answer_html)
                self.assertNotIn(raw_error, repr(narrator_messages))
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, phase, input_json, output_json, created_at) "
                    "VALUES ('retrying', 'plan-broad-candidate', ?, ?, "
                    "TIMESTAMP '2026-01-01 00:00:30')",
                    [
                        json.dumps({"gap_id": gap_id}),
                        json.dumps({"status": "attempting"}),
                    ],
                )
                self.assertEqual(
                    "investigation_attempt_in_progress",
                    gap_operational_reason(db, gap_id),
                )
                retry_gaps = _persisted_gap_drafts(ctx)
                self.assertNotIn(raw_error, repr(retry_gaps))
                in_progress_answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="question",
                    answer_id="Q1",
                    section_key=section,
                    block_heading=heading,
                    question_text=question,
                )
                self.assertEqual(
                    ["The investigation is in progress; no conclusion is available."],
                    in_progress_answer["missing_reason"],
                )
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, phase, input_json, output_json, created_at) "
                    "VALUES ('recovered', 'plan-broad-candidate', ?, ?, "
                    "TIMESTAMP '2026-01-01 00:01:00')",
                    [
                        json.dumps({"gap_id": gap_id}),
                        json.dumps({"status": "completed"}),
                    ],
                )
                db.execute(
                    "UPDATE report_gaps SET coverage_reason = ? WHERE gap_id = ?",
                    [coverage_reason, gap_id],
                )
                self.assertIsNone(gap_operational_reason(db, gap_id))
                current_answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="question",
                    answer_id="Q1",
                    section_key=section,
                    block_heading=heading,
                    question_text=question,
                )
                self.assertEqual([coverage_reason], current_answer["missing_reason"])

    def test_natural_question_contract_flows_through_settlement_and_exports(
        self,
    ) -> None:
        import asyncio
        import csv
        from unittest.mock import patch

        from forensia.config import Settings, settings_scope
        from forensia.core.session import SessionState
        from forensia.db.evidence_sources import register_evidence_source
        from forensia.investigation.hypotheses.hypothesis_runner import (
            _investigate_one_hypothesis,
        )
        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _draft_and_admit_candidate,
        )
        from forensia.investigation.investigation_session import Ctx
        from forensia.investigation.report_gap import inject_gap_hypotheses
        from forensia.report.render.writer import render_written_report
        from forensia.report.sections.report_input import SectionSource
        from forensia.report.sections.section_refresher import (
            async_refresh_report_sections,
        )
        from forensia.report.sections.template_parsing import TemplateMeta

        expected = "2041-09-23 14:07:36"
        wrong_field_value = "2041-09-24 08:11:05"
        target = r"C:\Users\Rhea\AppData\Local\Temp\meteor.bin"
        missing_field_target = r"D:\Profiles\Cato\Desktop\ledger.bin"
        wrong_target = r"E:\Profiles\Absent\Desktop\meteor.bin"
        distractor_target = r"E:\Profiles\Other\Desktop\meteor.bin"
        partial_target = r"F:\Users\Mina\Desktop\bundle.bin"
        questions = [
            ("natural-positive", target),
            ("natural-missing-si", missing_field_target),
            ("natural-wrong-target", wrong_target),
            ("natural-refuted", r"C:\Users\Nora\Desktop\active.bin"),
            ("natural-partial", partial_target),
            ("natural-evtx", "EVTX event ID 9917"),
        ]
        source = SectionSource(
            section_key="6_appendix",
            body="\n\n".join(
                f"## {answer_id}: {path}\n<!-- question: {('What computer value is recorded for ' + path + '?') if answer_id == 'natural-evtx' else ('What SI creation timestamp is recorded for the exact file ' + path + '?')} -->\n"
                f"<!-- answer_id: {answer_id} -->"
                for answer_id, path in questions
            ),
            meta=TemplateMeta(title="Exact file timestamps"),
            source="test-input",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir, source_timezone="UTC")
            session_id = "natural-question-contract"
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="synthetic-mft-question-source",
                    artifact_family="mft",
                    display_path="synthetic://question-contract/mft",
                    ingest_status="normalized",
                    parser_name="question-contract-test",
                    parser_version="1",
                    row_count=6,
                )
                register_evidence_source(
                    db,
                    source_id="synthetic-evtx-question-source",
                    artifact_family="evtx",
                    display_path="synthetic://question-contract/evtx",
                    ingest_status="normalized",
                    parser_name="question-contract-test",
                    parser_version="1",
                    row_count=2,
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, source_file, record_number, "
                    "file_path, file_name, si_created, fn_created) VALUES "
                    "('mft-natural-positive', 'synthetic-mft-question-source', 1, ?, "
                    "'meteor.bin', ?, ?), "
                    "('mft-natural-missing-si', 'synthetic-mft-question-source', 2, ?, "
                    "'ledger.bin', NULL, ?), "
                    "('mft-natural-distractor', 'synthetic-mft-question-source', 3, ?, "
                    "'meteor.bin', ?, ?), "
                    "('mft-natural-refuted', 'synthetic-mft-question-source', 4, ?, "
                    "'active.bin', NULL, NULL), "
                    "('mft-natural-partial', 'synthetic-mft-question-source', 5, ?, "
                    "'bundle.bin', ?, NULL), "
                    "('mft-natural-partial-z-unchecked', 'synthetic-mft-question-source', 6, ?, "
                    "'bundle.bin', ?, NULL)",
                    [
                        target,
                        datetime.fromisoformat(expected),
                        datetime.fromisoformat(expected),
                        missing_field_target,
                        datetime.fromisoformat(wrong_field_value),
                        distractor_target,
                        datetime.fromisoformat("2041-09-25 10:00:00"),
                        datetime.fromisoformat("2041-09-25 10:00:00"),
                        r"C:\Users\Nora\Desktop\active.bin",
                        partial_target,
                        datetime.fromisoformat(expected),
                        partial_target,
                        datetime.fromisoformat("2041-09-24 14:07:36"),
                    ],
                )
                db.execute(
                    "UPDATE mft_entries SET is_deleted = false "
                    "WHERE evidence_id = 'mft-natural-refuted'"
                )
                for index in range(2, 6):
                    db.execute(
                        "INSERT INTO mft_entries (evidence_id, source_file, "
                        "record_number, file_path, file_name, si_created, fn_created) "
                        "VALUES (?, 'synthetic-mft-question-source', ?, ?, 'meteor.bin', ?, ?)",
                        [
                            f"mft-natural-positive-extra-{index}",
                            index + 5,
                            target,
                            datetime(2041, 9, 23, 14, 7, index),
                            datetime(2041, 9, 23, 14, 8, index),
                        ],
                    )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, event_id, timestamp, computer) "
                    "VALUES ('evtx-natural-question', 'synthetic-evtx-question-source', 9917, TIMESTAMP '2043-02-17 11:26:09', 'ORCHID-7'), "
                    "('evtx-natural-distractor', 'synthetic-evtx-question-source', 9918, TIMESTAMP '2043-02-17 11:27:09', 'CEDAR-2')"
                )

                def refresh():
                    return asyncio.run(
                        async_refresh_report_sections(
                            case=case,
                            db=db,
                            session_id=session_id,
                            iteration=1,
                            base_url="unused",
                            model="unused",
                            sections=[source],
                            progress_callback=None,
                            focus_sections=[],
                            allow_narration=False,
                        )
                    )

                initial = refresh()
                requests = {
                    item["block_heading"].split(": ", maxsplit=1)[0]: item
                    for item in initial["question_requests"]
                }
                self.assertEqual({item[0] for item in questions}, set(requests))
                state = SessionState(session_id=session_id)
                inject_gap_hypotheses(
                    db,
                    state,
                    [],
                    session_id,
                    question_requests=list(requests.values()),
                )

                def select_request(answer_id: str) -> dict:
                    request = requests[answer_id]
                    gap = db.execute(
                        "SELECT gap_id, description, block_heading "
                        "FROM report_gaps WHERE section_key = ? AND block_heading = ?",
                        [source.section_key, request["block_heading"]],
                    ).fetchone()
                    self.assertIsNotNone(gap)
                    key = answer_id.replace("-", "_")
                    candidate = {
                        "candidate_ref": f"candidate-{key}",
                        "candidate_fingerprint": f"candidate-fingerprint-{key}",
                        "title": request["question_text"],
                        "summary": "Explicit natural-language report question",
                        "scope": {},
                        "evidence_ids": [],
                        "rule_ids": [],
                    }
                    selected = {
                        "candidate": candidate,
                        "gap": {
                            "gap_id": gap[0],
                            "description": gap[1],
                            "block_heading": gap[2],
                        },
                        "input_fingerprint": f"input-fingerprint-{key}",
                        "attempt_number": 1,
                        "prior_attempts": {},
                    }
                    return selected

                def discovery_response(path: str, *, wrong_sql: bool = False) -> dict:
                    sql = "SELECT evidence_id, file_path, si_created, fn_created FROM mft_entries"
                    if wrong_sql:
                        sql += " WHERE evidence_id = 'mft-natural-distractor'"
                    return {
                        "request_contract": {
                            "status": "resolved",
                            "scope_filters": [
                                {
                                    "family": "mft",
                                    "field": "file_path",
                                    "operator": "equals",
                                    "value": path,
                                }
                            ],
                            "requirements": [
                                {
                                    "family": "mft",
                                    "field": "si_created",
                                    "kind": "observed_value",
                                }
                            ],
                        },
                        "action": {
                            "intent": f"Retrieve SI creation time for exact path {path}",
                            "target_table": "mft_entries",
                            "sql": sql,
                        },
                    }

                def evtx_discovery_response() -> dict:
                    return {
                        "request_contract": {
                            "status": "resolved",
                            "scope_filters": [
                                {
                                    "family": "evtx",
                                    "field": "event_id",
                                    "operator": "equals",
                                    "value": 9917,
                                }
                            ],
                            "requirements": [
                                {
                                    "family": "evtx",
                                    "field": "computer",
                                    "kind": "observed_value",
                                }
                            ],
                        },
                        "action": {
                            "intent": "Retrieve the computer recorded for exact EVTX event ID 9917",
                            "target_table": "evtx_events",
                            "sql": (
                                "SELECT evidence_id, event_id, computer FROM evtx_events "
                                "WHERE event_id = 9917"
                            ),
                        },
                    }

                def evtx_draft() -> dict:
                    return {
                        "hypothesis": {
                            "required_entities": ["computer"],
                            "source_rule_ids": [],
                            "confirm_when": {
                                "observation": {
                                    "family": "evtx",
                                    "capability": "logon",
                                    "field": "computer",
                                    "operator": "equals",
                                    "value": "ORCHID-7",
                                }
                            },
                        }
                    }

                def typed_draft(timestamp: str) -> dict:
                    return {
                        "hypothesis": {
                            "required_entities": ["si_created"],
                            "source_rule_ids": [],
                            "confirm_when": {
                                "observation": {
                                    "family": "mft",
                                    "capability": "file_activity",
                                    "field": "si_created",
                                    "operator": "equals",
                                    "value": timestamp,
                                }
                            },
                        }
                    }

                def refuted_discovery_response() -> dict:
                    path = r"C:\Users\Nora\Desktop\active.bin"
                    return {
                        "request_contract": {
                            "status": "resolved",
                            "scope_filters": [
                                {
                                    "family": "mft",
                                    "field": "file_path",
                                    "operator": "equals",
                                    "value": path,
                                }
                            ],
                            "requirements": [
                                {
                                    "family": "mft",
                                    "field": "is_deleted",
                                    "kind": "predicate",
                                    "operator": "equals",
                                    "value": True,
                                }
                            ],
                        },
                        "action": {
                            "intent": f"Check whether exact file {path} is deleted",
                            "target_table": "mft_entries",
                            "sql": (
                                "SELECT evidence_id, file_path, is_deleted "
                                "FROM mft_entries"
                            ),
                        },
                    }

                def partial_discovery_response() -> dict:
                    return {
                        "request_contract": {
                            "status": "resolved",
                            "scope_filters": [
                                {
                                    "family": "mft",
                                    "field": "file_path",
                                    "operator": "equals",
                                    "value": partial_target,
                                }
                            ],
                            "requirements": [
                                {
                                    "family": "mft",
                                    "field": "si_created",
                                    "kind": "observed_value",
                                },
                                {
                                    "family": "mft",
                                    "field": "is_deleted",
                                    "kind": "predicate",
                                    "operator": "equals",
                                    "value": True,
                                },
                            ],
                        },
                        "action": {
                            "intent": f"Check creation time and deletion state for {partial_target}",
                            "target_table": "mft_entries",
                            "sql": (
                                "SELECT evidence_id, file_path, si_created, is_deleted "
                                "FROM mft_entries"
                            ),
                        },
                    }

                ctx = _BroadPlanContext(
                    state=state,
                    db=db,
                    session_id=session_id,
                    base_url="unused",
                    model="unused",
                    plan_cycle=1,
                    observed_keypoints=[],
                    observed_keypoint_labels=[],
                    emit_fn=None,
                    llm_status_fn=lambda _message: None,
                    progress_callback=None,
                    case_profile=None,
                )

                unavailable = select_request("natural-missing-si")
                unavailable["candidate"].update(
                    {
                        "candidate_ref": "candidate-null-requested-observation",
                        "candidate_fingerprint": "fingerprint-null-requested-observation",
                        "scope": {"source_family": "evtx"},
                        "evidence": [
                            {
                                "evidence_id": "evtx-empty-user",
                                "_source": "evtx_events",
                                "event_id": 4624,
                                "user_name": None,
                                "target_user": "CORP\\analyst",
                            }
                        ],
                        "request_contract": {
                            "requirements": [
                                {
                                    "family": "evtx",
                                    "field": "user_name",
                                    "kind": "observed_value",
                                }
                            ]
                        },
                    }
                )
                unavailable["gap"].pop("block_heading")
                unavailable["input_fingerprint"] = "input-null-requested-observation"
                from forensia.investigation.investigation_cycle import (
                    _unobserved_requested_values,
                )

                unavailable["candidate"]["request_contract"]["requirements"].append(
                    {
                        "family": "evtx",
                        "field": "target_user",
                        "kind": "observed_value",
                    }
                )
                self.assertEqual(
                    [], _unobserved_requested_values(unavailable["candidate"])
                )
                unavailable["candidate"]["request_contract"]["requirements"].pop()
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=AssertionError(
                        "unavailable observation must not draft"
                    ),
                ) as no_draft_api:
                    unavailable_draft, unavailable_outcome = asyncio.run(
                        _draft_and_admit_candidate(ctx, unavailable, 99)
                    )
                self.assertIsNone(unavailable_draft)
                self.assertEqual(
                    "unresolved_observation", unavailable_outcome["status"]
                )
                self.assertIn("user_name", unavailable_outcome["reason"])
                self.assertEqual(0, unavailable_outcome["draft_calls_used"])
                self.assertEqual(0, no_draft_api.call_count)

                # Only discovery and draft model responses are mocked. The discovery SQL,
                # admission, typed verification, assessment, settlement, and projections run.
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[
                        discovery_response(target),
                        typed_draft(expected),
                    ],
                ):
                    draft, admitted = asyncio.run(
                        _draft_and_admit_candidate(
                            ctx, select_request("natural-positive"), 1
                        )
                    )
                self.assertEqual("admitted", admitted["status"], admitted)
                self.assertIsNotNone(draft)
                hypothesis = next(
                    item
                    for item in state.active_hypotheses
                    if item.source_gap_id
                    == select_request("natural-positive")["gap"]["gap_id"]
                )
                positive_gap_id = select_request("natural-positive")["gap"]["gap_id"]
                refresh()
                before_export = next(
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in (case.reports_dir / "structured").glob("*.json")
                    if json.loads(path.read_text(encoding="utf-8")).get("id")
                    and json.loads(path.read_text(encoding="utf-8")).get("gap_id")
                    == positive_gap_id
                )
                self.assertNotEqual("answered", before_export["status"])
                self.assertEqual([], before_export["answer"])
                self.assertNotIn("unassessed_candidates", before_export)

                # The missing SI field has only an FN creation time with a plausible
                # timestamp; returning it as SI must fail drafting and remain unanswered.
                missing_sel = select_request("natural-missing-si")
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[
                        discovery_response(missing_field_target),
                        typed_draft(wrong_field_value),
                        typed_draft(wrong_field_value),
                    ],
                ):
                    _, missing_outcome = asyncio.run(
                        _draft_and_admit_candidate(ctx, missing_sel, 2)
                    )
                self.assertNotEqual("admitted", missing_outcome["status"])

                # SQL may nominate the wrong record, but request-contract scoping must
                # leave no candidate and therefore no hypothesis to settle.
                wrong_target_response = discovery_response(wrong_target, wrong_sql=True)
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[
                        wrong_target_response,
                        {"action": wrong_target_response["action"]},
                    ],
                ) as request_model:
                    _, wrong_outcome = asyncio.run(
                        _draft_and_admit_candidate(
                            ctx, select_request("natural-wrong-target"), 3
                        )
                    )
                self.assertEqual("discovery_failed", wrong_outcome["status"])
                self.assertEqual(2, request_model.call_count)
                self.assertEqual(
                    "discovery_repeated_empty_query", wrong_outcome["reason"]
                )

                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=AssertionError(
                        "typed observation verification is deterministic"
                    ),
                ):
                    asyncio.run(
                        _investigate_one_hypothesis(
                            hypothesis=hypothesis,
                            state=state,
                            ctx=Ctx(),
                            db=db,
                            base_url="unused",
                            model="unused",
                            plan_cycle=1,
                            session_id=session_id,
                            max_queries_per_hypothesis=1,
                            case=case,
                            query_limit=1,
                        )
                    )

                settled = db.execute(
                    "SELECT status, verdict FROM hypotheses WHERE hypothesis_id = ?",
                    [hypothesis.id],
                ).fetchone()
                self.assertEqual(("confirmed", "confirmed"), settled)
                self.assertEqual(
                    ("open", "question_requirements_unverified"),
                    db.execute(
                        "SELECT status, coverage_reason FROM report_gaps WHERE gap_id = ?",
                        [positive_gap_id],
                    ).fetchone(),
                )
                self.assertIsNotNone(
                    db.execute(
                        "SELECT 1 FROM hypothesis_evidence WHERE hypothesis_id = ? "
                        "AND COALESCE(assessment_id, '') <> ''",
                        [hypothesis.id],
                    ).fetchone()
                )

                # One satisfied requirement is not enough to answer a two-part
                # question; the observed SI timestamp is exported as partial.
                partial_sel = select_request("natural-partial")
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[partial_discovery_response(), typed_draft(expected)],
                ):
                    partial_draft, partial_admission = asyncio.run(
                        _draft_and_admit_candidate(ctx, partial_sel, 5)
                    )
                self.assertIsNotNone(partial_draft)
                self.assertEqual("admitted", partial_admission["status"])
                partial_hypothesis = next(
                    item
                    for item in state.active_hypotheses
                    if item.source_gap_id == partial_sel["gap"]["gap_id"]
                )
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=AssertionError(
                        "typed observation verification is deterministic"
                    ),
                ):
                    asyncio.run(
                        _investigate_one_hypothesis(
                            hypothesis=partial_hypothesis,
                            state=state,
                            ctx=Ctx(),
                            db=db,
                            base_url="unused",
                            model="unused",
                            plan_cycle=1,
                            session_id=session_id,
                            max_queries_per_hypothesis=1,
                            case=case,
                            query_limit=1,
                        )
                    )
                gap_state = db.execute(
                    "SELECT status, coverage_reason FROM report_gaps WHERE gap_id = ?",
                    [partial_sel["gap"]["gap_id"]],
                ).fetchone()
                self.assertEqual(
                    ("open", "question_requirements_unverified"), gap_state
                )
                partial_link = db.execute(
                    "SELECT link_id, query_id FROM hypothesis_evidence "
                    "WHERE hypothesis_id = ? AND evidence_id = ? LIMIT 1",
                    [partial_hypothesis.id, "mft-natural-partial"],
                ).fetchone()
                self.assertIsNotNone(partial_link)
                for suffix in ("q2", "q3"):
                    db.execute(
                        "INSERT INTO hypothesis_evidence (link_id, hypothesis_id, "
                        "evidence_id, finding_id, query_id, assessment_id, role, "
                        "source_family, source_file, derivation_group, content_fingerprint, "
                        "verification_spec_fingerprint, assessment_reason, matched_conditions, "
                        "strength, created_session, created_at) "
                        "SELECT ?, hypothesis_id, evidence_id, finding_id, ?, assessment_id, "
                        "role, source_family, source_file, derivation_group, content_fingerprint, "
                        "verification_spec_fingerprint, assessment_reason, matched_conditions, "
                        "strength, created_session, created_at FROM hypothesis_evidence "
                        "WHERE link_id = ?",
                        [
                            f"duplicate-{suffix}",
                            f"{partial_hypothesis.id}-{suffix}",
                            partial_link[0],
                        ],
                    )
                refresh()
                partial_export = next(
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in (case.reports_dir / "structured").glob("*.json")
                    if json.loads(path.read_text(encoding="utf-8")).get("gap_id")
                    == partial_sel["gap"]["gap_id"]
                )
                self.assertEqual("partial", partial_export["status"])
                self.assertEqual(
                    1,
                    len(partial_export["answer"]),
                )
                partial_row = partial_export["answer"][0]
                self.assertEqual("mft-natural-partial", partial_row["evidence_id"])
                self.assertEqual("observed", partial_row["status"])
                self.assertEqual(
                    sorted(
                        [
                            partial_link[1],
                            f"{partial_hypothesis.id}-q2",
                            f"{partial_hypothesis.id}-q3",
                        ]
                    ),
                    partial_row["query_ids"],
                )
                self.assertEqual(
                    partial_row["query_ids"],
                    sorted(partial_export["queries_run"]),
                )
                self.assertTrue(partial_export["missing_reason"])
                from forensia.report.answers.answer_store import (
                    render_structured_answer_markdown,
                )

                partial_markdown = render_structured_answer_markdown(
                    partial_export, "Partial answer"
                )
                self.assertIn("### Observed evidence", partial_markdown)
                self.assertIn("do not establish the requested answer", partial_markdown)
                self.assertNotIn("table supports the answer", partial_markdown)

                # A natural question that asks for is_deleted=true must be refuted
                # by the matching MFT row's canonical false value.
                refuted_sel = select_request("natural-refuted")
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[
                        refuted_discovery_response(),
                        {
                            "hypothesis": {
                                "required_entities": ["is_deleted"],
                                "source_rule_ids": [],
                                "confirm_when": {
                                    "observation": {
                                        "family": "mft",
                                        "capability": "file_activity",
                                        "field": "is_deleted",
                                        "operator": "equals",
                                        "value": True,
                                    }
                                },
                                "refute_when": {
                                    "observation": {
                                        "family": "mft",
                                        "capability": "file_activity",
                                        "field": "is_deleted",
                                        "operator": "equals",
                                        "value": False,
                                    }
                                },
                            }
                        },
                    ],
                ):
                    refuted_draft, refuted_admission = asyncio.run(
                        _draft_and_admit_candidate(ctx, refuted_sel, 4)
                    )
                self.assertIsNotNone(refuted_draft)
                self.assertEqual("admitted", refuted_admission["status"])
                refuted_hypothesis = next(
                    item
                    for item in state.active_hypotheses
                    if item.source_gap_id == refuted_sel["gap"]["gap_id"]
                )
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    return_value={
                        "action": {
                            "intent": "Retrieve canonical deletion state for the exact file",
                            "target_table": "mft_entries",
                            "template_id": None,
                            "sql": (
                                "SELECT evidence_id, file_path, is_deleted "
                                "FROM mft_entries "
                                "WHERE evidence_id = 'mft-natural-refuted'"
                            ),
                        }
                    },
                ):
                    asyncio.run(
                        _investigate_one_hypothesis(
                            hypothesis=refuted_hypothesis,
                            state=state,
                            ctx=Ctx(),
                            db=db,
                            base_url="unused",
                            model="unused",
                            plan_cycle=1,
                            session_id=session_id,
                            max_queries_per_hypothesis=2,
                            case=case,
                            query_limit=2,
                        )
                    )
                self.assertEqual(
                    ("refuted", "refuted"),
                    db.execute(
                        "SELECT status, verdict FROM hypotheses WHERE hypothesis_id = ?",
                        [refuted_hypothesis.id],
                    ).fetchone(),
                )
                refresh()
                refuted_export = next(
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in (case.reports_dir / "structured").glob("*.json")
                    if json.loads(path.read_text(encoding="utf-8")).get("gap_id")
                    == refuted_sel["gap"]["gap_id"]
                )
                self.assertEqual("answered", refuted_export["status"])
                self.assertEqual(
                    ["mft-natural-refuted"],
                    [row["evidence_id"] for row in refuted_export["answer"]],
                )
                self.assertFalse(refuted_export["answer"][0]["is_deleted"])

                refresh()
                answer_path = next(
                    path
                    for path in (case.reports_dir / "structured").glob("*.json")
                    if json.loads(path.read_text(encoding="utf-8")).get("gap_id")
                    == positive_gap_id
                )
                answer = json.loads(answer_path.read_text(encoding="utf-8"))
                self.assertEqual("partial", answer["status"])
                self.assertEqual(expected, answer["answer"][0]["si_created"])
                answer_ids = {row["evidence_id"] for row in answer["answer"]}
                candidate_ids = {
                    row["evidence_id"] for row in answer["unassessed_candidates"]
                }
                receipt_output = db.execute(
                    "SELECT output_json FROM trace.investigation_steps "
                    "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
                    [answer["candidate_search"]["discovery_step_id"]],
                ).fetchone()[0]
                if isinstance(receipt_output, str):
                    receipt_output = json.loads(receipt_output)
                receipt_ids = set(receipt_output["scoped_evidence_ids"])
                self.assertTrue(answer_ids.isdisjoint(candidate_ids))
                self.assertEqual(receipt_ids, answer_ids | candidate_ids)
                self.assertEqual(5, len(receipt_ids))
                self.assertTrue(
                    all(
                        row["discovery_step_id"]
                        == answer["candidate_search"]["discovery_step_id"]
                        for row in answer["unassessed_candidates"]
                    )
                )
                with (case.reports_dir / answer["unassessed_candidates_csv_path"]).open(
                    encoding="utf-8", newline=""
                ) as candidate_file:
                    candidate_csv = list(csv.DictReader(candidate_file))
                self.assertEqual(
                    candidate_ids, {row["evidence_id"] for row in candidate_csv}
                )
                csv_text = (case.reports_dir / answer["csv_path"]).read_text(
                    encoding="utf-8"
                )
                self.assertIn(expected, csv_text)
                self.assertIn("mft-natural-positive", csv_text)
                self.assertEqual(
                    receipt_output["sql"], answer["candidate_search"]["sql"]
                )
                discovery_step_id = answer["candidate_search"]["discovery_step_id"]
                original_trace_row = db.execute(
                    "SELECT output_json FROM trace.investigation_steps "
                    "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
                    [discovery_step_id],
                ).fetchone()
                self.assertIsNotNone(original_trace_row)
                original_receipt = original_trace_row[0]
                if isinstance(original_receipt, str):
                    original_receipt = json.loads(original_receipt)

                # A receipt ID whose live path leaves the recorded scope is removed
                # from both the assessed answer and the candidate projection.
                out_of_scope_id = "mft-natural-positive-extra-2"
                db.execute(
                    "UPDATE mft_entries SET file_path = ? WHERE evidence_id = ?",
                    [r"E:\Other\unrelated.bin", out_of_scope_id],
                )
                refresh()
                scoped_export = json.loads(answer_path.read_text(encoding="utf-8"))
                self.assertNotIn(
                    out_of_scope_id,
                    {row["evidence_id"] for row in scoped_export["answer"]}
                    | {
                        row["evidence_id"]
                        for row in scoped_export.get("unassessed_candidates", [])
                    },
                )
                db.execute(
                    "UPDATE mft_entries SET file_path = ? WHERE evidence_id = ?",
                    [target, out_of_scope_id],
                )

                # A receipt whose contract no longer hashes to its contract ID
                # cannot supply candidates or answer rows.
                tampered_receipt = dict(original_receipt)
                tampered_contract = dict(tampered_receipt["request_contract"])
                tampered_requirements = list(tampered_contract["requirements"])
                tampered_requirements[0] = dict(tampered_requirements[0])
                tampered_requirements[0]["field"] = "fn_created"
                tampered_contract["requirements"] = tampered_requirements
                tampered_receipt["request_contract"] = tampered_contract
                db.execute(
                    "UPDATE trace.investigation_steps SET output_json = ? "
                    "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
                    [json.dumps(tampered_receipt), discovery_step_id],
                )
                refresh()
                tampered_export = json.loads(answer_path.read_text(encoding="utf-8"))
                self.assertEqual([], tampered_export["answer"])
                self.assertEqual([], tampered_export.get("unassessed_candidates", []))
                db.execute(
                    "UPDATE trace.investigation_steps SET output_json = ? "
                    "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
                    [json.dumps(original_receipt), discovery_step_id],
                )
                refresh()
                truncated_receipt = dict(original_receipt)
                truncated_receipt["truncated"] = True
                db.execute(
                    "UPDATE trace.investigation_steps SET output_json = ? "
                    "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
                    [json.dumps(truncated_receipt), discovery_step_id],
                )
                refresh()
                truncated_export = json.loads(answer_path.read_text(encoding="utf-8"))
                self.assertEqual("partial", truncated_export["status"])
                self.assertTrue(truncated_export["candidate_search"]["query_truncated"])
                self.assertEqual(4, len(truncated_export["unassessed_candidates"]))
                db.execute(
                    "UPDATE trace.investigation_steps SET output_json = ? "
                    "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
                    [json.dumps(original_receipt), discovery_step_id],
                )
                refresh()

                evtx_sel = select_request("natural-evtx")
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[evtx_discovery_response(), evtx_draft()],
                ):
                    evtx_draft_hypothesis, evtx_admission = asyncio.run(
                        _draft_and_admit_candidate(ctx, evtx_sel, 6)
                    )
                self.assertIsNotNone(evtx_draft_hypothesis)
                self.assertEqual("admitted", evtx_admission["status"], evtx_admission)
                evtx_hypothesis = next(
                    item
                    for item in state.active_hypotheses
                    if item.id == evtx_admission["admitted_hypothesis_id"]
                )
                with patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=AssertionError(
                        "EVTX observation verification is deterministic"
                    ),
                ):
                    asyncio.run(
                        _investigate_one_hypothesis(
                            hypothesis=evtx_hypothesis,
                            state=state,
                            ctx=Ctx(),
                            db=db,
                            base_url="unused",
                            model="unused",
                            plan_cycle=1,
                            session_id=session_id,
                            max_queries_per_hypothesis=1,
                            case=case,
                            query_limit=1,
                        )
                    )
                evtx_gap_id = evtx_sel["gap"]["gap_id"]
                refresh()
                evtx_export = next(
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in (case.reports_dir / "structured").glob("*.json")
                    if json.loads(path.read_text(encoding="utf-8")).get("gap_id")
                    == evtx_gap_id
                )
                self.assertEqual("answered", evtx_export["status"])
                self.assertEqual(
                    ["evtx-natural-question"],
                    [row["evidence_id"] for row in evtx_export["answer"]],
                )
                self.assertEqual("ORCHID-7", evtx_export["answer"][0]["computer"])
                evtx_csv = (case.reports_dir / evtx_export["csv_path"]).read_text(
                    encoding="utf-8"
                )
                self.assertIn("evtx-natural-question", evtx_csv)
                self.assertNotIn("evtx-natural-distractor", evtx_csv)
                with settings_scope(Settings(llm_output_language="en")):
                    markdown_path, html_path = render_written_report(case, db)
                markdown = markdown_path.read_text(encoding="utf-8")
                html_text = html_path.read_text(encoding="utf-8")
                self.assertIn(expected, markdown)
                self.assertIn(expected, html_text)
                self.assertIn(target, markdown)
                self.assertIn(target, html_text)
                self.assertIn("ORCHID-7", markdown)
                self.assertIn("evtx-natural-question", markdown)
                self.assertIn("ORCHID-7", html_text)
                self.assertIn("evtx-natural-question", html_text)

                # A changed assessed row and a newly added exact-scope row invalidate
                # the discovery/assessment coverage before the next export.
                db.execute(
                    "UPDATE mft_entries SET si_created = ? "
                    "WHERE evidence_id = 'mft-natural-positive'",
                    [datetime.fromisoformat("2041-09-23 14:07:37")],
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, source_file, record_number, "
                    "file_path, file_name, si_created) VALUES "
                    "('mft-natural-added', 'synthetic-mft-question-source', 4, ?, "
                    "'meteor.bin', ?)",
                    [target, datetime.fromisoformat(expected)],
                )
                refresh()
                stale_checked = json.loads(answer_path.read_text(encoding="utf-8"))
                self.assertNotEqual("answered", stale_checked["status"])
                self.assertNotIn(
                    expected,
                    [row.get("si_created") for row in stale_checked["answer"]],
                )

                # Unlinked/no-match and field-mismatch questions never receive the
                # positive row through their own structured exports.
                for answer_id in (
                    "natural-missing-si",
                    "natural-wrong-target",
                ):
                    negative_gap_id = select_request(answer_id)["gap"]["gap_id"]
                    negative_path = next(
                        path
                        for path in (case.reports_dir / "structured").glob("*.json")
                        if json.loads(path.read_text(encoding="utf-8")).get("gap_id")
                        == negative_gap_id
                    )
                    negative = json.loads(negative_path.read_text(encoding="utf-8"))
                    self.assertNotEqual("answered", negative["status"])
                    self.assertNotIn(
                        expected,
                        [
                            str(value)
                            for row in negative["answer"]
                            for value in row.values()
                        ],
                    )

    def test_host_execution_keypoint_requires_event_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                events = [
                    (
                        4104,
                        "Application",
                        "Microsoft-Windows-Winlogon",
                        "wrong-channel",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-Winlogon",
                        "wrong-provider",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-PowerShell",
                        "powershell-event",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        None,
                        "missing-provider",
                    ),
                    (
                        4688,
                        "Security",
                        "Microsoft-Windows-Security-Auditing",
                        "process-event",
                    ),
                ]
                for index, (event_id, channel, provider, evidence_id) in enumerate(
                    events
                ):
                    raw_json = json.dumps(
                        {"winlog": {"provider": {"name": provider}}}
                        if provider
                        else {"winlog": {}}
                    )
                    db.execute(
                        """
                        INSERT INTO evtx_events (
                            evidence_id, event_id, channel, timestamp, computer,
                            process_name, raw_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"evtx-{index}",
                            event_id,
                            channel,
                            datetime(2015, 3, 22, 14, index),
                            "PC-01",
                            evidence_id,
                            raw_json,
                        ),
                    )

                result = resolve_evidence_results(
                    db, keypoints=["host_execution_activity"]
                )[0]

            self.assertEqual(2, result["row_count"])
            self.assertEqual(
                {"powershell-event", "process-event"},
                {row["process_name"] for row in result["sample_rows"]},
            )

    def test_keypoints_retain_domain_catalog_without_answer_specific_route(
        self,
    ) -> None:
        from forensia.knowledge.questions import question_spec_for_answer_spec

        self.assertIsNone(question_spec_for_answer_spec("resignation_file_timestamps"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name) VALUES (?, ?, ?)",
                    (
                        "mft-cloud-config",
                        r"C:\Users\Nora\AppData\Local\Google\Drive\sync_config.db",
                        "sync_config.db",
                    ),
                )
                result = resolve_evidence_results(
                    db, keypoints=["structured_cloud_artifacts"]
                )[0]
        self.assertGreaterEqual(result["row_count"], 1)

    def test_generic_answer_waits_for_question_specific_investigation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for user, name in (("Alice", "alice.ost"), ("Bob", "bob.ost")):
                    db.execute(
                        "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension) VALUES (?, ?, ?, ?)",
                        (
                            f"mft-{user.lower()}",
                            rf"C:\Users\{user}\Outlook\{name}",
                            name,
                            "ost",
                        ),
                    )
                inventory = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_data_files",
                    answer_id="alice-mail-scope",
                    section_key="6_appendix",
                    block_heading="Mail data files",
                )
                self.assertEqual("answered", inventory["status"])
                self.assertEqual(2, len(inventory["answer"]))
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_data_files",
                    answer_id="alice-mail-scope",
                    section_key="6_appendix",
                    block_heading="Mail data files",
                    question_text="List Alice's mail files",
                )
            self.assertEqual("not_searched", answer["status"])
            self.assertEqual([], answer["answer"])
            self.assertEqual("List Alice's mail files", answer["question_text"])
            exported = json.loads(
                (case.reports_dir / "structured" / "alice-mail-scope.json").read_text()
            )
            self.assertEqual("not_searched", exported["status"])
            self.assertEqual("List Alice's mail files", exported["question_text"])
            csv_export = (case.reports_dir / exported["csv_path"]).read_text()
            self.assertIn("evidence_ids", csv_export)
            self.assertNotIn("alice.ost", csv_export)
            self.assertNotIn("bob.ost", csv_export)
            with CaseDB(case) as db:
                build_structured_answer(
                    case,
                    db,
                    answer_spec="email_data_files",
                    answer_id="alice-mail-scope",
                    section_key="6_appendix",
                    block_heading="Mail data files",
                )
                unresolved = build_structured_answer(
                    case,
                    db,
                    answer_spec="",
                    answer_id="alice-mail-scope",
                    section_key="6_appendix",
                    block_heading="Unresolved file question",
                    question_text="Timestamps for harvest.ods",
                )
            self.assertEqual("not_searched", unresolved["status"])
            self.assertEqual(
                "description,status,summary,evidence_ids,query_ids",
                (case.reports_dir / unresolved["csv_path"]).read_text().strip(),
            )

    def test_report_heading_only_scope_is_unresolved(self) -> None:
        from forensia.report.sections.section_refresher import _block_projection

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for user, name in (("Alice", "alice.ost"), ("Bob", "bob.ost")):
                    db.execute(
                        "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension) VALUES (?, ?, ?, ?)",
                        (
                            f"mft-{user.lower()}",
                            rf"C:\Users\{user}\Outlook\{name}",
                            name,
                            "ost",
                        ),
                    )
                _markdown, _results, projection = _block_projection(
                    case,
                    db,
                    "6_appendix",
                    {
                        "heading": "List Alice's mail files",
                        "mode": "question",
                        "answer_spec": "email_data_files",
                    },
                )
                db.execute(
                    "INSERT INTO findings (finding_id, title, status) VALUES ('F-unrelated', 'Unrelated evidence', 'accepted')"
                )
                _, _, other_projection = _block_projection(
                    case,
                    db,
                    "6_appendix",
                    {
                        "heading": "List Bob's mail files",
                        "mode": "question",
                        "answer_spec": "email_data_files",
                    },
                )
                arbitrary_markdown, _results, arbitrary_projection = _block_projection(
                    case,
                    db,
                    "6_appendix",
                    {
                        "heading": "Show timestamps for quarterly_budget.xlsx",
                        "mode": "question",
                    },
                )
            self.assertEqual("not_searched", projection["answer"]["status"])
            self.assertEqual([], projection["answer"]["answer"])
            self.assertNotEqual(
                projection["answer"]["id"], other_projection["answer"]["id"]
            )
            first_export = json.loads(
                (case.reports_dir / projection["answer"]["json_path"]).read_text()
            )
            self.assertIn("Alice", first_export["question_text"])
            self.assertNotIn("Bob", first_export["question_text"])
            self.assertEqual("not_searched", arbitrary_projection["answer"]["status"])
            self.assertEqual([], arbitrary_projection["answer"]["answer"])
            self.assertIn("no current assessed result", arbitrary_markdown.lower())
            self.assertNotIn("Unrelated evidence", arbitrary_markdown)

    def test_email_data_files_uses_question_spec_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension,
                        si_created, si_modified
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000004-01",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 25, 14, 10, 0),
                        datetime(2015, 3, 25, 14, 20, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension) VALUES (?, ?, ?, ?)",
                    ("mft-bob", r"C:\Users\Bob\Outlook\bob.ost", "bob.ost", "ost"),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_data_files",
                    answer_id="Q-email",
                    section_key="6_appendix",
                    block_heading="Email data files",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(["structured:email_data_files:mft"], answer["queries_run"])
            self.assertEqual(
                {"mailbox.ost", "bob.ost"},
                {row["file_name"] for row in answer["answer"]},
            )

    def test_email_application_usage_uses_question_spec_catalog_label(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000005-01",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 25, 14, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_application_usage",
                    answer_id="Q-email-app",
                    section_key="6_appendix",
                    block_heading="Email application",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(
                "Microsoft Outlook", answer["answer"][0].get("application_name")
            )

    def test_email_application_usage_ranks_stationery_after_mail_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index in range(35):
                    db.execute(
                        """
                        INSERT INTO mft_entries (
                            evidence_id, file_path, file_name, extension, si_modified
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            f"mft-stationery-{index:04d}",
                            rf"C:\Users\Alice\AppData\Local\Microsoft\Windows Mail\Stationery\image-{index}.jpg",
                            f"image-{index}.jpg",
                            "jpg",
                            datetime(2015, 3, 25, 15, index % 60, 0),
                        ),
                    )
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-mailbox-priority",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 20, 12, 0, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_application_usage",
                    answer_id="Q-email-app-ranked",
                    section_key="6_appendix",
                    block_heading="Email application",
                )

            self.assertEqual(
                "mailbox.ost", answer["answer"][0]["artifact_path"].rsplit("\\", 1)[-1]
            )

    def test_structured_benchmark_last_logon_persists_json_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, event_id, channel, timestamp, computer, target_user,
                        logon_type, process_name, src_ip, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        4624,
                        "Security",
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                        "informant",
                        "2",
                        r"C:\Windows\System32\winlogon.exe",
                        "127.0.0.1",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="last_human_logon",
                    answer_id="Q8",
                    section_key="6_appendix",
                    block_heading="2. Last logged-on user",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("answered", answer["status"])
            self.assertEqual(
                [
                    "logon_time",
                    "computer",
                    "user_name",
                    "logon_type",
                    "process_name",
                    "src_ip",
                    "evidence_id",
                ],
                answer["columns"],
            )
            self.assertEqual("informant", answer["answer"][0]["user_name"])
            self.assertIn("2015-03-22T14:34:28", answer["answer"][0]["logon_time"])
            self.assertTrue((case.reports_dir / "structured" / "Q8.csv").exists())
            answer_path = case.reports_dir / answer["json_path"]
            self.assertTrue(answer_path.exists())
            self.assertEqual(
                "Q8", json.loads(answer_path.read_text(encoding="utf-8"))["id"]
            )

    def test_structured_benchmark_last_shutdown_ignores_overall_last_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, channel, timestamp, computer, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-000000000001",
                        6006,
                        "System",
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                        '{"winlog":{"provider":{"name":"EventLog"}}}',
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, channel, timestamp, computer, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-wrong-context",
                        6006,
                        "Application",
                        datetime(2015, 3, 24, 14, 38, 16),
                        "informant-PC",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Winlogon"}}}',
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000002",
                        4624,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="last_shutdown_event",
                    answer_id="Q9",
                    section_key="6_appendix",
                    block_heading="3. Last shutdown time",
                )

            self.assertIsNotNone(answer)
            self.assertEqual(6006, answer["answer"][0]["event_id"])
            self.assertIn("2015-03-22T14:38:16", answer["answer"][0]["shutdown_time"])

    def test_structured_benchmark_antiforensics_filters_noise_across_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        "Security",
                        1100,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000002",
                        "Security",
                        1102,
                        datetime(2015, 3, 25, 15, 32, 0),
                        "informant-PC",
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000003",
                        "Security",
                        1100,
                        datetime(2015, 3, 25, 15, 33, 0),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "UPDATE evtx_events SET raw_json = ? WHERE event_id IN (1100, 1102)",
                    ('{"winlog":{"provider":{"name":"Microsoft-Windows-Eventlog"}}}',),
                )
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name, exec_count, last_exec_time) VALUES (?, ?, ?, ?)",
                    (
                        "prefetch-privazer-exe-0001",
                        "PrivaZer.exe",
                        1,
                        datetime(2015, 3, 25, 15, 40, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
                        "Program Files/CCleaner/Lang/lang-1041.dll",
                        "lang-1041.dll",
                        datetime(2015, 3, 13, 13, 54, 32),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
                        "Windows/Prefetch/CCLEANER64.EXE-779BD542.pf",
                        "CCLEANER64.EXE-779BD542.pf",
                        datetime(2015, 3, 25, 15, 15, 50),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000003-00",
                        "Windows/System32/cipher.exe",
                        "cipher.exe",
                        datetime(2009, 7, 14, 1, 38, 59),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000004-00",
                        "Program Files/CCleaner/CCleaner64.exe",
                        "CCleaner64.exe",
                        datetime(2015, 3, 13, 11, 10, 26),
                    ),
                )
                for evidence_id, path, name in (
                    ("mft-google-note", "Users/Alice/Google/notes.txt", "notes.txt"),
                    ("mft-mail-file", "Users/Alice/Outlook/alpha.ost", "alpha.ost"),
                ):
                    db.execute(
                        "INSERT INTO mft_entries (evidence_id, file_path, file_name, is_deleted) VALUES (?, ?, ?, false)",
                        (evidence_id, path, name),
                    )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="antiforensic_activity",
                    answer_id="Q45",
                    section_key="6_appendix",
                    block_heading="12. Antiforensic activity",
                )

            evidence_ids = {row.get("evidence_id") for row in answer["answer"]}
            self.assertEqual(
                {
                    "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
                    "prefetch-privazer-exe-0001",
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000002",
                },
                evidence_ids,
            )
            self.assertEqual("answered", answer["status"])
            self.assertNotIn("mft-google-note", evidence_ids)
            self.assertNotIn("mft-mail-file", evidence_ids)
            event_ids = {
                row.get("event_id")
                for row in answer["answer"]
                if row.get("event_id") is not None
            }
            self.assertEqual({1102}, event_ids)

    def test_structured_benchmark_prefetch_fallback_excludes_non_pf_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
                        "Windows/Prefetch/PfSvPerfStats.bin",
                        "PfSvPerfStats.bin",
                        "bin",
                        datetime(2015, 3, 25, 15, 31, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
                        "Windows/Prefetch/WINWORD.EXE-CECBA770.pf",
                        "WINWORD.EXE-CECBA770.pf",
                        "pf",
                        datetime(2015, 3, 25, 15, 30, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="application_execution_history",
                    answer_id="Q12",
                    section_key="6_appendix",
                    block_heading="4. Application execution history",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("partial", answer["status"])
            self.assertEqual(
                ["WINWORD.EXE"], [row["executable_name"] for row in answer["answer"]]
            )

    def test_structured_desktop_rename_does_not_infer_recent_lnk_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/pricing decision.lnk",
                        "pricing decision.lnk",
                        datetime(2015, 3, 23, 20, 26, 54),
                        datetime(2015, 3, 23, 20, 26, 54),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/(secret_project)_pricing_decision.xlsx.lnk",
                        "(secret_project)_pricing_decision.xlsx.lnk",
                        datetime(2015, 3, 23, 20, 26, 53),
                        datetime(2015, 3, 23, 20, 26, 53),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="desktop_rename_candidates",
                    answer_id="Q24",
                    section_key="6_appendix",
                    block_heading="Desktop file renames",
                )

            self.assertEqual("unobservable", answer["status"])
            self.assertEqual([], answer["answer"])

    def test_citation_gate_accepts_evtx_and_mft_evidence_ids(self) -> None:
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        body = (
            "This may indicate suspicious activity supported by "
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001 and mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-01."
        )
        msg, score = check_hedge_no_citation(body, ctx)
        self.assertIsNone(msg)
        msg, score = check_citation_token_no_finding_id(body, ctx)
        self.assertIsNone(msg)

    def test_citation_gate_flags_citation_token_without_ids(self) -> None:
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        body = "The evidence suggests an incident, but the narrative does not name a concrete citation."
        msg, score = check_citation_token_no_finding_id(body, ctx)
        self.assertIsNotNone(msg)

    def test_prefetch_evidence_ids_validate_against_prefetch_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) VALUES (?, ?)",
                    (
                        "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-winword-exe-cecba770",
                        "WINWORD.EXE",
                    ),
                )
                missing = validate_body_evidence_ids(
                    db,
                    "WINWORD execution is supported by prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-winword-exe-cecba770.",
                )

            self.assertEqual([], missing)

    def test_validate_section_evidence_ids_removes_fabricated_keeps_real(self) -> None:
        """Real evidence IDs stay cited while fabricated IDs are removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                    ),
                )
                body = (
                    "The real event evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001 supported by evidence. "
                    "The fabricated event （evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999） not in DB. "
                    "Another fabricated one (mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-999999999999-99) also not present."
                )
                cleaned, gaps = validate_section_evidence_ids(db, body)

                self.assertIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                    cleaned,
                )
                self.assertNotIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
                    cleaned,
                )
                self.assertNotIn("security-999999999999", cleaned)
                self.assertNotIn(
                    "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-999999999999-99",
                    cleaned,
                )
                self.assertNotIn("（）", cleaned)
                self.assertNotIn("()", cleaned)
                self.assertNotIn("（,", cleaned)
                self.assertTrue(
                    any(
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999"
                        in g
                        for g in gaps
                    ),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertTrue(
                    any(
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-999999999999-99"
                        in g
                        for g in gaps
                    ),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertFalse(
                    any(
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001"
                        in g
                        for g in gaps
                    ),
                    msg=f"real ID in gaps: {gaps}",
                )

    def test_validate_section_evidence_ids_keeps_valid_id_sharing_parens_with_invalid(
        self,
    ) -> None:
        """Removing invalid IDs must not remove valid IDs from the same citation group."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122",
                        4648,
                        datetime(2015, 3, 22, 15, 57, 54),
                        "informant-PC",
                    ),
                )
                body = (
                    "Invalid first （evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999, evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122） here. "
                    "Invalid last (evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122, evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bogus-999999999999) there."
                )
                cleaned, _gaps = validate_section_evidence_ids(db, body)

                self.assertIn(
                    "（evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122）",
                    cleaned,
                )
                self.assertIn(
                    "(evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122)",
                    cleaned,
                )
                self.assertNotIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
                    cleaned,
                )
                self.assertNotIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bogus-999999999999",
                    cleaned,
                )


class DailySessionTimelineBuilderTests(unittest.TestCase):
    """Daily session timeline answer builder over evtx event classes."""

    def test_load_event_class_definitions(self):
        classes = load_event_class_definitions()
        self.assertIn("startup", classes)
        self.assertIn("shutdown", classes)
        self.assertIn("logon", classes)
        self.assertIn("logoff", classes)
        self.assertEqual(classes["startup"]["event_ids"], [6005, 12])
        self.assertEqual(classes["shutdown"]["event_ids"], [6006, 13, 1074])
        # 4648 (explicit credential use) is deliberately NOT in the logon
        # class: session/daily-timeline builders count logons from this class,
        # and explicit credential use is not a logon. It lives in the separate
        # explicit_credential class consumed by auth-pattern code paths.
        self.assertEqual(classes["logon"]["event_ids"], [4624])
        self.assertEqual(classes["explicit_credential"]["event_ids"], [4648])
        self.assertEqual(classes["logon"]["logon_types"], [2, 10, 11])
        self.assertEqual(classes["logoff"]["event_ids"], [4634, 4647])

    def test_builder_with_empty_db_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="daily_session_timeline",
                    answer_id="daily",
                    section_key="2_timeline",
                    block_heading="Daily session timeline",
                )
                self.assertEqual(answer["answer"], [])
                self.assertEqual(answer["status"], "not_found")

    def test_builder_returns_correct_shape_over_two_days(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Day 1: 2015-03-22
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e1",
                        6005,
                        datetime(2015, 3, 22, 8, 0, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e2",
                        4624,
                        datetime(2015, 3, 22, 8, 15, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e3",
                        4624,
                        datetime(2015, 3, 22, 9, 0, 0),
                        "HOST1",
                        "bob",
                        "10",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e4",
                        4634,
                        datetime(2015, 3, 22, 17, 0, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e5",
                        1074,
                        datetime(2015, 3, 22, 17, 30, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )

                # Day 2: 2015-03-23
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e6",
                        12,
                        datetime(2015, 3, 23, 7, 45, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e7",
                        4624,
                        datetime(2015, 3, 23, 8, 5, 0),
                        "HOST1",
                        "charlie",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e8",
                        4647,
                        datetime(2015, 3, 23, 16, 45, 0),
                        "HOST1",
                        "charlie",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e9",
                        6006,
                        datetime(2015, 3, 23, 17, 0, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    """
                    UPDATE evtx_events
                    SET channel = CASE WHEN event_id IN (6005, 6006, 6008, 12, 13, 1074) THEN 'System' ELSE 'Security' END,
                        raw_json = CASE
                          WHEN event_id IN (6005, 6006, 6008) THEN '{"winlog":{"provider":{"name":"EventLog"}}}'
                          WHEN event_id IN (12, 13) THEN '{"winlog":{"provider":{"name":"Microsoft-Windows-Kernel-General"}}}'
                          WHEN event_id = 1074 THEN '{"winlog":{"provider":{"name":"User32"}}}'
                          ELSE '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}'
                        END
                    WHERE event_id IN (6005, 6006, 6008, 12, 13, 4624, 4634, 4647, 1074)
                    """
                )

                rows = build_structured_answer(
                    case,
                    db,
                    answer_spec="daily_session_timeline",
                    answer_id="daily",
                    section_key="2_timeline",
                    block_heading="Daily session timeline",
                )["answer"]

        self.assertEqual(len(rows), 2)

        day1 = rows[0]
        self.assertEqual(day1["date"], "2015-03-22")
        self.assertEqual(day1["first_startup"], "2015-03-22 08:00:00")
        self.assertEqual(day1["first_logon"], "2015-03-22 08:15:00")
        self.assertEqual(day1["last_logoff"], "2015-03-22 17:00:00")
        self.assertEqual(day1["last_shutdown"], "2015-03-22 17:30:00")
        self.assertIn("alice", day1["logon_users"])
        self.assertIn("bob", day1["logon_users"])
        self.assertEqual(day1["interactive_logon_count"], 2)
        self.assertEqual(
            set(day1["evidence_ids"]),
            {"evtx-e1", "evtx-e2", "evtx-e3", "evtx-e4", "evtx-e5"},
        )
        self.assertEqual(len(day1["event_trace"]), 5)
        self.assertIn("UTC event_id=", day1["event_trace"][0])

        day2 = rows[1]
        self.assertEqual(day2["date"], "2015-03-23")
        self.assertEqual(day2["first_startup"], "2015-03-23 07:45:00")
        self.assertEqual(day2["first_logon"], "2015-03-23 08:05:00")
        self.assertEqual(day2["last_logoff"], "2015-03-23 16:45:00")
        self.assertEqual(day2["last_shutdown"], "2015-03-23 17:00:00")
        self.assertIn("charlie", day2["logon_users"])
        self.assertEqual(day2["interactive_logon_count"], 1)

    def test_direct_timeline_builder_respects_scope_timezone_and_references(self):
        from forensia.report.answers.answer_builders_host import (
            _build_daily_session_timeline,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir, source_timezone="America/New_York")
            with CaseDB(case) as db:
                times = [
                    "2015-01-22 13:30:00",
                    "2015-01-22 14:30:00",
                    "2015-03-22 12:59:59",
                    "2015-03-22 13:00:00",
                    "2015-03-22 22:00:00",
                    "2015-03-22 22:00:01",
                    "2015-03-23 13:00:00",
                    "2015-03-22 09:00:00",
                    "2015-03-23 03:00:00",
                ]
                ids = [f"evtx-{'a' * 64}-security-{i:012d}" for i in range(len(times))]
                for evidence_id, timestamp in zip(ids, times, strict=True):
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type, channel, raw_json) VALUES (?, 4624, ?, 'HOST1', 'alice', '2', 'Security', ?)",
                        (
                            evidence_id,
                            timestamp,
                            '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                        ),
                    )
                answer = _build_daily_session_timeline(
                    case,
                    db,
                    "daily",
                    "timeline",
                    "session",
                    "Consider only between 09:00 and 18:00 local time, between 2015-01-22 and 2015-03-22.",
                )
                rows = answer["answer"]
                self.assertEqual("answered", answer["status"])
                self.assertEqual(
                    ["2015-01-22", "2015-03-22"], [row["date"] for row in rows]
                )
                self.assertEqual("2015-01-22 14:30:00", rows[0]["first_logon"])
                self.assertEqual("2015-01-22 09:30:00", rows[0]["first_logon_local"])
                self.assertEqual("2015-03-22 13:00:00", rows[1]["first_logon"])
                self.assertEqual(
                    {ids[1], ids[3], ids[4]},
                    set(rows[0]["evidence_ids"] + rows[1]["evidence_ids"]),
                )
                self.assertEqual(2, len(rows[1]["event_trace"]))

                overnight = _build_daily_session_timeline(
                    case,
                    db,
                    "night",
                    "timeline",
                    "session",
                    "between 22:00 and 06:00 local time, between 2015-03-22 and 2015-03-22.",
                )
                self.assertEqual(
                    {ids[7], ids[8]}, set(overnight["answer"][0]["evidence_ids"])
                )

                case.source_timezone = "UTC"
                unresolved = _build_daily_session_timeline(
                    case,
                    db,
                    "unknown-tz",
                    "timeline",
                    "session",
                    "between 09:00 and 18:00 local time, between 2015-01-22 and 2015-03-22.",
                )
                self.assertEqual("partial", unresolved["status"])
                self.assertIn(
                    "local-time basis is unknown", unresolved["missing_reason"][0]
                )
                self.assertGreater(len(unresolved["answer"]), len(rows))

                db.execute("DELETE FROM evtx_events")
                empty = _build_daily_session_timeline(
                    case,
                    db,
                    "empty",
                    "timeline",
                    "session",
                    "between 09:00 and 18:00 local time.",
                )
                self.assertEqual("unobservable", empty["status"])
                self.assertEqual([], empty["answer"])

                case.source_timezone = "America/New_York"
                db.execute(
                    "INSERT INTO evtx_events (event_id, timestamp, target_user, logon_type, channel, raw_json) VALUES (4624, '2015-03-22 13:00:00', 'alice', '2', 'Security', ?)",
                    (
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                    ),
                )
                unreferenced = build_structured_answer(
                    case,
                    db,
                    answer_spec="daily_session_timeline",
                    answer_id="unreferenced",
                    section_key="2_timeline",
                    block_heading="Daily session timeline",
                )
                self.assertEqual("partial", unreferenced["status"])
                self.assertTrue(
                    any(
                        "no stable" in reason
                        for reason in unreferenced["missing_reason"]
                    )
                )


if __name__ == "__main__":
    unittest.main()
