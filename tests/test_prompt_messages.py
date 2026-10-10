from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from forensia.config import (
    reload_settings,
)
from forensia.context.prompt_context import (
    _build_event_id_guidance,
    _build_schema_guidance,
    _trim_dynamic_content,
    slim_report_brief_for_section,
    truncate_context_sections,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.report.sections.evidence_projection import (
    project_report_evidence_row,
)
from forensia.report.sections.prompts import (
    build_paragraph_narrate_messages,
    build_section_outline_messages,
    build_structured_classify_messages,
)
from forensia.report.sections.section_exec import question_report_brief
from forensia.report.sections.section_quality import validate_body_evidence_ids


class PromptMessageTests(unittest.TestCase):
    """Prompt message content: truncation, guidance blocks, language handling."""

    def tearDown(self) -> None:
        reload_settings()

    def test_truncate_context_sections_keeps_text_within_1500_chars(self) -> None:
        sections = {"2_timeline": "x" * 1500, "3_technical": "y" * 1501}

        trimmed = truncate_context_sections(sections)

        self.assertEqual("x" * 1500, trimmed["2_timeline"])
        self.assertLessEqual(len(trimmed["3_technical"]), 1500)
        self.assertIn("…[truncated]", trimmed["3_technical"])

    def test_benchmark_report_brief_strips_narrative_keys(self) -> None:
        brief = question_report_brief(
            {
                "investigation_objective": "Narrative objective",
                "top_findings": [{"finding_id": "F-1"}],
                "active_hypotheses": [{"hypothesis_id": "H-1"}],
                "confirmed_hypotheses": [{"hypothesis_id": "H-2"}],
                "prior_sections": {"3_technical": "narrative"},
                "existing_claims": [{"claim_text": "narrative"}],
                "evidence_coverage": {"evtx_events": 12},
                "source_timezone": "Asia/Tokyo",
                "timezone_offset": "+09:00",
                "time_range": "2026-05-01 to 2026-05-02",
            }
        )

        self.assertEqual(
            {
                "evidence_coverage": {"evtx_events": 12},
                "source_timezone": "Asia/Tokyo",
                "timezone_offset": "+09:00",
                "time_range": "2026-05-01 to 2026-05-02",
            },
            brief,
        )

    def test_observed_candidate_drafter_discloses_sigma_fields_and_retrieval_terms(
        self,
    ) -> None:
        from forensia.investigation import prompts

        captured: dict[str, object] = {}

        def capture_knowledge(*, extra_words=None, **_kwargs):
            captured["extra_words"] = extra_words
            return ""

        candidate = {
            "candidate_ref": "cand-test",
            "title": "Suspicious service creation",
            "summary": "Service command launched remotely",
            "scope": {"source_family": "evtx"},
            "evidence_ids": ["evtx-test"],
            "evidence": [
                {
                    "evidence_id": "evtx-test",
                    "event_id": 7045,
                    "command_line": "sc.exe create updater binPath=...",
                    "service_name": "Updater",
                    "logon_type": 3,
                    "subject_user": "CORP\\analyst",
                    "target_group": "Administrators",
                    "target_server": "host-02",
                }
            ],
        }
        rules = [
            {
                "id": "sigma-service-rule",
                "title": "Remote Service Installation",
                "tags": ["attack.persistence", "attack.t1543.003"],
            }
        ]
        with patch.object(
            prompts, "_org_knowledge_block", side_effect=capture_knowledge
        ):
            messages, _schema = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "host_execution_activity"},
                rules,
                observed_candidate=candidate,
            )

        joined = "\n".join(message["content"] for message in messages)
        for field in (
            "command_line",
            "service_name",
            "logon_type",
            "subject_user",
            "target_group",
            "target_server",
        ):
            self.assertIn(field, joined)
        self.assertIn("sc.exe create updater", joined)
        self.assertIn("Remote Service Installation", captured["extra_words"])
        self.assertIn("attack.t1543.003", captured["extra_words"])
        self.assertIn("Suspicious service creation", captured["extra_words"])


class TestConfirmedFindingsBlock(unittest.TestCase):
    """Tests for the <CONFIRMED_FINDINGS> block in build_query_intent_messages."""

    def test_no_findings_omits_block(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=[],
        )
        system_content = msgs[0]["content"]
        self.assertNotIn("<CONFIRMED_FINDINGS>", system_content)

    def test_evidence_ids_string_parsed(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        findings = [
            {
                "severity": "high",
                "title": "test finding",
                "hypothesis_id": "H-001",
                "finding_id": "f-001",
                "evidence_ids": "evtx-001,evtx-002",
            },
        ]
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=findings,
        )
        system_content = msgs[0]["content"]
        self.assertIn("evtx-001", system_content)
        self.assertIn("evtx-002", system_content)


class PriorAttemptsBlockTests(unittest.TestCase):
    """Attempt history reaches the planner as structured fields, not prose.

    Why: weak local models act reliably on structured lists (query_id /
    verdict / evidence_count) but often ignore clipped free text. The
    structured block is also what lets the planner avoid repeating queries.
    """

    def test_render_prior_attempts_structured_fields(self) -> None:
        from forensia.investigation.prompts import render_prior_attempts

        block = render_prior_attempts(
            [
                {
                    "query_id": "q-001",
                    "template_id": "t-logon",
                    "verdict": "inconclusive",
                    "evidence_ids": [],
                    "purpose": "find 4720 account creation",
                    "summary": "no rows returned for event 4720",
                },
                {
                    "query_id": "q-002",
                    "verdict": "inconclusive",
                    "evidence_ids": ["e-1", "e-2"],
                    "body": "partial overlap only",
                },
            ]
        )
        self.assertIn("<PRIOR_ATTEMPTS>", block)
        self.assertIn("query_id=q-001", block)
        self.assertIn("template=t-logon", block)
        self.assertIn("verdict=inconclusive", block)
        self.assertIn("evidence_count=0", block)
        self.assertIn("evidence_count=2", block)
        self.assertIn("do_not_repeat_query_ids: q-001, q-002", block)

    def test_intent_messages_carry_structured_attempts(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        msgs = build_query_intent_messages(
            hypothesis=Hypothesis(id="H-001", description="test hypothesis"),
            recent_history=[
                {
                    "query_id": "q-009",
                    "verdict": "inconclusive",
                    "summary": "zero rows",
                }
            ],
            active_hypotheses=[],
            time_range={},
            schema_context="",
        )
        system = msgs[0]["content"]
        self.assertIn("<PRIOR_ATTEMPTS>", system)
        self.assertIn("query_id=q-009", system)
        # The raw JSON dump of history must be gone.
        self.assertNotIn("recent_history:", system)

    def test_investigation_prompts_project_repeated_and_raw_context(self) -> None:
        from forensia.investigation.prompts import (
            build_query_intent_messages,
            build_verdict_review_messages,
        )

        hypothesis = Hypothesis(
            id="H-001",
            description="UNIQUE-CURRENT-HYPOTHESIS",
            confirm_when={"co_observed_event_ids": [4625]},
        )
        with patch(
            "forensia.investigation.prompts._org_knowledge_block",
            return_value="",
        ):
            plan_messages = build_query_intent_messages(
                hypothesis=hypothesis,
                recent_history=[],
                active_hypotheses=[
                    hypothesis,
                    Hypothesis(id="H-002", description="peer hypothesis"),
                ],
                extra_context_md=(
                    "# KP-1\n\n- theme_finding_count: 2\n\n"
                    "## Theme Finding IDs\n- opaque-1\n- opaque-2\n\n"
                    "## Evidence IDs\n- ev-1\n"
                ),
            )
        combined = "\n".join(message["content"] for message in plan_messages)
        self.assertEqual(1, combined.count("UNIQUE-CURRENT-HYPOTHESIS"))
        self.assertNotIn("confirm_when", combined)
        self.assertIn("verification_spec", combined)
        self.assertIn("peer hypothesis", combined)
        self.assertNotIn("opaque-1", combined)
        self.assertIn("theme_finding_count: 2", combined)
        self.assertIn("## Evidence IDs", combined)

        raw_json = (
            '{"event":{"provider":"microsoft-windows-eventsystem","code":4625},'
            '"winlog":{"channel":"Application","event_id":4625,'
            '"provider":{"name":"Microsoft-Windows-EventSystem",'
            '"guid":"discard-me"},"event_data":{"param1":"86400"}},'
            '"log":{"file":{"path":"/private/sample.evtx"}},'
            '"source_file":"hash","ingested_at":"later"}'
        )
        summary = {
            "row_count": 2,
            "head_rows": [{"evidence_id": "ev-1", "raw_json": raw_json}],
            "tail_rows": [{"evidence_id": "ev-2", "raw_json": raw_json}],
            "sample_rows": [
                {"evidence_id": "ev-1", "event_id": 4625, "raw_json": raw_json},
                {"evidence_id": "ev-2", "event_id": 4625, "raw_json": raw_json},
            ],
            "event_id_set": [4625],
            "evidence_ids": ["ev-1", "ev-2"],
        }
        verdict_messages, _ = build_verdict_review_messages(
            hypothesis,
            PlannedQuery(
                query_id="Q-1", hypothesis_id="H-001", purpose="test", sql="SELECT 1"
            ),
            summary,
        )
        verdict_user = verdict_messages[1]["content"]
        self.assertNotIn('"head_rows"', verdict_user)
        self.assertNotIn('"tail_rows"', verdict_user)
        self.assertEqual(1, verdict_user.count("raw_event_context"))
        self.assertIn("Application", verdict_user)
        self.assertIn("Microsoft-Windows-EventSystem", verdict_user)
        self.assertIn("param1", verdict_user)
        self.assertNotIn("/private/sample.evtx", verdict_user)
        self.assertNotIn("discard-me", verdict_user)

    def test_intent_knowledge_terms_include_previous_check_feedback(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        with patch(
            "forensia.investigation.prompts._org_knowledge_block",
            return_value="",
        ) as knowledge_block:
            build_query_intent_messages(
                hypothesis=Hypothesis(id="H-001", description="test hypothesis"),
                recent_history=[{"summary": "prior answer about log clearing"}],
                active_hypotheses=[],
                prior_check_feedback="missing event_id 1102",
            )
        extra_words = knowledge_block.call_args.kwargs["extra_words"]
        self.assertIn("missing event_id 1102", extra_words)
        self.assertIn("prior answer about log clearing", extra_words)

    def test_dynamic_context_trim_respects_effective_budget(self) -> None:
        messages = [
            {"role": "system", "content": "s" * 1000},
            {"role": "user", "content": "u" * 20000},
        ]
        trimmed = _trim_dynamic_content(messages, max_total_tokens=1000)
        self.assertLessEqual(sum(len(m["content"]) for m in trimmed), 4000)
        self.assertIn("…[truncated]", trimmed[1]["content"])
        self.assertEqual("u" * 20000, messages[1]["content"])


class NarratePromptContractTests(unittest.TestCase):
    """Schema and brief-slimming contracts for narrative section prompts."""

    def test_large_aggregate_evidence_is_semantically_projected(self) -> None:
        """A complete 5,199-ID set stays authoritative but never floods report prompts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            db = CaseDB(case)
            try:
                evidence_ids = [
                    f"evtx-{'a' * 64}-security-{index:012d}" for index in range(1, 5200)
                ]
                base = datetime(2015, 3, 22, 12, 0, 0)
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, timestamp, channel, computer, target_user, event_id
                    )
                    SELECT 'evtx-' || repeat('a', 64) || '-security-' ||
                           lpad((i + 1)::VARCHAR, 12, '0'),
                           ?::TIMESTAMP + i * INTERVAL '1 second',
                           ['Security', 'System', 'Application'][i % 3 + 1],
                           ['host-a', 'host-b'][i % 2 + 1],
                           ['alice', 'bob', 'carol'][i % 3 + 1],
                           [4624, 4625, 4648, 4720][i % 4 + 1]
                    FROM range(5199) AS r(i)
                    """,
                    (base,),
                )
                unordered_ids = evidence_ids[2600:] + evidence_ids[:2600]
                aggregate = {
                    "first_event": str(base),
                    "last_event": str(base + timedelta(seconds=5198)),
                    "event_count": 5199,
                    "evidence_ids": unordered_ids,
                    "_source_keypoint": "evidence_query",
                }
                original = copy.deepcopy(aggregate)

                projected = project_report_evidence_row(aggregate, db=db)
                projected_from_reverse = project_report_evidence_row(
                    {**aggregate, "evidence_ids": list(reversed(unordered_ids))},
                    db=db,
                )

                self.assertEqual(original, aggregate)
                self.assertEqual(projected, projected_from_reverse)
                self.assertEqual(5199, projected["event_count"])
                self.assertEqual(5199, projected["evidence_count"])
                self.assertEqual(str(base), projected["first_event"])
                self.assertEqual(
                    str(base + timedelta(seconds=5198)), projected["last_event"]
                )
                self.assertNotIn("evidence_ids", projected)
                representatives = projected["representative_evidence_ids"]
                self.assertIn(evidence_ids[0], representatives)
                self.assertIn(evidence_ids[-1], representatives)
                self.assertTrue(set(representatives).issubset(evidence_ids))
                self.assertLessEqual(len(representatives), 10)
                distribution = projected["evidence_distribution"]
                self.assertEqual(3, distribution["source_family"]["distinct_count"])
                self.assertEqual(2, distribution["host"]["distinct_count"])
                self.assertEqual(3, distribution["user"]["distinct_count"])
                self.assertEqual(4, distribution["event_family"]["distinct_count"])

                narrative, _ = build_paragraph_narrate_messages(
                    heading="Time Basis and Coverage",
                    key_points=[],
                    evidence_rows=[aggregate],
                    template_body="Covered period, source coverage, timezone, gaps.",
                    report_context={"source_timezone": "UTC"},
                    db=db,
                )
                outline, _ = build_section_outline_messages(
                    template_body="## Time Basis and Coverage",
                    relevant_evidence=[aggregate],
                    section_meta={"section": "2_timeline"},
                    db=db,
                )
                structured, _ = build_structured_classify_messages(
                    question="What period is covered?",
                    block_heading="Time Basis and Coverage",
                    evidence_rows=[aggregate],
                    expected_shape={
                        "fields": ["first_event", "last_event", "event_count"]
                    },
                    db=db,
                )
                prompt_texts = [
                    narrative[1]["content"],
                    outline[1]["content"],
                    structured[1]["content"],
                ]
                raw_size = len(json.dumps([aggregate]))
                for prompt_text in prompt_texts:
                    self.assertIn("evidence_count", prompt_text)
                    self.assertIn("first_event", prompt_text)
                    self.assertIn("last_event", prompt_text)
                    self.assertIn("evidence_query", prompt_text)
                    self.assertLess(len(prompt_text), raw_size // 10)
                    self.assertLessEqual(
                        len(
                            re.findall(
                                r"evtx-[a-f0-9]{64}-security-\d{12}", prompt_text
                            )
                        ),
                        20,
                    )
                self.assertIn('"source_timezone": "UTC"', narrative[1]["content"])

                body = "Observed coverage (" + ", ".join(representatives[:3]) + ")."
                self.assertEqual([], validate_body_evidence_ids(db, body))

                small = {
                    "event_count": 3,
                    "evidence_ids": evidence_ids[:3],
                    "_source_keypoint": "evidence_query",
                }
                self.assertEqual(small, project_report_evidence_row(small, db=db))

                unavailable = project_report_evidence_row(aggregate, db=None)
                self.assertNotIn("evidence_ids", unavailable)
                self.assertEqual([], unavailable["representative_evidence_ids"])
                self.assertFalse(unavailable["citable"])
                no_db_messages, _ = build_paragraph_narrate_messages(
                    heading="Time Basis and Coverage",
                    key_points=[],
                    evidence_rows=[aggregate],
                    template_body="## Time Basis and Coverage",
                )
                self.assertNotIn(evidence_ids[0], no_db_messages[1]["content"])
                self.assertLess(len(no_db_messages[1]["content"]), raw_size // 10)

                unresolved = project_report_evidence_row(
                    {
                        "event_count": 21,
                        "evidence_ids": [
                            f"evtx-{'a' * 64}-security-{index:012d}"
                            for index in range(900_000, 900_021)
                        ],
                    },
                    db=db,
                )
                self.assertEqual([], unresolved["representative_evidence_ids"])
                self.assertFalse(unresolved["citable"])
                self.assertEqual(
                    21,
                    unresolved["evidence_projection"]["unresolved_evidence_count"],
                )
            finally:
                db.close()

    def test_slim_report_brief_keeps_case_level_context_for_narrative_sections(self):
        brief = {
            "time_range": {"start": "2015-03-22", "end": "2015-03-23"},
            "source_timezone": "UTC",
            "top_findings": [
                {
                    "finding_id": "finding-1",
                    "title": "Explicit credential logon",
                    "summary": "4648 activity involving informant.",
                    "severity": "high",
                    "confidence": 0.9,
                    "evidence_ids": [
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122"
                    ],
                    "large_unused_field": "x" * 200,
                }
            ],
            "confirmed_hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "description": "Explicit credentials were used.",
                    "status": "confirmed",
                    "verdict": "confirmed",
                }
            ],
            "active_hypotheses": [
                {"hypothesis_id": "H-002", "description": "Missing collection gap."}
            ],
        }

        technical = slim_report_brief_for_section(brief, "3_technical")
        gaps = slim_report_brief_for_section(brief, "4_gaps")

        self.assertEqual(
            "Explicit credential logon", technical["top_findings"][0]["title"]
        )
        self.assertIn("confirmed_hypotheses", technical)
        self.assertNotIn("large_unused_field", technical["top_findings"][0])
        self.assertEqual("H-002", gaps["active_hypotheses"][0]["hypothesis_id"])
        self.assertNotIn("top_findings", gaps)


def test_section_knowledge_selection_uses_template_frontmatter_tags(
    tmp_path: Path,
) -> None:
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs
    from forensia.report.sections.section_block_plan import _inject_org_knowledge

    (tmp_path / "allowed.md").write_text(
        "---\ntype: knowledge\ntitle: Timeline notes\n"
        "description: timeline\ntags: [template-tag]\n---\n"
        "## Timeline\ntimeline evidence from allowed doc\n",
        encoding="utf-8",
    )
    (tmp_path / "blocked.md").write_text(
        "---\ntype: knowledge\ntitle: Timeline timeline timeline\n"
        "description: timeline timeline timeline\ntags: [section-family]\n---\n"
        "## Timeline\ntimeline timeline timeline from blocked doc\n",
        encoding="utf-8",
    )
    set_knowledge_docs(scan_knowledge_dir(tmp_path))
    try:
        ctx = SimpleNamespace(
            title="Timeline",
            block_heading="Timeline",
            template_tags=("template-tag",),
            base_url="",
            model="",
        )
        system = _inject_org_knowledge("SYSTEM\n", ctx)
    finally:
        set_knowledge_docs([])

    assert "allowed" in system
    assert "blocked" not in system


def test_section_knowledge_selection_uses_latest_missing_question(
    tmp_path: Path,
) -> None:
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs
    from forensia.report.sections.section_block_plan import _inject_org_knowledge

    (tmp_path / "log-clearing.md").write_text(
        "---\ntype: knowledge\ntitle: Event 1102 log clearing\n"
        "description: Security log removal\ntags: [windows]\n---\n"
        "## Event 1102\nCheck event 1102 and adjacent service events.\n",
        encoding="utf-8",
    )
    set_knowledge_docs(scan_knowledge_dir(tmp_path))
    try:
        ctx = SimpleNamespace(
            title="Technical assessment",
            block_heading="Open questions",
            template_tags=("windows",),
            base_url="",
            model="",
        )
        system = _inject_org_knowledge(
            "SYSTEM\n", ctx, focus_terms=["missing event_id 1102 log clearing"]
        )
    finally:
        set_knowledge_docs([])
    # The fragment shows the document title, not the file name.
    assert "Event 1102 log clearing" in system
    assert "log-clearing" not in system


def test_section_knowledge_llm_compaction_preserves_fragment_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs
    from forensia.report.sections.section_block_plan import _inject_org_knowledge

    (tmp_path / "log-clearing.md").write_text(
        "---\ntype: knowledge\ntitle: Event 1102 log clearing\n"
        "description: Security log removal reference\ntags: [windows]\n---\n"
        "## Event 1102\n" + ("Check event 1102 and adjacent service events.\n" * 200),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "forensia.llm.compaction.llm_compact",
        lambda text, budget, **kwargs: "Check event 1102 and adjacent service events.",
    )
    set_knowledge_docs(scan_knowledge_dir(tmp_path))
    try:
        ctx = SimpleNamespace(
            title="Technical assessment",
            block_heading="Open questions",
            template_tags=("windows",),
            base_url="http://llm.invalid",
            model="test-model",
        )
        system = _inject_org_knowledge(
            "SYSTEM\n", ctx, focus_terms=["event 1102 log clearing"]
        )
    finally:
        set_knowledge_docs([])

    assert "Topic: Event 1102 log clearing" in system
    assert "Summary: Security log removal reference" in system
    assert "log-clearing.md" not in system


class IndexedContextTests(unittest.TestCase):
    """T-21: repeated global prompts become compact indexes with lazy detail."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.case = Case.init(self.tmpdir)
        self.db = CaseDB(self.case)

    def tearDown(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass

    def test_schema_guidance_returns_only_selected_card(self) -> None:
        text = _build_schema_guidance("evtx_events", db=self.db, session_id="S-1")
        self.assertNotIn("<SCHEMA_INDEX>", text)
        self.assertNotIn("load schema card", text)
        self.assertNotIn("RECIPE_INDEX", text)
        self.assertIn("<SELECTED_SCHEMA_CARDS>", text)
        row = self.db.execute(
            "SELECT source_kind, selected_refs FROM retrieval_events"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual("schema_hints", row[0])
        self.assertIn("evtx_events", row[1])

    def test_event_guidance_inlines_selected_rules_without_continuation(self) -> None:
        guidance = _build_event_id_guidance([{"sample_rows": [{"event_id": 4624}]}])
        self.assertIn("Event ID 4624", guidance)
        self.assertIn("allowed_claims", guidance)
        self.assertNotIn("EVENT_ID_INDEX", guidance)
        self.assertNotIn("load event rule", guidance)


if __name__ == "__main__":
    unittest.main()
