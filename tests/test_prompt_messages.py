from __future__ import annotations

import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from forensia.ai.llm.schemas import PARAGRAPH_NARRATE_SCHEMA
from forensia.ai.prompts.prompt_context import (
    _trim_dynamic_content,
    slim_report_brief_for_section,
    truncate_context_sections,
)
from forensia.ai.prompts.prompt_sections import (
    build_paragraph_narrate_messages,
    build_question_classify_messages,
    build_report_section_messages,
    build_structured_classify_messages,
)
from forensia.ai.prompts.sql_schema import build_investigation_framework
from forensia.ai.sections.section_exec import question_report_brief
from forensia.config import (
    clear_llm_settings_cache,
    reload_settings,
    resolve_llm_config,
)
from forensia.core.session import Hypothesis


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

    def test_report_section_messages_truncate_previous_sections(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "1_overview"},
            evidence_results=[],
            context_sections={"1_overview": "x" * 1600},
            template_body="# Section",
            report_brief={},
        )
        payload = messages[1]["content"]
        self.assertIn("x" * 120, payload)
        self.assertNotIn("x" * 200, payload)

    def test_report_section_messages_placeholder_follows_output_language(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            messages = build_report_section_messages(
                section_meta={"section": "1_overview"},
                evidence_results=[],
                context_sections={},
                template_body="# Section",
                report_brief={},
            )
        system = messages[0]["content"]
        self.assertIn("[INSUFFICIENT EVIDENCE: reason]", system)

    def test_report_section_prompt_includes_ioc_catalog(self) -> None:
        # A case profile is always set before report prompts at runtime
        # (investigate() computes it). Without one, the unfiltered Event ID
        # Reference alone exceeds the system-prompt budget and every droppable
        # playbook section (including the IOC catalog) is trimmed. Set a small
        # profile explicitly so this test is order-independent.
        from forensia.ai.case_profile import set_case_profile

        set_case_profile("test-profile", {4624, 4625, 4648, 1102, 104, 7045})
        self.addCleanup(lambda: set_case_profile(None, None))
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[],
            context_sections={},
            template_body="# Section",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("## IOC Catalog", system)
        self.assertIn("Eraser", system)
        self.assertIn("LOLBins", system)

    def test_report_section_messages_include_recommendation_strength_guidance(
        self,
    ) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "5_recommendations"},
            evidence_results=[],
            context_sections={},
            template_body="# Recommended Actions",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("Match wording to confidence", system)
        self.assertIn("Recommended actions must scale with evidence strength", system)

    def test_report_section_messages_include_language_confidence_matrix_and_categories(
        self,
    ) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[],
            context_sections={},
            template_body="# Persistence and Execution",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("confidence >= 0.8", system)
        self.assertIn("confidence < 0.5", system)
        self.assertIn(
            "Do not use 'confirmed' for findings or conclusions below 0.8 confidence",
            system,
        )
        self.assertIn("GOOGLEDRIVESYNC.EXE=cloud_sync", system)
        self.assertIn("SCHTASKS.EXE=persistence_tool", system)

    def test_investigation_framework_includes_machine_account_and_category_guidance(
        self,
    ) -> None:
        framework = build_investigation_framework()

        self.assertIn("account names ending with '$' as machine_account", framework)
        self.assertIn("never store a machine account in source_ip", framework)
        self.assertIn("GOOGLEDRIVESYNC.EXE=cloud_sync", framework)
        self.assertIn("SCHTASKS.EXE=persistence_tool", framework)

    def test_benchmark_report_brief_strips_narrative_keys(self) -> None:
        brief = question_report_brief(
            {
                "investigation_objective": "Narrative objective",
                "top_findings": [{"finding_id": "F-1"}],
                "active_hypotheses": [{"hypothesis_id": "H-1"}],
                "confirmed_hypotheses": [{"hypothesis_id": "H-2"}],
                "evidence_inventory": {
                    "time_range": "2026-05-01 to 2026-05-02",
                    "row_counts": {"evtx_events": 12},
                    "narrative": "drop this",
                },
            }
        )

        self.assertNotIn("investigation_objective", brief)
        self.assertNotIn("top_findings", brief)
        self.assertNotIn("active_hypotheses", brief)
        self.assertEqual(
            {
                "time_range": "2026-05-01 to 2026-05-02",
                "row_counts": {"evtx_events": 12},
            },
            brief["evidence_inventory"],
        )

    def test_report_section_messages_include_event_id_guidance(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[
                {
                    "kind": "rows",
                    "sample_rows": [{"event_id": 4720, "evidence_id": "ev-1"}],
                    "head_rows": [],
                    "tail_rows": [],
                }
            ],
            context_sections={},
            template_body="# Section",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("Event ID 4720", system)
        self.assertIn("allowed_claims", system)

    def test_report_section_messages_include_strength_guidance_for_non_confirmed_sources(
        self,
    ) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[
                {
                    "kind": "rows",
                    "source_verdict": "newlead",
                    "sample_rows": [{"event_id": 4720, "evidence_id": "ev-1"}],
                }
            ],
            context_sections={},
            template_body="# Section",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("source_verdict guidance", system)
        self.assertIn("avoid 'confirmed'", system)

    def test_benchmark_classify_messages_request_picked_row_indices_only(self) -> None:
        messages, _ = build_question_classify_messages(
            question="## 8. Mail data files",
            block_heading="8. Mail data files",
            evidence_rows=[
                {"evidence_id": "ev-1", "file_path": "C:/Users/Alice/file.ost"}
            ],
            expected_shape={
                "format": "name_with_version",
                "fields": ["application_name", "version", "data_files"],
            },
        )
        system = messages[0]["content"]
        user = messages[1]["content"]
        self.assertIn("question_classifier", system)
        self.assertIn("picked_row_indices", system)
        self.assertNotIn('"answer"', system)
        self.assertIn("ev-1", user)
        self.assertIn("application_name", user)

    def test_structured_classify_messages_use_neutral_role(self) -> None:
        messages, schema = build_structured_classify_messages(
            question="When was the last shutdown?",
            block_heading="Last shutdown",
            evidence_rows=[
                {"evidence_id": "ev-1", "shutdown_time": "2015-03-22T14:38:16"}
            ],
            expected_shape={
                "format": "list",
                "fields": ["shutdown_time", "evidence_id"],
            },
        )
        self.assertIn("structured_classifier", messages[0]["content"])
        self.assertNotIn("question_classifier", messages[0]["content"])
        self.assertEqual("StructuredClassifier", schema["title"])


class TestConfirmedFindingsBlock(unittest.TestCase):
    """Tests for the <CONFIRMED_FINDINGS> block in build_query_intent_messages."""

    def test_no_findings_omits_block(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=[],
        )
        system_content = msgs[0]["content"]
        self.assertNotIn("<CONFIRMED_FINDINGS>", system_content)

    def test_none_findings_omits_block(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=None,
        )
        system_content = msgs[0]["content"]
        self.assertNotIn("<CONFIRMED_FINDINGS>", system_content)

    def test_top5_by_severity(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        # 10 findings with various severities
        findings = [
            {
                "severity": "low",
                "title": f"finding-{i}",
                "hypothesis_id": f"H-{i:03d}",
                "finding_id": f"f-{i:03d}",
                "evidence_ids": [f"evtx-{i:03d}"],
            }
            for i in range(1, 11)
        ]
        # Insert critical/high in positions 6,7 so they should bubble to top
        findings[5]["severity"] = "critical"
        findings[6]["severity"] = "high"
        findings[0]["severity"] = "critical"  # another critical

        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=findings,
        )
        system_content = msgs[0]["content"]
        # Find the line in the CONFIRMED_FINDINGS block
        for line in system_content.split("\n"):
            if "[high]" in line:
                self.assertLessEqual(len(line.strip()), 163)  # 160 + "... "
                # Line may or may not end with "..." depending on length
                break
        else:
            self.fail("No [high] finding line found in CONFIRMED_FINDINGS block")

    def test_evidence_ids_string_parsed(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

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

    def test_max_length_truncation(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        # Finding with very long title
        findings = [
            {
                "severity": "critical",
                "title": "A" * 200,
                "hypothesis_id": "H-001",
                "finding_id": "f-001",
                "evidence_ids": [],
            },
        ]
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=findings,
        )
        system_content = msgs[0]["content"]
        # Should contain truncated title (truncated to ~80 chars)
        self.assertIn("A" * 80, system_content)  # First 80 chars kept


class PriorAttemptsBlockTests(unittest.TestCase):
    """Attempt history reaches the planner as structured fields, not prose.

    Why: weak local models act reliably on structured lists (query_id /
    verdict / evidence_count) but often ignore clipped free text. The
    structured block is also what lets the planner avoid repeating queries.
    """

    def test_render_prior_attempts_structured_fields(self) -> None:
        from forensia.ai.prompts.prompt_investigation import render_prior_attempts

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

    def test_render_prior_attempts_omits_absent_fields(self) -> None:
        """Fields missing from a row are omitted, never fabricated (Rule 12)."""
        from forensia.ai.prompts.prompt_investigation import render_prior_attempts

        block = render_prior_attempts([{"verdict": "inconclusive"}])
        self.assertNotIn("query_id=", block)
        self.assertNotIn("evidence_count=", block)
        self.assertNotIn("do_not_repeat_query_ids", block)

    def test_render_prior_attempts_empty_history(self) -> None:
        from forensia.ai.prompts.prompt_investigation import render_prior_attempts

        self.assertIn("(none)", render_prior_attempts([]))

    def test_intent_messages_carry_structured_attempts(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

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

    def test_intent_knowledge_terms_include_previous_check_feedback(self) -> None:
        from forensia.ai.prompts.prompt_investigation import build_query_intent_messages

        with patch(
            "forensia.ai.prompts.prompt_investigation._org_knowledge_block",
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

    def test_paragraph_narrate_schema_required_body(self):
        self.assertIn("required", PARAGRAPH_NARRATE_SCHEMA)
        self.assertIn("body", PARAGRAPH_NARRATE_SCHEMA["required"])
        messages, _ = build_paragraph_narrate_messages(
            heading="Executive Summary",
            key_points=[],
            evidence_rows=[],
            template_body="## Executive Summary",
        )
        self.assertIn('{"body"', messages[0]["content"])
        self.assertIn("Do not return a bare string", messages[0]["content"])

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
                    "evidence_ids": ["evtx-security-000000000122"],
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
    from forensia.ai.sections.section_block_plan import _inject_org_knowledge
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs

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
    from forensia.ai.sections.section_block_plan import _inject_org_knowledge
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs

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
    from forensia.ai.sections.section_block_plan import _inject_org_knowledge
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs

    (tmp_path / "log-clearing.md").write_text(
        "---\ntype: knowledge\ntitle: Event 1102 log clearing\n"
        "description: Security log removal reference\ntags: [windows]\n---\n"
        "## Event 1102\n" + ("Check event 1102 and adjacent service events.\n" * 200),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "forensia.ai.compaction.llm_compact",
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


def test_prior_section_runs_keep_prefiltered_and_matching_history() -> None:
    from forensia.ai.prompts.prompt_sections import _filter_prior_runs_by_heading

    runs = [
        {"block_heading": "Log Integrity", "payload": {"missing_questions": ["1102"]}},
        {"block_heading": "Other", "payload": {}},
        {"payload": {"legacy": True}},
    ]
    selected = _filter_prior_runs_by_heading(runs, "Log Integrity")
    assert selected == [runs[0], runs[2]]


if __name__ == "__main__":
    unittest.main()
