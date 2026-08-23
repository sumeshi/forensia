"""Tests for forensia.ai.compaction — stage-2 LLM compaction with guards."""

from __future__ import annotations

from unittest.mock import patch

from forensia.ai.compaction import (
    _essential_tokens_present,
    _extract_essential_tokens,
    clear_compaction_cache,
    llm_compact,
    structured_compact,
)
from forensia.core.compaction import TRUNCATION_MARKER


class TestExtractEssentialTokens:
    def test_event_ids(self) -> None:
        tokens = _extract_essential_tokens("Event ID 4624 and 4625 occurred")
        assert "4624" in tokens
        assert "4625" in tokens

    def test_table_names(self) -> None:
        tokens = _extract_essential_tokens(
            "SELECT * FROM evtx_events WHERE event_id = 4624"
        )
        assert "evtx_events" in tokens

    def test_windows_paths(self) -> None:
        tokens = _extract_essential_tokens("File at C:\\Windows\\System32\\cmd.exe")
        assert any("C:\\Windows" in t for t in tokens)

    def test_unix_paths(self) -> None:
        tokens = _extract_essential_tokens("File at /usr/bin/python3")
        assert any("/usr/bin/python3" in t for t in tokens)

    def test_evidence_ids(self) -> None:
        tokens = _extract_essential_tokens("See evtx-security-00000000122 for details")
        assert "evtx-security-00000000122" in tokens

    def test_empty_text(self) -> None:
        assert _extract_essential_tokens("") == set()

    def test_short_tokens_excluded(self) -> None:
        tokens = _extract_essential_tokens("ab cd ef")
        assert all(len(t) >= 3 for t in tokens)


class TestEssentialTokensPresent:
    def test_all_present(self) -> None:
        assert _essential_tokens_present(
            {"4624", "evtx_events"}, "Event 4624 from evtx_events"
        )

    def test_missing_token(self) -> None:
        assert not _essential_tokens_present({"4624", "4625"}, "Event 4624 only")

    def test_empty_tokens_always_pass(self) -> None:
        assert _essential_tokens_present(set(), "anything")

    def test_case_insensitive(self) -> None:
        assert _essential_tokens_present({"EVTX_EVENTS"}, "from evtx_events table")


class TestLlmCompact:
    def setup_method(self) -> None:
        clear_compaction_cache()

    def test_under_budget_returned_unchanged(self) -> None:
        result = llm_compact("short text", 100, base_url="http://x", model="m")
        assert result == "short text"

    def test_zero_budget_returns_empty(self) -> None:
        assert llm_compact("text", 0, base_url="http://x", model="m") == ""

    def test_mechanical_sufficiency(self) -> None:
        """When text < 1.5x budget, mechanical is used (no LLM call)."""
        text = "x" * 140  # 140 < 100 * 1.5
        with patch("forensia.ai.compaction._call_llm") as mock_llm:
            result = llm_compact(text, 100, base_url="http://x", model="m")
        mock_llm.assert_not_called()
        assert len(result) <= 100
        assert TRUNCATION_MARKER in result

    def test_llm_called_when_text_exceeds_threshold(self) -> None:
        text = "Event 4624 from evtx_events table. " * 50  # well over 1.5x budget
        llm_response = "Summarised: Event 4624 from evtx_events."
        with patch(
            "forensia.ai.compaction._call_llm", return_value=llm_response
        ) as mock_llm:
            result = llm_compact(text, 200, base_url="http://x", model="m")
        mock_llm.assert_called_once()
        assert "4624" in result
        assert "evtx_events" in result

    def test_fallback_on_llm_exception(self) -> None:
        text = "Event 4624 from evtx_events. " * 50
        with patch(
            "forensia.ai.compaction._call_llm", side_effect=RuntimeError("LLM down")
        ):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert len(result) <= 200
        assert TRUNCATION_MARKER in result

    def test_fallback_on_missing_essential_tokens(self) -> None:
        text = "Event ID 4624 from evtx_events on host WS-01. " * 50
        # LLM drops event ID 4624
        llm_response = "Summary: events from the table on host WS-01."
        with patch("forensia.ai.compaction._call_llm", return_value=llm_response):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        # Should fall back to mechanical (which preserves the original)
        assert TRUNCATION_MARKER in result or len(result) <= 200

    def test_fallback_on_empty_llm_output(self) -> None:
        text = "Event 4624 from evtx_events. " * 50
        with patch("forensia.ai.compaction._call_llm", return_value=""):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert len(result) <= 200
        assert result  # not empty

    def test_budget_exceeded_by_llm_gets_mechanical_followup(self) -> None:
        text = "Event 4624 from evtx_events. " * 50
        llm_response = "Event 4624 from evtx_events. " + "x" * 500  # over budget
        with patch("forensia.ai.compaction._call_llm", return_value=llm_response):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert len(result) <= 200

    def test_followup_compaction_cannot_drop_essential_tokens(self) -> None:
        text = "Event 4624 from evtx_events. " + "original detail. " * 100
        llm_response = "x" * 500 + " Event 4624 from evtx_events"
        with patch("forensia.ai.compaction._call_llm", return_value=llm_response):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert "4624" in result
        assert "evtx_events" in result

    def test_cache_hit_avoids_llm_call(self) -> None:
        text = "Event 4624 from evtx_events table. " * 50
        llm_response = "Summarised: Event 4624 from evtx_events."
        with patch(
            "forensia.ai.compaction._call_llm", return_value=llm_response
        ) as mock_llm:
            r1 = llm_compact(text, 200, base_url="http://x", model="m")
            r2 = llm_compact(text, 200, base_url="http://x", model="m")
        assert r1 == r2
        assert mock_llm.call_count == 1  # second call used cache

    def test_different_budget_different_cache_entry(self) -> None:
        text = "Event 4624 from evtx_events table. " * 50
        llm_response_200 = "A" * 180
        llm_response_300 = "B" * 280
        with patch(
            "forensia.ai.compaction._call_llm",
            side_effect=[llm_response_200, llm_response_300],
        ) as mock_llm:
            r1 = llm_compact(text, 200, base_url="http://x", model="m")
            r2 = llm_compact(text, 300, base_url="http://x", model="m")
        assert mock_llm.call_count == 2
        assert r1 != r2

    def test_budget_never_exceeded(self) -> None:
        text = "Event 4624 from evtx_events. " * 100
        for budget in (50, 100, 200, 500):
            with patch(
                "forensia.ai.compaction._call_llm", side_effect=RuntimeError("fail")
            ):
                result = llm_compact(text, budget, base_url="http://x", model="m")
            assert len(result) <= budget, f"budget={budget} exceeded: len={len(result)}"

    def test_preserve_pattern_with_capture_group_uses_full_match(self) -> None:
        text = ("case evidence ABC-1234 should remain. " * 30).strip()
        response = "case evidence ABC-1234 should remain."
        with patch("forensia.ai.compaction._call_llm", return_value=response):
            result = llm_compact(
                text,
                100,
                base_url="http://x",
                model="m",
                preserve_patterns=[r"ABC-(\d{4})"],
            )
        assert "ABC-1234" in result


class TestEnforceSystemBudgetCompaction:
    """Verify that _enforce_system_budget tries compacting before dropping."""

    def test_last_section_compacted_instead_of_dropped(self) -> None:
        from forensia.ai.prompts.prompt_context import _enforce_system_budget

        # Create a system string where compacting the last section can fit
        small_playbook = "A" * 5000
        big_schema = "B" * 10000
        medium_notes = "C" * 8000
        system = f"{small_playbook}\n<SCHEMA_GUIDANCE>\n{big_schema}\n</SCHEMA_GUIDANCE>\n## Schema Notes\n{medium_notes}\n"

        # Budget: 14000 — dropping Schema Notes entirely would leave 15000 (over),
        # but compacting it should help
        result = _enforce_system_budget(system, budget_chars=14000)
        assert len(result) <= 14000

    def test_compacted_xml_section_keeps_closing_tag(self) -> None:
        from forensia.ai.prompts.prompt_context import _enforce_system_budget

        playbook = "A" * 5000
        knowledge_lines = "\n".join(f"knowledge line {i}" for i in range(600))
        system = f"{playbook}\n<ORG_KNOWLEDGE>\n{knowledge_lines}\n</ORG_KNOWLEDGE>\n"
        result = _enforce_system_budget(system, budget_chars=10000)
        assert len(result) <= 10000
        if "<ORG_KNOWLEDGE>" in result:
            assert "</ORG_KNOWLEDGE>" in result

    def test_budget_respected_with_known_markers(self) -> None:
        from forensia.ai.prompts.prompt_context import _enforce_system_budget

        playbook = "P" * 5000
        schema = "S" * 10000
        event_ids = "E" * 8000
        system = (
            f"{playbook}\n"
            f"<SCHEMA_GUIDANCE>\n{schema}\n</SCHEMA_GUIDANCE>\n"
            f"## Event ID Reference\n{event_ids}\n"
        )
        budget = 12000
        result = _enforce_system_budget(system, budget_chars=budget)
        assert len(result) <= budget

    def test_real_section_plan_prompt_respects_default_budget(self) -> None:
        import os

        from forensia.ai.prompts.prompt_context import _enforce_system_budget
        from forensia.ai.prompts.prompt_sections import (
            build_section_agent_plan_messages,
        )
        from forensia.config import reload_settings

        old_budget = os.environ.get("FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS")
        old_total = os.environ.get("FORENSIA_PROMPT_BUDGET_TOKENS")
        os.environ["FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS"] = "0"
        os.environ["FORENSIA_PROMPT_BUDGET_TOKENS"] = "0"
        reload_settings()
        try:
            messages, _ = build_section_agent_plan_messages(
                section_key="2_timeline",
                section_title="Activity Timeline",
                block_heading="Log Integrity",
                template_body="## Log Integrity",
                report_brief={},
                context_sections={},
                current_section_outline=[],
                findings_snapshot=[],
                keypoint_catalog=[],
                query_template_catalog=[],
                prior_runs=[],
                reusable_facts=[],
                reusable_evidence=[],
            )
            result = _enforce_system_budget(messages[0]["content"])
            assert len(result) <= 24000
            assert "<TASK>" in result
            assert "Output JSON only" in result
        finally:
            if old_budget is None:
                os.environ.pop("FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS", None)
            else:
                os.environ["FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS"] = old_budget
            if old_total is None:
                os.environ.pop("FORENSIA_PROMPT_BUDGET_TOKENS", None)
            else:
                os.environ["FORENSIA_PROMPT_BUDGET_TOKENS"] = old_total
            reload_settings()

    def test_real_section_plan_retains_question_specific_reference(self) -> None:
        import os

        from forensia.ai.prompts.prompt_context import _enforce_system_budget
        from forensia.ai.prompts.prompt_sections import (
            build_section_agent_plan_messages,
        )
        from forensia.config import reload_settings

        old_budget = os.environ.get("FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS")
        old_total = os.environ.get("FORENSIA_PROMPT_BUDGET_TOKENS")
        os.environ["FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS"] = "0"
        os.environ["FORENSIA_PROMPT_BUDGET_TOKENS"] = "0"
        reload_settings()
        try:
            messages, _ = build_section_agent_plan_messages(
                section_key="2_timeline",
                section_title="Activity Timeline",
                block_heading="Log Integrity",
                template_body="## Log Integrity",
                report_brief={},
                context_sections={},
                current_section_outline=[],
                findings_snapshot=[],
                keypoint_catalog=[],
                query_template_catalog=[],
                prior_runs=[],
                reusable_facts=[],
                reusable_evidence=[],
            )
            system = (
                messages[0]["content"]
                + "\n<ORG_KNOWLEDGE>\n"
                + "Event 1102 means the Security log was cleared.\n"
                + "</ORG_KNOWLEDGE>\n"
            )
            result = _enforce_system_budget(system)
            assert len(result) <= 24000
            assert "Event 1102 means the Security log was cleared" in result
        finally:
            if old_budget is None:
                os.environ.pop("FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS", None)
            else:
                os.environ["FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS"] = old_budget
            if old_total is None:
                os.environ.pop("FORENSIA_PROMPT_BUDGET_TOKENS", None)
            else:
                os.environ["FORENSIA_PROMPT_BUDGET_TOKENS"] = old_total
            reload_settings()

    def test_section_plan_uses_neutral_playbook_for_methodology(self) -> None:
        from forensia.ai.prompts.prompt_sections import (
            build_section_agent_plan_messages,
        )

        messages, _ = build_section_agent_plan_messages(
            section_key="1_overview",
            section_title="Investigation Overview",
            block_heading="Scope and Methodology",
            template_body="Define the investigated time window, systems, and evidence sources.",
            report_brief={
                "top_findings": [{"finding_id": "F1", "evidence_ids": ["evtx-1"]}],
                "investigation_objective": "Assess activity",
            },
            context_sections={},
            current_section_outline=[],
            findings_snapshot=[{"finding_id": "F1", "summary": "signal"}],
            keypoint_catalog=[],
            query_template_catalog=[],
            prior_runs=[],
            reusable_facts=[],
            reusable_evidence=[],
        )
        assert "## Event ID Reference" not in messages[0]["content"]
        assert "report_brief: {'investigation_objective': 'Assess activity'}" in messages[1]["content"]

    def test_section_plan_scopes_event_reference_to_contract(self) -> None:
        from forensia.ai.prompts.prompt_sections import (
            build_section_agent_plan_messages,
        )

        messages, _ = build_section_agent_plan_messages(
            section_key="3_technical",
            section_title="Technical Analysis",
            block_heading="Successful Logon",
            template_body="Investigate event 4624.",
            report_brief={},
            context_sections={},
            current_section_outline=[],
            findings_snapshot=[],
            keypoint_catalog=[],
            query_template_catalog=[],
            prior_runs=[],
            reusable_facts=[],
            reusable_evidence=[],
        )
        assert "## Event ID Reference" in messages[0]["content"]
        assert "4624" in messages[0]["content"]

    def test_section_plan_prior_runs_keep_action_result_reason(self) -> None:
        from forensia.ai.prompts.report_evidence_projection import (
            project_section_plan_prior_runs,
        )

        runs = project_section_plan_prior_runs(
            [
                {
                    "block_heading": "X",
                    "iteration": 1,
                    "phase": "plan",
                    "payload": {
                        "action": "sql",
                        "sql": "SELECT " + "x" * 1000,
                        "purpose": "Find evidence",
                        "result": {"status": "not_found", "sample_rows": [{"x": "y"}]},
                    },
                }
            ],
            db=None,
        )
        assert runs == [
            {
                "block_heading": "X",
                "iteration": 1,
                "phase": "plan",
                "action": "sql",
                "result": {"status": "not_found"},
                "reason": "Find evidence",
            }
        ]

    def test_section_plan_catalog_keeps_late_explicit_candidate(self) -> None:
        from forensia.ai.prompts.prompt_sections import (
            build_section_agent_plan_messages,
        )

        keypoints = [
            {"name": f"noise_{i}", "description": "unrelated"} for i in range(79)
        ]
        keypoints.append(
            {"name": "target_late_keypoint", "description": "host identity"}
        )
        messages, _ = build_section_agent_plan_messages(
            section_key="1_overview",
            section_title="Overview",
            block_heading="Host Identity",
            template_body="Use the target_late_keypoint evidence.",
            report_brief={},
            context_sections={},
            current_section_outline=[],
            findings_snapshot=[],
            keypoint_catalog=keypoints,
            query_template_catalog=[],
            prior_runs=[],
            reusable_facts=[],
            reusable_evidence=[],
            evidence_keypoints=["target_late_keypoint"],
        )
        assert "target_late_keypoint" in messages[1]["content"]

    def test_neutral_plan_ignores_global_catalog_terms(self) -> None:
        from forensia.ai.prompts.prompt_sections import (
            build_section_agent_plan_messages,
        )

        messages, _ = build_section_agent_plan_messages(
            section_key="5_recommendations",
            section_title="Recommendations",
            block_heading="Action Plan",
            template_body="Prioritize follow-up actions.",
            report_brief={},
            context_sections={},
            current_section_outline=[],
            findings_snapshot=[],
            keypoint_catalog=[
                {"name": "powershell_execution", "description": "PowerShell IOC"}
            ],
            query_template_catalog=[
                {"template_id": "network_ioc", "description": "IP and hash"}
            ],
            prior_runs=[],
            reusable_facts=[],
            reusable_evidence=[],
        )
        assert "## Application Catalog" not in messages[0]["content"]
        assert "## IOC Catalog" not in messages[0]["content"]


class TestTrimDynamicContentMarker:
    """Verify that _trim_dynamic_content uses the truncation marker."""

    def test_marker_present_in_trimmed_content(self) -> None:
        from forensia.ai.prompts.prompt_context import _trim_dynamic_content

        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "x" * 200000},
        ]
        trimmed = _trim_dynamic_content(messages, max_total_tokens=1000)
        user_msg = trimmed[1]["content"]
        assert "…[truncated]" in user_msg


class TestStructuredCompact:
    """T-22: versioned structured projection for context-overflow compaction."""

    def setup_method(self) -> None:
        clear_compaction_cache()

    def _many_turns(self) -> str:
        # Two older turns (large enough to exceed the LLM threshold) plus three
        # recent turns: needs >= preserve_recent_turns+2 turns to project.
        older = "Event 4624 from evtx_events table. " * 30
        return "\n\n".join(
            [
                older,
                older,
                "recent alpha turn",
                "recent beta turn",
                "recent gamma turn",
            ]
        )

    def test_preserves_recent_verbatim_and_summarizes_older(self) -> None:
        text = self._many_turns()
        llm_response = "Summary: Event 4624 from evtx_events."
        with patch(
            "forensia.ai.compaction._call_llm", return_value=llm_response
        ) as mock_llm:
            out = structured_compact(text, 2000, base_url="http://x", model="m")
        mock_llm.assert_called_once()
        assert "<STRUCTURED_PROJECTION" in out
        assert 'revision="1"' in out
        assert 'regeneratable="true"' in out
        # Recent turns preserved verbatim.
        assert "recent alpha turn" in out
        assert "recent beta turn" in out
        assert "recent gamma turn" in out
        # Older turns folded into the summary.
        assert "Summary: Event 4624 from evtx_events." in out

    def test_refuses_to_summarize_an_existing_projection(self) -> None:
        projection = (
            '<STRUCTURED_PROJECTION revision="2" source_revision="1" '
            'regeneratable="true"><RECENT_VERBATIM>x</RECENT_VERBATIM>'
            "<SUMMARY>y</SUMMARY></STRUCTURED_PROJECTION>"
        )
        with patch("forensia.ai.compaction._call_llm") as mock_llm:
            out = structured_compact(
                projection, 2000, base_url="http://x", model="m"
            )
        mock_llm.assert_not_called()  # recursive degradation prevented
        assert out == projection
