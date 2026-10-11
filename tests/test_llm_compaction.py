"""Tests for forensia.llm.compaction — stage-2 LLM compaction with guards."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from forensia.core.compaction import TRUNCATION_MARKER
from forensia.llm.compaction import (
    CompactionPreservationError,
    llm_compact,
    structured_compact,
)


class TestLlmCompact:
    def test_budget_exhaustion_propagates_instead_of_falling_back(self) -> None:
        from forensia.core.session import LLMBudgetExceededError

        text = "Event 4624 from evtx_events. " * 50
        with patch(
            "forensia.llm.compaction._call_llm",
            side_effect=LLMBudgetExceededError(1, 1),
        ):
            with pytest.raises(LLMBudgetExceededError):
                llm_compact(text, 200, base_url="http://x", model="m")

    def test_mechanical_sufficiency(self) -> None:
        """When text < 1.5x budget, mechanical is used (no LLM call)."""
        text = "x" * 140  # 140 < 100 * 1.5
        with patch("forensia.llm.compaction._call_llm") as mock_llm:
            assert (
                llm_compact("short text", 100, base_url="http://x", model="m")
                == "short text"
            )
            assert llm_compact("text", 0, base_url="http://x", model="m") == ""
            result = llm_compact(text, 100, base_url="http://x", model="m")
        mock_llm.assert_not_called()
        assert len(result) <= 100
        assert TRUNCATION_MARKER in result

    def test_fallback_on_llm_exception(self) -> None:
        text = "Event 4624 from evtx_events. " * 50
        with patch(
            "forensia.llm.compaction._call_llm", side_effect=RuntimeError("LLM down")
        ):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert len(result) <= 200
        assert TRUNCATION_MARKER in result

    def test_fallback_on_missing_essential_tokens(self) -> None:
        source_hash = "a" * 64
        registry_hash = "b" * 64
        anchors = (
            rf"4624 evtx_events evtx-{source_hash}-security-000000000001 "
            rf"registry-{registry_hash} registry_artifacts "
            r"C:\Temp\trace.evtx /cases/trace.evtx"
        )
        text = anchors + "\n" + "Investigation detail. " * 100
        # A plausible summary keeps the event/table but loses evidence identity and paths.
        llm_response = "Summary: Event 4624 from evtx_events on host WS-01."
        with patch("forensia.llm.compaction._call_llm", return_value=llm_response):
            result = llm_compact(text, 400, base_url="http://x", model="m")
        assert TRUNCATION_MARKER in result
        assert "4624" in result and "evtx_events" in result
        assert all(anchor in result for anchor in anchors.split())
        assert len(result) <= 400

    def test_fallback_on_empty_llm_output(self) -> None:
        text = "Event 4624 from evtx_events. " * 50
        with patch("forensia.llm.compaction._call_llm", return_value=""):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert len(result) <= 200
        assert result  # not empty

    def test_followup_compaction_cannot_drop_essential_tokens(self) -> None:
        text = "Event 4624 from evtx_events. " + "original detail. " * 100
        llm_response = "x" * 500 + " Event 4624 from evtx_events"
        with patch("forensia.llm.compaction._call_llm", return_value=llm_response):
            result = llm_compact(text, 200, base_url="http://x", model="m")
        assert "4624" in result
        assert "evtx_events" in result
        assert len(result) <= 200

    def test_repeated_call_does_not_reuse_generated_summary(self) -> None:
        text = "Event 4624 from evtx_events table. " * 50
        llm_response = "Summarised: Event 4624 from evtx_events."
        with patch(
            "forensia.llm.compaction._call_llm", return_value=llm_response
        ) as mock_llm:
            r1 = llm_compact(text, 200, base_url="http://x", model="m")
            r2 = llm_compact(text, 200, base_url="http://x", model="m")
        assert r1 == r2
        assert r1 == llm_response
        assert "4624" in r1 and "evtx_events" in r1
        assert mock_llm.call_count == 2

    def test_each_call_uses_its_requested_budget(self) -> None:
        text = "Event 4624 from evtx_events table. " * 50
        llm_response_200 = "A" * 180
        llm_response_300 = "B" * 280
        with patch(
            "forensia.llm.compaction._call_llm",
            side_effect=[llm_response_200, llm_response_300],
        ) as mock_llm:
            r1 = llm_compact(text, 200, base_url="http://x", model="m")
            r2 = llm_compact(text, 300, base_url="http://x", model="m")
        assert mock_llm.call_count == 2
        assert r1 != r2

    def test_impossible_required_reference_preservation_is_explicit(self) -> None:
        with (
            patch("forensia.llm.compaction._call_llm", return_value="details"),
            pytest.raises(CompactionPreservationError, match="too small"),
        ):
            llm_compact(
                "evtx_events " + "details " * 100,
                8,
                base_url="http://x",
                model="m",
            )

    def test_preserve_pattern_with_capture_group_uses_full_match(self) -> None:
        text = ("case evidence ABC-1234 should remain. " * 30).strip()
        response = "case evidence ABC-1234 should remain."
        with patch("forensia.llm.compaction._call_llm", return_value=response):
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

    def test_compacted_xml_section_keeps_closing_tag(self) -> None:
        from forensia.context.prompt_context import _enforce_system_budget

        playbook = "A" * 5000
        knowledge_lines = "\n".join(f"knowledge line {i}" for i in range(600))
        system = f"{playbook}\n<ORG_KNOWLEDGE>\n{knowledge_lines}\n</ORG_KNOWLEDGE>\n"
        result = _enforce_system_budget(system, budget_chars=10000)
        assert len(result) <= 10000
        if "<ORG_KNOWLEDGE>" in result:
            assert "</ORG_KNOWLEDGE>" in result

    def test_real_section_plan_prompt_respects_default_budget(self) -> None:
        from forensia.config import Settings, settings_scope
        from forensia.context.prompt_context import _enforce_system_budget
        from forensia.report.sections.prompts import (
            build_section_agent_plan_messages,
        )

        with settings_scope(Settings()):
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

    def test_real_section_plan_retains_question_specific_reference(self) -> None:
        from forensia.config import Settings, settings_scope
        from forensia.context.prompt_context import _enforce_system_budget
        from forensia.report.sections.prompts import (
            build_section_agent_plan_messages,
        )

        with settings_scope(Settings()):
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

    def test_section_plan_uses_neutral_playbook_for_methodology(self) -> None:
        from forensia.report.sections.prompts import (
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
        assert (
            "report_brief: {'investigation_objective': 'Assess activity'}"
            in messages[1]["content"]
        )

    def test_section_plan_scopes_event_reference_to_contract(self) -> None:
        from forensia.report.sections.prompts import (
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
        from forensia.report.sections.evidence_projection import (
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
        from forensia.report.sections.prompts import (
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
        from forensia.report.sections.prompts import (
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


class TestStructuredCompact:
    """R10: bounded context-overflow reduction with an honest contract.

    The reduction is one-way: it keeps the most recent sections verbatim,
    preserves essential tokens, and labels what is preserved — it never
    claims a revision/source origin it cannot verify or that the original is
    reconstructible.
    """

    def _many_sections(self) -> str:
        # Two older sections (large enough to exceed the LLM threshold) plus
        # three recent ones: needs >= preserve_recent_sections+2 sections.
        older = "Event 4624 from evtx_events table. " * 30
        return "\n\n".join(
            [
                older,
                older,
                "recent alpha section",
                "recent beta section",
                "recent gamma section",
            ]
        )

    def test_preserves_recent_section_and_condenses_older(self) -> None:
        text = self._many_sections()
        llm_response = "Summary: Event 4624 from evtx_events."
        with patch(
            "forensia.llm.compaction._call_llm", return_value=llm_response
        ) as mock_llm:
            out = structured_compact(text, 2000, base_url="http://x", model="m")
        mock_llm.assert_called_once()
        # One-way reduction statement, no fabricated revision/regeneratable
        # labels: nothing guarantees reconstruction of the original.
        assert "<COMPACTED_CONTEXT" in out
        assert "nothing is re-generated" in out
        assert "regeneratable" not in out.lower()
        assert 'revision="' not in out
        assert 'source_revision="' not in out
        assert "<STRUCTURED_PROJECTION" not in out
        assert "RECENT_VERBATIM" not in out
        # The latest sections kept verbatim; older ones condensed.
        assert "recent alpha section" in out
        assert "recent beta section" in out
        assert "recent gamma section" in out
        assert "Summary: Event 4624 from evtx_events." in out

    def test_reducing_a_reduction_changes_nothing(self) -> None:
        with patch(
            "forensia.llm.compaction._call_llm",
            return_value="Summary: Event 4624 from evtx_events table.",
        ) as first_call:
            first = structured_compact(
                self._many_sections(), 2000, base_url="http://x", model="m"
            )
        first_call.assert_called_once()
        # Content already produced by this reduction is never reduced again
        # (no recursive degradation).
        with patch("forensia.llm.compaction._call_llm") as mock_llm:
            out = structured_compact(first, 2000, base_url="http://x", model="m")
        mock_llm.assert_not_called()
        assert out == first
