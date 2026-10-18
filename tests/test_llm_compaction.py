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
