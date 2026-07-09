"""Unit tests for T-05b: immediate untestable resolution on unavailable event IDs."""

from __future__ import annotations

from forensia.ai.hypothesis_runner import _unavailable_missing_event_ids


class TestUnavailableMissingEventIds:
    def test_all_missing_ids_unavailable(self) -> None:
        """missing_questions name only event IDs absent from the case → returned."""
        result = _unavailable_missing_event_ids(
            ["event_id 4663 file access", "event 4688 process creation"],
            available_event_ids={4624, 4648, 1100},
        )
        assert result == [4663, 4688]

    def test_some_id_available_keeps_investigating(self) -> None:
        """at least one referenced ID exists in the case → empty (keep going)."""
        result = _unavailable_missing_event_ids(
            ["event_id 4663", "event_id 4624"],
            available_event_ids={4624},
        )
        assert result == []

    def test_artifact_table_alternative_keeps_investigating(self) -> None:
        """missing questions that also point at mft/prefetch stay testable."""
        result = _unavailable_missing_event_ids(
            ["event_id 4663, or check mft_entries WHERE file_path LIKE '%.docx'"],
            available_event_ids={4624},
        )
        assert result == []

    def test_no_profile_returns_empty(self) -> None:
        result = _unavailable_missing_event_ids(["event_id 4663"], None)
        assert result == []

    def test_no_event_id_reference_returns_empty(self) -> None:
        """plain-text missing questions without known event IDs → empty."""
        result = _unavailable_missing_event_ids(
            ["need firewall logs", "correlate with proxy data from 2015"],
            available_event_ids={4624},
        )
        assert result == []

    def test_counts_and_years_are_not_event_ids(self) -> None:
        """numbers outside the event-id vocabulary (years, row counts) are ignored."""
        result = _unavailable_missing_event_ids(
            ["found 5199 rows in 2015 but need more"],
            available_event_ids={4624},
        )
        assert result == []
