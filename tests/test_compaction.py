"""Tests for forensia.core.compaction — stage-1 mechanical compaction."""

from __future__ import annotations

from forensia.core.compaction import TRUNCATION_MARKER, mechanical_compact


class TestMechanicalCompact:
    def test_under_budget_returned_unchanged(self) -> None:
        assert mechanical_compact("short text", 100) == "short text"

    def test_zero_or_negative_budget_returns_empty(self) -> None:
        assert mechanical_compact("text", 0) == ""
        assert mechanical_compact("text", -5) == ""

    def test_blank_run_collapse_may_avoid_truncation(self) -> None:
        text = "a\n\n\n\n\nb"
        out = mechanical_compact(text, 5)
        assert out == "a\n\nb"

    def test_truncates_at_line_boundary_with_marker(self) -> None:
        text = "\n".join(f"line {i:02d}" for i in range(50))
        out = mechanical_compact(text, 100)
        assert len(out) <= 100
        assert out.endswith(TRUNCATION_MARKER)
        # No partial line before the marker
        body = out[: -len(TRUNCATION_MARKER)].rstrip("\n")
        assert all(line.startswith("line ") for line in body.splitlines())

    def test_single_long_line_hard_cut(self) -> None:
        text = "x" * 500
        out = mechanical_compact(text, 50)
        assert len(out) <= 50
        assert out.endswith(TRUNCATION_MARKER)

    def test_deterministic(self) -> None:
        text = "\n".join(f"line {i}" for i in range(100))
        assert mechanical_compact(text, 200) == mechanical_compact(text, 200)

    def test_budget_never_exceeded(self) -> None:
        text = "\n".join(f"some longer line of text number {i}" for i in range(30))
        for budget in (10, 50, 100, 333, 1000):
            assert len(mechanical_compact(text, budget)) <= budget
