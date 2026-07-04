"""Tests for near-duplicate suppression in facts/timeline tracking (G-4)."""
from __future__ import annotations

import tempfile
import unittest

from forensia.core.case import Case
from forensia.core.memory import MemoryManager


class FuzzyDedupTests(unittest.TestCase):
    """Verify that _append_markdown_entry suppresses near-duplicates via jaccard_similarity."""

    def _make_manager(self) -> MemoryManager:
        tmpdir = tempfile.mkdtemp()
        case = Case.init(tmpdir)
        return MemoryManager(case)

    def test_exact_duplicate_skipped(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line = "- User logged in [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line))
        # Exact same line should be skipped
        self.assertFalse(mm._append_markdown_entry(path, heading, line))

    def test_near_duplicate_same_evidence_skipped(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- The user logged in at 2pm [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Same fact, slightly different wording, same evidence → suppressed
        self.assertFalse(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_near_duplicate_different_evidence_appended(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- The user logged in at 2pm [confirmed | evidence: E-002]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Same fact, different evidence → must be kept
        self.assertTrue(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_different_fact_appended(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- Server crashed at midnight [confirmed | evidence: E-003]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Completely different fact → must be appended
        self.assertTrue(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_fuzzy_dedup_disabled_by_default(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- The user logged in at 2pm [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Without fuzzy_dedup, near-duplicates pass through (existing behavior)
        self.assertTrue(mm._append_markdown_entry(path, heading, line2))

    def test_timeline_near_duplicate_skipped(self):
        mm = self._make_manager()
        path = mm.timeline_path
        heading = "# Timeline"
        line1 = "- 2026-01-01 12:00: User logged in [confirmed | evidence: E-001]"
        line2 = "- 2026-01-01 12:00: The user logged in [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        self.assertFalse(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_extract_line_text(self):
        line = "- [fact-001] User logged in [confirmed | evidence: E-001]"
        self.assertEqual(
            MemoryManager._extract_line_text(line), "User logged in"
        )

    def test_extract_evidence_ids(self):
        line = "- User logged in [confirmed | evidence: E-001, E-002]"
        self.assertEqual(
            MemoryManager._extract_evidence_ids(line), ["E-001", "E-002"]
        )

    def test_extract_evidence_ids_none(self):
        line = "- User logged in [confirmed]"
        self.assertEqual(MemoryManager._extract_evidence_ids(line), [])


class AppendConfirmedFactFuzzyDedupTests(unittest.TestCase):
    """Integration tests for append_confirmed_fact with fuzzy dedup."""

    def _make_manager(self) -> MemoryManager:
        tmpdir = tempfile.mkdtemp()
        case = Case.init(tmpdir)
        return MemoryManager(case)

    def test_same_fact_different_words_skipped(self):
        mm = self._make_manager()
        mm.append_confirmed_fact("User logged in at 2pm", ["E-001"])
        # Same fact, slightly reworded → suppressed
        mm.append_confirmed_fact("The user logged in at 2pm", ["E-001"])
        content = mm.facts_path.read_text()
        # Should contain only one fact entry
        self.assertEqual(content.count("[fact-"), 1)

    def test_same_fact_different_evidence_kept(self):
        mm = self._make_manager()
        mm.append_confirmed_fact("User logged in at 2pm", ["E-001"])
        mm.append_confirmed_fact("User logged in at 2pm", ["E-002"])
        content = mm.facts_path.read_text()
        # Different evidence → both kept
        self.assertEqual(content.count("[fact-"), 2)

    def test_different_fact_kept(self):
        mm = self._make_manager()
        mm.append_confirmed_fact("User logged in at 2pm", ["E-001"])
        mm.append_confirmed_fact("Server crashed at midnight", ["E-003"])
        content = mm.facts_path.read_text()
        self.assertEqual(content.count("[fact-"), 2)


class AppendTimelineFuzzyDedupTests(unittest.TestCase):
    """Integration tests for append_timeline_anchor with fuzzy dedup."""

    def _make_manager(self) -> MemoryManager:
        tmpdir = tempfile.mkdtemp()
        case = Case.init(tmpdir)
        return MemoryManager(case)

    def test_same_event_different_words_skipped(self):
        mm = self._make_manager()
        mm.append_timeline_anchor("2026-01-01 12:00", "User logged in", ["E-001"])
        mm.append_timeline_anchor(
            "2026-01-01 12:00", "The user logged in", ["E-001"]
        )
        content = mm.timeline_path.read_text()
        self.assertEqual(content.count("- 2026-01-01"), 1)

    def test_same_event_different_evidence_kept(self):
        mm = self._make_manager()
        mm.append_timeline_anchor("2026-01-01 12:00", "User logged in", ["E-001"])
        mm.append_timeline_anchor("2026-01-01 12:00", "User logged in", ["E-002"])
        content = mm.timeline_path.read_text()
        self.assertEqual(content.count("- 2026-01-01"), 2)


if __name__ == "__main__":
    unittest.main()
