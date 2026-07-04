"""Tests for hypothesis-scoped entity/keypoint selection (G-3)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from forensia.core.case import Case
from forensia.core.memory import MemoryManager


class TokenizeTests(unittest.TestCase):
    """Unit tests for MemoryManager._tokenize."""

    def test_basic_split(self):
        result = MemoryManager._tokenize("User logged in at 2pm")
        self.assertIn("user", result)
        self.assertIn("logged", result)
        self.assertIn("2pm", result)

    def test_casefold(self):
        result = MemoryManager._tokenize("Alice BOB charlie")
        self.assertEqual(result, {"alice", "bob", "charlie"})

    def test_single_char_excluded(self):
        result = MemoryManager._tokenize("a is the X")
        self.assertNotIn("a", result)
        self.assertIn("is", result)
        self.assertIn("the", result)


class FileMatchesRelevanceTests(unittest.TestCase):
    """Unit tests for MemoryManager._file_matches_relevance."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Create a simple file with known content
        ent_dir = self.tmpdir / "entities" / "user"
        ent_dir.mkdir(parents=True)
        (ent_dir / "ALICE_SMITH.md").write_text(
            "# Alice Smith\n\n- Active directory account for alice\n",
            encoding="utf-8",
        )
        (ent_dir / "BOB_JONES.md").write_text(
            "# Bob Jones\n\n- Service account for bob\n",
            encoding="utf-8",
        )
        self.rel_path_alice = "entities/user/ALICE_SMITH.md"
        self.rel_path_bob = "entities/user/BOB_JONES.md"

    def test_filename_match(self):
        terms = {"alice"}
        self.assertTrue(
            MemoryManager._file_matches_relevance(
                self.rel_path_alice, self.tmpdir, terms
            )
        )

    def test_filename_no_match(self):
        terms = {"alice"}
        self.assertFalse(
            MemoryManager._file_matches_relevance(
                self.rel_path_bob, self.tmpdir, terms
            )
        )

    def test_content_match(self):
        # "service" is in Bob's content, not filename
        terms = {"service"}
        self.assertTrue(
            MemoryManager._file_matches_relevance(
                self.rel_path_bob, self.tmpdir, terms
            )
        )

    def test_content_no_match(self):
        terms = {"firewall"}
        self.assertFalse(
            MemoryManager._file_matches_relevance(
                self.rel_path_alice, self.tmpdir, terms
            )
        )

    def test_nonexistent_file(self):
        terms = {"alice"}
        self.assertFalse(
            MemoryManager._file_matches_relevance(
                "entities/user/NOPE.md", self.tmpdir, terms
            )
        )


class BuildRelevanceTermsTests(unittest.TestCase):
    """Unit tests for MemoryManager.build_relevance_terms_from_hypothesis."""

    def test_none_hypothesis(self):
        self.assertEqual(MemoryManager.build_relevance_terms_from_hypothesis(None), set())

    def test_extracts_description_tokens(self):
        hyp = SimpleNamespace(
            description="Compromised user alice via phishing",
            required_entities=[],
        )
        terms = MemoryManager.build_relevance_terms_from_hypothesis(hyp)
        self.assertIn("compromised", terms)
        self.assertIn("alice", terms)
        self.assertIn("phishing", terms)

    def test_extracts_required_entities(self):
        hyp = SimpleNamespace(
            description="Investigate lateral movement",
            required_entities=["alice-smith", "file-server-01"],
        )
        terms = MemoryManager.build_relevance_terms_from_hypothesis(hyp)
        self.assertIn("alice", terms)
        self.assertIn("smith", terms)
        self.assertIn("file", terms)
        self.assertIn("server", terms)


class InvestigationContextFilesRelevanceTests(unittest.TestCase):
    """Integration tests for investigation_context_files with relevance filtering."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.case = Case.init(self.tmpdir)
        self.mm = MemoryManager(self.case)

        # Create 10 entity files: 2 related to "alice", 8 unrelated
        ent_dir = self.mm.entities_dir
        ent_user_dir = ent_dir / "user"
        ent_user_dir.mkdir(parents=True, exist_ok=True)
        ent_host_dir = ent_dir / "host"
        ent_host_dir.mkdir(parents=True, exist_ok=True)
        ent_ip_dir = ent_dir / "ip"
        ent_ip_dir.mkdir(parents=True, exist_ok=True)

        # 2 related to alice
        (ent_user_dir / "ALICE_SMITH.md").write_text(
            "# Alice Smith\n- User account alice-smith [confirmed]\n",
            encoding="utf-8",
        )
        (ent_host_dir / "WORKSTATION-ALICE.md").write_text(
            "# WORKSTATION-ALICE\n- Host used by alice-smith\n",
            encoding="utf-8",
        )
        # 8 unrelated
        for name in [
            "BOB_JONES", "CHARLIE_BROWN", "DAVE_WILSON", "EVE_ADAMS",
            "FRANK_MILLER", "GRACE_HOPPER", "HELEN_PARK", "IVAN_PETROV",
        ]:
            subdir = ent_user_dir if name in ("BOB_JONES", "CHARLIE_BROWN") else ent_ip_dir
            subdir.mkdir(parents=True, exist_ok=True)
            (subdir / f"{name}.md").write_text(
                f"# {name}\n- Some unrelated entity\n", encoding="utf-8"
            )

        # Create 2 keypoint files: 1 related, 1 unrelated
        kp_dir = self.mm.keypoints_dir
        kp_dir.mkdir(parents=True, exist_ok=True)
        (kp_dir / "KP-ALICE-MOVEMENT.md").write_text(
            "# KP Alice Movement\n- Alice moved laterally from workstation\n",
            encoding="utf-8",
        )
        (kp_dir / "KP-BOB-LOGIN.md").write_text(
            "# KP Bob Login\n- Bob logged in at 9am\n",
            encoding="utf-8",
        )

    def test_no_relevance_returns_all_entities(self):
        """Without relevance_terms, all entity files are included."""
        files = self.mm.investigation_context_files(
            include_overview=False, include_archive=False,
            include_keypoints=False, include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        self.assertEqual(len(entity_files), 10)

    def test_empty_relevance_returns_all_entities(self):
        """Empty relevance_terms should include all entity files (backward compat)."""
        files = self.mm.investigation_context_files(
            relevance_terms=set(),
            include_overview=False, include_archive=False,
            include_keypoints=False, include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        self.assertEqual(len(entity_files), 10)

    def test_relevance_filters_entities(self):
        """With alice-related terms, only 2 entity files should be returned."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False, include_archive=False,
            include_keypoints=False, include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        self.assertEqual(len(entity_files), 2)
        names = {Path(f).stem for f in entity_files}
        self.assertIn("ALICE_SMITH", names)
        self.assertIn("WORKSTATION-ALICE", names)

    def test_relevance_filters_keypoints(self):
        """With alice-related terms, only the alice keypoint should be returned."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False, include_archive=False,
            include_entities=False, include_scratch=False,
        )
        kp_files = [f for f in files if f.startswith("keypoints/")]
        self.assertEqual(len(kp_files), 1)
        self.assertIn("ALICE", Path(kp_files[0]).stem)

    def test_relevance_filters_both_entities_and_keypoints(self):
        """Combined filtering of entities and keypoints."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False, include_archive=False, include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        kp_files = [f for f in files if f.startswith("keypoints/")]
        self.assertEqual(len(entity_files), 2)
        self.assertEqual(len(kp_files), 1)

    def test_overview_files_not_filtered(self):
        """Overview/archive/scratch files are never filtered by relevance_terms."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_entities=False, include_keypoints=False,
        )
        # overview.md, facts.md, timeline.md, tasks.md should always be present
        self.assertIn("overview.md", files)
        self.assertIn("facts.md", files)

    def test_no_matching_terms_returns_empty_entities(self):
        """If relevance_terms don't match anything, entity/keypoint lists are empty."""
        terms = {"zzzznonexistent"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False, include_archive=False, include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        kp_files = [f for f in files if f.startswith("keypoints/")]
        self.assertEqual(len(entity_files), 0)
        self.assertEqual(len(kp_files), 0)


class LoadInvestigationContextRelevanceTests(unittest.TestCase):
    """Integration test for load_investigation_context passing relevance_terms."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.case = Case.init(self.tmpdir)
        self.mm = MemoryManager(self.case)

        ent_user_dir = self.mm.entities_dir / "user"
        ent_user_dir.mkdir(parents=True, exist_ok=True)
        (ent_user_dir / "ALICE_SMITH.md").write_text(
            "# Alice Smith\n- User account alice-smith\n",
            encoding="utf-8",
        )
        (ent_user_dir / "BOB_JONES.md").write_text(
            "# Bob Jones\n- Unrelated entity bob-jones\n",
            encoding="utf-8",
        )

    def test_load_investigation_context_filters(self):
        """load_investigation_context should pass relevance_terms through."""
        context = self.mm.load_investigation_context(
            relevance_terms={"alice"},
            include_overview=False, include_archive=False,
            include_keypoints=False, include_scratch=False,
            max_bytes=100_000,
        )
        # Should contain alice file but not bob file
        self.assertIn("alice-smith", context.lower())
        self.assertNotIn("bob-jones", context.lower())


if __name__ == "__main__":
    unittest.main()


def test_ctx_refresh_caches_forwards_relevance_terms() -> None:
    """The investigator's preloaded contexts must carry relevance filtering.

    Why: ctx.memory_plan / ctx.memory_check are handed to the planner and
    checker as their default context, which SKIPS the lazy-load fallbacks
    where relevance filtering also lives. If the preload does not filter,
    G-3 is inert for the whole main investigation loop.
    """
    from unittest.mock import MagicMock

    from forensia.ai.investigator import _Ctx, _ctx_refresh_caches
    from forensia.core.memory import MemoryManager
    from forensia.core.session import Hypothesis

    memory = MagicMock()
    memory.max_bytes = 16384
    memory.load_compact_context.return_value = ""
    memory.load_investigation_context.return_value = ""
    memory.build_relevance_terms_from_hypothesis.side_effect = (
        MemoryManager.build_relevance_terms_from_hypothesis
    )

    hypothesis = Hypothesis(
        id="H-001",
        description="credential reuse by informant",
        required_entities=["target_user"],
    )
    _ctx_refresh_caches(_Ctx(), memory, "http://localhost", "m", hypothesis=hypothesis)

    calls = memory.load_investigation_context.call_args_list
    assert len(calls) == 2  # memory_plan and memory_check
    for call in calls:
        terms = call.kwargs.get("relevance_terms")
        assert terms, "preloaded context must be relevance-filtered"
        assert "informant" in terms
        assert call.args[0] == "H-001" or call.kwargs.get("hypothesis_id") == "H-001"
