"""Regression tests for hypothesis similarity / semantic triple extraction."""

from __future__ import annotations

from forensia.ai.hypothesis_manager import (
    _extract_semantic_triple,
    _hypothesis_similarity,
)


class TestExtractSemanticTriple:
    def test_target_fallback_pattern_does_not_crash(self) -> None:
        """Descriptions with a target keyword but no 'to/on/into/onto <word>' phrase
        previously raised IndexError (fallback pattern had no capturing group)."""
        triple = _extract_semantic_triple(
            "Repeated 4625 failures targeting one account indicate brute-force"
        )
        assert triple["target"] == "account"

    def test_full_triple(self) -> None:
        triple = _extract_semantic_triple(
            "Lateral movement by attacker to a server via stolen credentials"
        )
        assert triple["actor"] not in ("", None)
        assert triple["action"] == "lateral movement"
        assert triple["target"] == "server"

    def test_empty_description(self) -> None:
        triple = _extract_semantic_triple("")
        assert triple == {"actor": "unknown", "action": "unknown", "target": "unknown"}


class TestHypothesisSimilarity:
    def test_similarity_handles_keyword_only_descriptions(self) -> None:
        """End-to-end: similarity between rule-seeded style descriptions must not raise."""
        left = "Explicit credential logon for account informant may indicate misuse"
        right = "Service installed shortly after logon suggests persistence"
        score = _hypothesis_similarity(left, right)
        assert 0.0 <= score <= 1.0

    def test_identical_descriptions_score_high(self) -> None:
        text = "Repeated failed logons from a single source ip targeting one user"
        assert _hypothesis_similarity(text, text) >= 0.85
