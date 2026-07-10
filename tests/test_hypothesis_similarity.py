"""Regression tests for hypothesis similarity / semantic triple extraction."""

from __future__ import annotations

import tempfile

from forensia.ai.hypotheses.hypothesis_manager import _merge_active_hypotheses
from forensia.ai.hypotheses.hypothesis_model import (
    _extract_semantic_triple,
    _hypothesis_evidence_strength,
    _hypothesis_similarity,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB


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


class TestResolvedHypothesisDedup:
    """Regression: near-duplicate of a resolved hypothesis must not create
    a conflicting active hypothesis with opposite verdict."""

    def test_similar_to_resolved_is_bound_not_duplicated(self, capsys) -> None:
        """Hypothesis B with a near-identical description to a confirmed
        resolved hypothesis A is bound to A, not added as a separate active."""
        desc_a = "RDP lateral movement to deploy service on remote host"
        desc_b = "RDP lateral movement was used to deploy service on remote host"

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Persist H-001 as confirmed (resolved)
                db.execute(
                    """INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES (
                        'H-001', ?, 'confirmed', 'confirmed', 'done', 'broad_plan',
                        'S-1', 'S-2', now(), now(), '["rule-1"]', '["host"]', NULL
                    )""",
                    (desc_a,),
                )

                resolved = [
                    Hypothesis(
                        id="H-001",
                        description=desc_a,
                        status="confirmed",
                        verdict="confirmed",
                        summary="done",
                        source_rule_ids=["rule-1"],
                    ),
                ]

                merged = _merge_active_hypotheses(
                    db=db,
                    current=[],
                    updates=[
                        Hypothesis(
                            id="H-new",
                            description=desc_b,
                            status="active",
                            source_rule_ids=["rule-2"],
                            required_entities=["host"],
                        ),
                    ],
                    resolved=resolved,
                    session_id="session-test",
                    origin="broad_plan",
                )

                # B should NOT appear as a separate active hypothesis
                assert len(merged) == 0, (
                    f"expected no active hypotheses, got {len(merged)}: "
                    f"{[h.description for h in merged]}"
                )

                # The resolved hypothesis should still be in DB with its verdict
                rows = db.execute(
                    "SELECT hypothesis_id, status, verdict "
                    "FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()
                assert len(rows) == 1, f"expected 1 row, got {len(rows)}"
                assert rows[0][0] == "H-001"
                assert rows[0][1] == "confirmed", (
                    f"resolved hypothesis status changed to {rows[0][1]}"
                )
                assert rows[0][2] == "confirmed"

                # Verify log records the binding decision
                captured = capsys.readouterr()
                assert "bound to resolved H-001" in captured.out, (
                    f"expected log about binding, got: {captured.out}"
                )

    def test_identical_to_resolved_not_duplicated(self, capsys) -> None:
        """Exact description match against a resolved hypothesis
        does not create a new active hypothesis."""
        desc = "Backdoor via service install using explicit credentials"

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES (
                        'H-004', ?, 'confirmed', 'confirmed',
                        'confirmed by evidence', 'broad_plan',
                        'S-1', 'S-2', now(), now(),
                        '["rule-backdoor"]', '["service"]',
                        '{"co_observed_event_ids": ["E-001"]}'
                    )""",
                    (desc,),
                )

                resolved = [
                    Hypothesis(
                        id="H-004",
                        description=desc,
                        status="confirmed",
                        verdict="confirmed",
                        summary="confirmed by evidence",
                        source_rule_ids=["rule-backdoor"],
                        confirm_when={"co_observed_event_ids": ["E-001"]},
                    ),
                ]

                merged = _merge_active_hypotheses(
                    db=db,
                    current=[],
                    updates=[
                        Hypothesis(
                            id="H-draft",
                            description=desc,
                            status="active",
                            source_rule_ids=["rule-backdoor"],
                            required_entities=["service"],
                        ),
                    ],
                    resolved=resolved,
                    session_id="session-test",
                    origin="broad_plan",
                )

                # Should not be added to active
                assert len(merged) == 0

                captured = capsys.readouterr()
                assert "bound to resolved H-004" in captured.out


class TestHypothesisEvidenceStrength:
    """Unit tests for _hypothesis_evidence_strength scoring."""

    def test_llm_speculated_scores_zero(self) -> None:
        h = Hypothesis(
            id="H-000",
            description="LLM-speculated hypothesis",
            status="active",
        )
        assert _hypothesis_evidence_strength(h) == 0

    def test_rule_seeded_only_scores_one(self) -> None:
        h = Hypothesis(
            id="H-001",
            description="Rule-seeded hypothesis",
            status="active",
            source_rule_ids=["rule-1"],
        )
        assert _hypothesis_evidence_strength(h) == 1

    def test_rule_seeded_with_evidence_scores_two(self) -> None:
        h = Hypothesis(
            id="H-002",
            description="Rule-seeded with evidence",
            status="active",
            source_rule_ids=["rule-1"],
            confirm_when={"co_observed_event_ids": ["E-001"]},
        )
        assert _hypothesis_evidence_strength(h) == 2

    def test_zero_rows_placeholder_not_strong_evidence(self) -> None:
        h = Hypothesis(
            id="H-003",
            description="Rule-seeded with zero_rows placeholder",
            status="active",
            source_rule_ids=["rule-1"],
            confirm_when={"zero_rows": True},
        )
        assert _hypothesis_evidence_strength(h) == 1

    def test_refute_when_also_counts_as_evidence(self) -> None:
        h = Hypothesis(
            id="H-004",
            description="Rule-seeded with refute criteria",
            status="active",
            source_rule_ids=["rule-1"],
            refute_when={"co_observed_event_ids": ["E-002"]},
        )
        assert _hypothesis_evidence_strength(h) == 2
