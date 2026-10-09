"""Tests for hypothesis lifecycle in hypothesis_manager / hypothesis_model.

Covers:
  - similarity / semantic triple extraction used to merge duplicate hypotheses
  - stale propagation from hypothesis resolution to report sections
    (target_keypoint_id -> owning section, description keyword matching,
    rulepack-declared report_sections, update_count cap enforcement)
"""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.checking.assessment import assess_evidence_group
from forensia.ai.checking.check_guardrails import _co_observation_satisfied
from forensia.ai.hypotheses.hypothesis_manager import (
    MAX_SECTION_UPDATES,
    admit_new_hypothesis,
    merge_active_hypotheses,
    qualify_event_contexts,
    resolve_hypothesis,
)
from forensia.ai.hypotheses.hypothesis_model import (
    extract_semantic_triple,
    hypothesis_evidence_strength,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.report.sections.section_quality import _event_claim_gaps
from forensia.report.sections.section_taxonomy import sections_for_keypoint


class TestHypothesisAdmissionConformance(unittest.TestCase):
    def test_rejects_unmaterialized_or_unverifiable_claims(self) -> None:
        state = SessionState(session_id="S-admission")

        def admission(description: str, condition: dict) -> tuple[bool, str]:
            candidate = Hypothesis(
                id="draft-test",
                description=description,
                required_entities=["src_ip", "target_user"],
                confirm_when=condition,
            )
            return admit_new_hypothesis(candidate, state)

        self.assertEqual(
            (False, "unresolved-placeholder"),
            admission(
                "Execution from {src_ip} against target_user", {"event_id": 4624}
            ),
        )
        self.assertEqual(
            (False, "empty-verification-spec"),
            admission("Account change requires investigation", {}),
        )
        description = (
            "Repeated logon events from a single src_ip to the same target_user "
            "within 30 minutes indicate automated access"
        )
        base = {"co_observed_event_ids": [4624, 4625], "within_minutes": 30}
        self.assertEqual(
            (False, "claim-spec-entity-correlation-missing"),
            admission(description, base),
        )
        self.assertEqual(
            (True, "accepted"),
            admission(
                description,
                {**base, "same_entities": ["src_ip", "target_user"], "min_count": 2},
            ),
        )

    def test_rejects_known_event_reinterpretations(self) -> None:
        state = SessionState(session_id="S-semantic")
        for description, event_id in (
            ("Process creation (4672)", 4672),
            ("Password reset (4624)", 4624),
        ):
            with self.subTest(event_id=event_id):
                candidate = Hypothesis(
                    id="draft-semantic",
                    description=description,
                    required_entities=["computer"],
                    confirm_when={"co_observed_event_ids": [event_id]},
                )
                self.assertEqual(
                    (False, f"event-semantic-mismatch:{event_id}"),
                    admit_new_hypothesis(candidate, state),
                )

    def test_rejects_account_lifecycle_event_reinterpretations(self) -> None:
        state = SessionState(session_id="S-lifecycle-semantic")
        for description, event_id in (
            ("Account deleted (4722)", 4722),
            ("User enabled (4727)", 4727),
            ("Account enabled (4726)", 4726),
        ):
            with self.subTest(event_id=event_id):
                candidate = Hypothesis(
                    id="draft-lifecycle-semantic",
                    description=description,
                    required_entities=["computer"],
                    confirm_when={
                        "co_observed_event_ids": [event_id],
                        "event_contexts": [
                            {
                                "event_id": event_id,
                                "channel": "Security",
                                "provider": "Microsoft-Windows-Security-Auditing",
                            }
                        ],
                    },
                )
                self.assertEqual(
                    (False, f"event-semantic-mismatch:{event_id}"),
                    admit_new_hypothesis(candidate, state),
                )

    def test_event_context_is_catalog_qualified(self) -> None:
        state = SessionState(session_id="S-provider-semantic")
        valid = Hypothesis(
            id="draft-powershell",
            description="PowerShell script block execution was observed",
            required_entities=["computer"],
            confirm_when={
                "co_observed_event_ids": [4104],
                "event_contexts": [
                    {
                        "event_id": 4104,
                        "channel": "Microsoft-Windows-PowerShell/Operational",
                        "provider": "Microsoft-Windows-PowerShell",
                    }
                ],
            },
        )
        self.assertEqual((True, "accepted"), admit_new_hypothesis(valid, state))
        # Admission and Assessment share one condition vocabulary: a spec
        # admitted with event_contexts must be evaluable by Assessment.
        admitted_rows = [
            {
                "evidence_id": "evtx-1",
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "raw_json": {
                    "winlog": {"provider": {"name": "Microsoft-Windows-PowerShell"}}
                },
            }
        ]
        assessment = assess_evidence_group(
            hypothesis=valid,
            rows=admitted_rows,
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(assessment.role, "supporting")
        invalid = Hypothesis(
            id="draft-winlogon",
            description=valid.description,
            required_entities=["computer"],
            confirm_when={
                "co_observed_event_ids": [4104],
                "event_contexts": [
                    {
                        "event_id": 4104,
                        "channel": "Application",
                        "provider": "Microsoft-Windows-Winlogon",
                    }
                ],
            },
        )
        self.assertEqual(
            (False, "event-context-mismatch:4104"),
            admit_new_hypothesis(invalid, state),
        )

    def test_context_list_may_omit_unconstrained_co_observed_ids(self) -> None:
        candidate = Hypothesis(
            id="draft-mixed-context",
            description="RDP followed by PowerShell script block execution",
            required_entities=["computer"],
            confirm_when={
                "co_observed_event_ids": [4624, 4104],
                "event_contexts": [
                    {
                        "event_id": 4104,
                        "channel": "Microsoft-Windows-PowerShell/Operational",
                        "provider": "Microsoft-Windows-PowerShell",
                    }
                ],
            },
        )
        self.assertEqual(
            (True, "accepted"),
            admit_new_hypothesis(candidate, SessionState(session_id="S-mixed")),
        )

    def test_event_context_is_derived_from_authoritative_evtx_rows(self) -> None:
        candidate = Hypothesis(
            id="draft-derived-context",
            description="PowerShell script block execution was observed",
            required_entities=["computer"],
            confirm_when={"co_observed_event_ids": [4104]},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (event_id, channel, raw_json) VALUES (?, ?, ?)",
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-PowerShell"}}}',
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (event_id, channel, raw_json) VALUES (?, ?, ?)",
                    (
                        4104,
                        "Application",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Winlogon"}}}',
                    ),
                )
                qualify_event_contexts(candidate, db)
        self.assertEqual(
            candidate.confirm_when["event_contexts"][0]["provider"],
            "Microsoft-Windows-PowerShell",
        )
        self.assertEqual(
            (True, "accepted"),
            admit_new_hypothesis(candidate, SessionState(session_id="S-derived")),
        )

    def test_co_observation_ignores_ineligible_provider_rows(self) -> None:
        rows = [
            {
                "event_id": 4104,
                "channel": "Application",
                "raw_json": {
                    "winlog": {"provider": {"name": "Microsoft-Windows-Winlogon"}}
                },
            }
        ]
        condition = {
            "co_observed_event_ids": [4104],
            "event_contexts": [
                {
                    "event_id": 4104,
                    "channel": "Microsoft-Windows-PowerShell/Operational",
                    "provider": "Microsoft-Windows-PowerShell",
                }
            ],
        }
        satisfied, reason = _co_observation_satisfied(condition, rows)
        self.assertFalse(satisfied)
        self.assertIn("missing", reason)

    def test_admitted_spec_with_unknown_key_stays_contextual(self) -> None:
        """Admission tolerates keys outside the shared vocabulary, but such a
        spec must not silently become supporting at Assessment."""

        state = SessionState(session_id="S-unknown-key")
        candidate = Hypothesis(
            id="draft-keywords",
            description="Logon activity on the workstation",
            confirm_when={
                "co_observed_event_ids": [4624],
                "keywords": ["sc.exe"],
            },
        )
        self.assertEqual((True, "accepted"), admit_new_hypothesis(candidate, state))
        assessment = assess_evidence_group(
            hypothesis=candidate,
            rows=[{"evidence_id": "evtx-1", "event_id": 4624}],
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(assessment.role, "contextual")
        self.assertIn("unsupported condition keys", assessment.reason)

        # A spec admission rejects (no evaluable event IDs) must likewise
        # never become supporting at Assessment.
        rejected_candidate = Hypothesis(
            id="draft-keywords-only",
            description="Logon activity on the workstation",
            confirm_when={"keywords": ["logon"]},
        )
        self.assertEqual(
            (False, "non-testable-verification-spec"),
            admit_new_hypothesis(rejected_candidate, state),
        )
        rejected_assessment = assess_evidence_group(
            hypothesis=rejected_candidate,
            rows=[{"evidence_id": "evtx-1", "event_id": 4624}],
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(rejected_assessment.role, "contextual")

    def test_quality_uses_eligible_context_when_rows_are_mixed(self) -> None:
        rows = [
            {
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "raw_json": {
                    "winlog": {"provider": {"name": "Microsoft-Windows-PowerShell"}}
                },
            },
            {
                "event_id": 4104,
                "channel": "Application",
                "raw_json": {
                    "winlog": {"provider": {"name": "Microsoft-Windows-Winlogon"}}
                },
            },
        ]
        gaps = _event_claim_gaps(
            "PowerShell script block execution was observed", [{"sample_rows": rows}]
        )
        self.assertFalse(any("channel/provider context" in gap for gap in gaps))


def _setup_confirmed_invariant(db: CaseDB, hypothesis_id: str) -> None:
    """Set up sufficiency and evidence links so confirmed verdict passes invariants."""
    # First ensure the hypothesis exists in the DB
    db.execute(
        "INSERT INTO hypotheses (hypothesis_id, description, status, sufficiency_status, "
        "verification_spec) VALUES (?, 'test', 'active', 'unknown', "
        '\'{"spec_version":"1"}\') ON CONFLICT (hypothesis_id) DO NOTHING',
        (hypothesis_id,),
    )
    db.execute(
        "UPDATE hypotheses SET sufficiency_status = 'sufficient', "
        "sufficiency_score = 0.8 WHERE hypothesis_id = ?",
        (hypothesis_id,),
    )
    from forensia.ai.checking.sufficiency import create_hypothesis_evidence_link

    db.execute(
        "INSERT INTO evtx_events (evidence_id, source_file) VALUES (?, 'test-source')",
        (f"evtx-{hypothesis_id}",),
    )
    create_hypothesis_evidence_link(
        db,
        hypothesis_id=hypothesis_id,
        evidence_id=f"evtx-{hypothesis_id}",
        role="supporting",
        query_id="Q-test",
    )


class TestSufficiencyIndependence(unittest.TestCase):
    def test_resolution_does_not_rewrite_machine_sufficiency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(
                    session_id="S-1",
                    active_hypotheses=[
                        Hypothesis(id="H-SUFF", description="Unlinked claim")
                    ],
                )
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, description, summary,
                        sufficiency_status, sufficiency_reason,
                        created_at, updated_at
                    ) VALUES (
                        'H-SUFF', 'active', 'Unlinked claim', '',
                        'insufficient', 'no evidence links', now(), now()
                    )
                    """
                )
                resolve_hypothesis(
                    db,
                    state,
                    "H-SUFF",
                    "confirmed",
                    "LLM confirmation",
                    "S-1",
                )
                status, reason = db.execute(
                    "SELECT sufficiency_status, sufficiency_reason "
                    "FROM hypotheses WHERE hypothesis_id = 'H-SUFF'"
                ).fetchone()
                self.assertEqual("insufficient", status)
                self.assertEqual("no evidence links", reason)


class TestExtractSemanticTriple:
    def test_target_fallback_pattern_does_not_crash(self) -> None:
        """Descriptions with a target keyword but no 'to/on/into/onto <word>' phrase
        previously raised IndexError (fallback pattern had no capturing group)."""
        triple = extract_semantic_triple(
            "Repeated 4625 failures targeting one account indicate brute-force"
        )
        assert triple["target"] == "account"


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
                        source_rule_ids, required_entities
                    ) VALUES (
                        'H-001', ?, 'confirmed', 'confirmed', 'done', 'broad_plan',
                        'S-1', 'S-2', now(), now(), '["rule-1"]', '["host"]'
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

                merged = merge_active_hypotheses(
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

    def test_spec_change_reopens_resolved_hypothesis(self) -> None:
        from forensia.ai.checking.sufficiency import (
            create_hypothesis_evidence_link,
            evidence_link_currentness,
            load_evidence_links,
        )
        from forensia.ai.hypotheses.hypothesis_store import (
            _upsert_hypothesis,
            load_persisted_hypotheses,
        )
        from forensia.ai.investigation.selection import select_focus_hypotheses

        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                resolved = Hypothesis(
                    id="H-001",
                    description="4624 event shows remote interactive logon",
                    status="confirmed",
                    verdict="confirmed",
                    summary="Previously confirmed",
                    target_keypoint_id="host_execution_activity",
                )
                _insert_section(db, "3_technical", update_count=MAX_SECTION_UPDATES)
                _upsert_hypothesis(
                    db,
                    resolved,
                    origin="rule",
                    session_id="session-old",
                    resolved_session="session-old",
                )
                db.execute(
                    "UPDATE hypotheses SET selection_count = 7, "
                    "last_selected_at = now(), next_eligible_at = now() + INTERVAL '1 day', "
                    "blocked_reason = 'old retry block', sufficiency_status = 'sufficient', "
                    "sufficiency_score = 1.0 WHERE hypothesis_id = 'H-001'"
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file) "
                    "VALUES ('evtx-H-001', 'source-H-001')"
                )
                create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-001",
                    evidence_id="evtx-H-001",
                    assessment_id="EA-old-spec",
                )
                db.execute(
                    "INSERT INTO claims (claim_id, section_key, claim_text, "
                    "finding_ids, hypothesis_ids, evidence_ids, support_status, "
                    "created_at, updated_at) VALUES ('C-H-001', '3_technical', "
                    "'old claim', '[]', '[\"H-001\"]', '[\"evtx-H-001\"]', "
                    "'supported', now(), now())"
                )
                assert len(load_evidence_links(db, "H-001", current_only=True)) == 1
                assert (
                    db.execute(
                        "SELECT support_status FROM claims WHERE claim_id = 'C-H-001'"
                    ).fetchone()[0]
                    == "supported"
                )
                assert (
                    db.execute(
                        "SELECT stale FROM report_sections WHERE section_key = '3_technical'"
                    ).fetchone()[0]
                    is False
                )
                resolved_projection = [resolved]
                reopened = merge_active_hypotheses(
                    db=db,
                    current=[],
                    updates=[
                        Hypothesis(
                            id="H-new",
                            description=resolved.description,
                            status="active",
                            refute_when={"zero_rows": True},
                        )
                    ],
                    resolved=resolved_projection,
                    session_id="session-spec-change",
                    origin="broad_plan",
                )

                assert len(reopened) == 1
                assert reopened[0].id == "H-001"
                assert reopened[0].status == "active"
                assert reopened[0].verdict is None
                assert reopened[0].verification_spec.refute_conditions == {
                    "zero_rows": True
                }
                assert resolved_projection == []
                row = db.execute(
                    "SELECT status, verdict, resolved_session, selection_count, "
                    "last_selected_at, next_eligible_at, blocked_reason, "
                    "sufficiency_status FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                assert row == (
                    "active",
                    None,
                    None,
                    0,
                    None,
                    None,
                    None,
                    "needs_review",
                )
                active, terminal = load_persisted_hypotheses(db)
                assert [item.id for item in active] == ["H-001"]
                assert terminal == []
                selected = select_focus_hypotheses(
                    db,
                    limit=1,
                    session_id="session-spec-change",
                    iteration=1,
                )
                assert [
                    result.hypothesis_id for result in selected if result.eligible
                ] == ["H-001"]
                history = load_evidence_links(db, "H-001")
                current = load_evidence_links(db, "H-001", current_only=True)
                assert len(history) == 1 and current == []
                assert (
                    evidence_link_currentness(db, history[0])[1]
                    == "verification_spec_changed"
                )
                assert (
                    db.execute(
                        "SELECT support_status FROM claims WHERE claim_id = 'C-H-001'"
                    ).fetchone()[0]
                    == "needs_review"
                )
                assert (
                    db.execute(
                        "SELECT stale FROM report_sections WHERE section_key = '3_technical'"
                    ).fetchone()[0]
                    is True
                )

    def test_same_id_spec_update_with_different_description_reopens_once(self) -> None:
        from forensia.ai.hypotheses.hypothesis_store import _upsert_hypothesis

        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                resolved = Hypothesis(
                    id="H-009",
                    description="Original resolved claim",
                    status="confirmed",
                    verdict="confirmed",
                )
                _upsert_hypothesis(
                    db,
                    resolved,
                    origin="rule",
                    session_id="session-old",
                    resolved_session="session-old",
                )
                resolved_projection = [resolved]
                reopened = merge_active_hypotheses(
                    db=db,
                    current=[],
                    updates=[
                        Hypothesis(
                            id="H-009",
                            description="Different wording for the same persisted claim",
                            status="active",
                            refute_when={"zero_rows": True},
                        )
                    ],
                    resolved=resolved_projection,
                    session_id="session-new",
                    origin="broad_plan",
                )

                assert len(reopened) == 1
                assert reopened[0].id == "H-009"
                assert reopened[0].description == "Original resolved claim"
                assert reopened[0].status == "active"
                assert reopened[0].verdict is None
                assert resolved_projection == []
                assert (
                    db.execute(
                        "SELECT COUNT(*) FROM hypotheses WHERE hypothesis_id = 'H-009'"
                    ).fetchone()[0]
                    == 1
                )


class TestHypothesisEvidenceStrength:
    """Unit tests for hypothesis_evidence_strength scoring."""

    def test_llm_speculated_scores_zero(self) -> None:
        h = Hypothesis(
            id="H-000",
            description="LLM-speculated hypothesis",
            status="active",
        )
        assert hypothesis_evidence_strength(h) == 0

    def test_rule_seeded_only_scores_one(self) -> None:
        h = Hypothesis(
            id="H-001",
            description="Rule-seeded hypothesis",
            status="active",
            source_rule_ids=["rule-1"],
        )
        assert hypothesis_evidence_strength(h) == 1

    def test_rule_seeded_with_evidence_scores_two(self) -> None:
        h = Hypothesis(
            id="H-002",
            description="Rule-seeded with evidence",
            status="active",
            source_rule_ids=["rule-1"],
            confirm_when={"co_observed_event_ids": [4624]},
        )
        assert hypothesis_evidence_strength(h) == 2

    def test_zero_rows_placeholder_not_strong_evidence(self) -> None:
        h = Hypothesis(
            id="H-003",
            description="Rule-seeded with zero_rows placeholder",
            status="active",
            source_rule_ids=["rule-1"],
            confirm_when={"zero_rows": True},
        )
        assert hypothesis_evidence_strength(h) == 1

    def test_refute_when_also_counts_as_evidence(self) -> None:
        h = Hypothesis(
            id="H-004",
            description="Rule-seeded with refute criteria",
            status="active",
            source_rule_ids=["rule-1"],
            refute_when={"zero_rows": True},
        )
        assert hypothesis_evidence_strength(h) == 2


def _insert_section(db: CaseDB, section_key: str, update_count: int = 0) -> None:
    """Insert a minimal report_sections row."""
    db.execute(
        """INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale)
           VALUES (?, ?, '', 0.5, 'draft', ?, FALSE)
           ON CONFLICT (section_key) DO UPDATE SET update_count = excluded.update_count, stale = FALSE""",
        (section_key, section_key, update_count),
    )


def _stale_status(db: CaseDB, section_key: str) -> bool:
    row = db.execute(
        "SELECT stale FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    return bool(row[0]) if row else False


class StalePropagationViaTargetKeypointTests(unittest.TestCase):
    """Resolving a draft-origin hypothesis with target_keypoint_id marks its section stale."""

    def test_resolve_with_target_keypoint_marks_section_stale(self) -> None:
        """A hypothesis with target_keypoint_id='host_execution_activity' should
        mark section '3_technical' stale (family '3' owns that keypoint)."""
        keypoint = "host_execution_activity"
        # Expect family "3" which maps to section key 3_technical
        owning_sections = sections_for_keypoint(keypoint)
        self.assertIn(
            "3_technical",
            owning_sections,
            f"{keypoint} should map to section 3_technical, got {owning_sections}",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-1",
                            description="suspicious process execution",
                            status="active",
                            target_keypoint_id=keypoint,
                        )
                    ],
                )
                _setup_confirmed_invariant(db, "H-1")
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-1",
                    verdict="confirmed",
                    summary="confirmed by query",
                    session_id="S-1",
                )
                self.assertTrue(
                    _stale_status(db, "3_technical"),
                    "section 3_technical should be marked stale",
                )

    def test_target_keypoint_marks_correct_section_only(self) -> None:
        """A timeline keypoint should only mark 2_timeline stale, not 3_technical."""
        keypoint = "timeline_log_clearing"
        owning = sections_for_keypoint(keypoint)
        self.assertIn("2_timeline", owning)
        self.assertNotIn("3_technical", owning)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "2_timeline")
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-2",
                            description="log clearing detected",
                            status="active",
                            target_keypoint_id=keypoint,
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-2",
                    verdict="refuted",
                    summary="no log clearing found",
                    session_id="S-1",
                )
                self.assertTrue(_stale_status(db, "2_timeline"))
                self.assertFalse(_stale_status(db, "3_technical"))

    def test_target_keypoint_none_does_not_mark_sections(self) -> None:
        """No target_keypoint_id should not mark any section stale."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-3",
                            description="suspicious activity",
                            status="active",
                            target_keypoint_id=None,
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-3",
                    verdict="confirmed",
                    summary="confirmed",
                    session_id="S-1",
                )
                self.assertFalse(_stale_status(db, "3_technical"))


class StalePropagationViaDescriptionTests(unittest.TestCase):
    """Resolving a gap-origin hypothesis marks sections guessed from description stale."""

    def test_gap_description_matches_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical")
                _insert_section(db, "4_gaps")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-4",
                            description="unknown persistence mechanism on host PC-01",
                            status="active",
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-4",
                    verdict="refuted",
                    summary="no persistence found",
                    session_id="S-1",
                )
                # "host" and "persistence" both match 3_technical
                self.assertTrue(_stale_status(db, "3_technical"))


class StalePropagationUpdateCountCapTests(unittest.TestCase):
    """Sections with update_count >= max should not be marked stale."""

    def test_section_at_cap_not_marked_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical", update_count=MAX_SECTION_UPDATES)
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-5",
                            description="suspicious execution on host",
                            status="active",
                            target_keypoint_id="host_execution_activity",
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-5",
                    verdict="confirmed",
                    summary="confirmed",
                    session_id="S-1",
                )
                self.assertFalse(
                    _stale_status(db, "3_technical"),
                    "section at update_count cap should NOT be marked stale",
                )

    def test_section_below_cap_marked_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical", update_count=MAX_SECTION_UPDATES - 1)
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-6",
                            description="suspicious execution on host",
                            status="active",
                            target_keypoint_id="host_execution_activity",
                        )
                    ],
                )
                _setup_confirmed_invariant(db, "H-6")
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-6",
                    verdict="confirmed",
                    summary="confirmed",
                    session_id="S-1",
                )
                self.assertTrue(
                    _stale_status(db, "3_technical"),
                    "section below cap should be marked stale",
                )


class StalePropagationRulepackDeclTests(unittest.TestCase):
    """Resolving a rulepack-origin hypothesis marks sections from its declaration."""

    def test_rulepack_declaration_marks_sections(self) -> None:
        """A hypothesis originating from a rulepack with report_sections should
        mark those sections stale."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "2_timeline")
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-7",
                            description="log clearing indicator",
                            status="active",
                            source_rule_ids=["windows-system-104-log-cleared"],
                        )
                    ],
                )
                _setup_confirmed_invariant(db, "H-7")
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-7",
                    verdict="confirmed",
                    summary="log clear confirmed",
                    session_id="S-1",
                )
                self.assertTrue(
                    _stale_status(db, "2_timeline"),
                    "rulepack declaration should mark 2_timeline stale",
                )


class CollectSectionRequestsTests(unittest.TestCase):
    """R6-01: the stale-section query must survive contact with real DuckDB rows.

    The previous implementation did dict-style access on raw fetchall() tuples
    and crashed with TypeError on the first stale row — killing every report
    refresh after the initial fill (sessions 89dae1d15b9a / 907bd96e669c)."""

    def test_stale_section_produces_render_request(self) -> None:
        from pathlib import Path

        from forensia.ai.sections.section_refresher import collect_section_requests
        from forensia.report.sections.report_input import sections_from_template_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_dir = Path(tmpdir) / "templates"
            template_dir.mkdir()
            (template_dir / "1_overview.md").write_text(
                "# Investigation Overview\n\n## Executive Summary\n<!-- mode: narrative; summary -->\n",
                encoding="utf-8",
            )
            (template_dir / "4_gaps.md").write_text(
                "# Investigation Gaps\n\n## Evidence Gaps\n<!-- mode: table; builder: gaps_evidence -->\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                # 1_overview: filled and fresh → must NOT be re-rendered.
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_overview', 'Overview', 'filled body text', 0.8, 'ai_exhausted', 1, FALSE)"
                )
                # 4_gaps: filled but stale → must be re-rendered.
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('4_gaps', 'Gaps', 'old gap body', 0.5, 'draft', 1, TRUE)"
                )
                prior_filled = {
                    "1_overview": "filled body text",
                    "4_gaps": "old gap body",
                }
                requests = collect_section_requests(
                    case,
                    db,
                    sections_from_template_dir(template_dir),
                    prior_filled,
                    report_brief={},
                )

        keys = [str(r.get("section_key")) for r in requests]
        self.assertIn("4_gaps", keys, "stale section must produce a render request")
        self.assertNotIn("1_overview", keys, "fresh filled section must be skipped")
        gap_request = next(r for r in requests if r["section_key"] == "4_gaps")
        self.assertTrue(gap_request["is_stale"])

    def test_failure_marker_produces_retry_request_even_when_fresh(self) -> None:
        from pathlib import Path

        from forensia.ai.sections.section_refresher import collect_section_requests
        from forensia.report.sections.report_input import section_source_from_path

        marker = "_Section could not be generated due to an internal error._"
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = Path(tmpdir) / "1_overview.md"
            template_path.write_text(
                "# Investigation Overview\n\n## Executive Summary\n<!-- mode: narrative; summary -->\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, stale
                    ) VALUES ('1_overview', 'Overview', ?, 0, 'draft', 1, FALSE)
                    """,
                    [marker],
                )
                requests = collect_section_requests(
                    case,
                    db,
                    [section_source_from_path(template_path)],
                    {"1_overview": marker},
                    report_brief={},
                )

        self.assertEqual(["1_overview"], [item["section_key"] for item in requests])
        self.assertTrue(requests[0]["is_stale"])

    def test_force_all_returns_every_template(self) -> None:
        from pathlib import Path

        from forensia.ai.sections.section_refresher import collect_section_requests
        from forensia.report.sections.report_input import sections_from_template_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_dir = Path(tmpdir) / "templates"
            template_dir.mkdir()
            (template_dir / "1_overview.md").write_text(
                "# Investigation Overview\n\n## Executive Summary\n<!-- mode: narrative; summary -->\n",
                encoding="utf-8",
            )
            (template_dir / "4_gaps.md").write_text(
                "# Investigation Gaps\n\n## Evidence Gaps\n<!-- mode: table; builder: gaps_evidence -->\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_overview', 'Overview', 'filled body text', 0.8, 'ai_exhausted', 1, FALSE)"
                )
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('4_gaps', 'Gaps', 'old gap body', 0.5, 'draft', 5, FALSE)"
                )
                prior_filled = {
                    "1_overview": "filled body text",
                    "4_gaps": "old gap body",
                }
                requests = collect_section_requests(
                    case,
                    db,
                    sections_from_template_dir(template_dir),
                    prior_filled,
                    report_brief={},
                    force_all=True,
                )

        keys = [str(r.get("section_key")) for r in requests]
        self.assertIn("1_overview", keys, "force_all must include fresh sections")
        self.assertIn("4_gaps", keys, "force_all must include at-cap sections")
        for r in requests:
            self.assertTrue(
                r["is_stale"], f"force_all must mark {r['section_key']} as stale"
            )
            self.assertTrue(
                r["needs_refresh"],
                f"force_all must mark {r['section_key']} as needs_refresh",
            )


if __name__ == "__main__":
    unittest.main()
