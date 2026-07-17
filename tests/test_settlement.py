"""Tests for R8-01: Unified settlement gate.

These tests verify that:
- Event 21 + 4624 with different user/unknown src/LogonType 5 does NOT confirm H-003
- 4720 + unrelated 4732/4624 on same host does NOT confirm backdoor account
- Required entities + correlation + EvidenceLink + sufficient = confirmed
- Checker refuted/inconclusive cannot be overridden by auto-confirm
- No partial state leaks on settlement exceptions
"""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.checking.settlement import (
    SettlementInput,
    _is_concrete_entity,
    _is_loopback_ip,
    build_settlement_input,
    decide_settlement,
    settle_hypothesis,
)
from forensia.ai.checking.sufficiency import (
    create_hypothesis_evidence_link,
)
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB


def _make_hypothesis(
    *,
    hid: str = "H-001",
    description: str = "test hypothesis",
    source_rule_ids: list[str] | None = None,
    required_entities: list[str] | None = None,
    confirm_when: dict | None = None,
) -> Hypothesis:
    return Hypothesis(
        id=hid,
        description=description,
        status="active",
        source_rule_ids=source_rule_ids or [],
        required_entities=required_entities or [],
        confirm_when=confirm_when,
    )


def _make_evidence_link(
    db: CaseDB,
    *,
    hypothesis_id: str = "H-001",
    evidence_id: str = "evtx-001",
    role: str = "supporting",
    source_family: str = "evtx",
    strength: str = "moderate",
) -> str:
    return create_hypothesis_evidence_link(
        db,
        hypothesis_id=hypothesis_id,
        evidence_id=evidence_id,
        role=role,
        source_family=source_family,
        strength=strength,
        query_id="Q-test",
    )


class EntityValidationTests(unittest.TestCase):
    """Test concrete entity validation logic."""

    def test_none_is_not_concrete(self) -> None:
        self.assertFalse(_is_concrete_entity(None))

    def test_empty_string_is_not_concrete(self) -> None:
        self.assertFalse(_is_concrete_entity(""))

    def test_unknown_is_not_concrete(self) -> None:
        self.assertFalse(_is_concrete_entity("unknown"))

    def test_placeholder_is_not_concrete(self) -> None:
        self.assertFalse(_is_concrete_entity("{target_user}"))

    def test_concrete_value_is_concrete(self) -> None:
        self.assertTrue(_is_concrete_entity("INFORMANT-PC"))

    def test_loopback_is_not_concrete_for_src(self) -> None:
        self.assertTrue(_is_loopback_ip("127.0.0.1"))
        self.assertTrue(_is_loopback_ip("::1"))
        self.assertTrue(_is_loopback_ip("localhost"))
        self.assertTrue(_is_loopback_ip("-"))
        self.assertTrue(_is_loopback_ip(""))

    def test_external_ip_is_concrete(self) -> None:
        self.assertFalse(_is_loopback_ip("192.168.1.100"))
        self.assertFalse(_is_loopback_ip("10.0.0.1"))


class SettlementGateTests(unittest.TestCase):
    """Test the unified settlement gate logic."""

    def test_no_evidence_blocks_confirmed(self) -> None:
        """Confirmed blocked when no supporting EvidenceLink exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    source_rule_ids=["rule-1"],
                    required_entities=["target_user"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="confirmed",
                    check_summary="test",
                    sample_rows=[{"event_id": 21, "target_user": "admin"}],
                    co_observation_satisfied=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertFalse(decision.allowed)
                self.assertIn("no_supporting_evidence_link", decision.gates_failed)

    def test_insufficient_sufficiency_blocks_confirmed(self) -> None:
        """Confirmed blocked when machine sufficiency is not sufficient."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    source_rule_ids=["rule-1"],
                    required_entities=["target_user"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                # Create a single weak evidence link
                _make_evidence_link(db, strength="weak", source_family="mft")
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="confirmed",
                    check_summary="test",
                    sample_rows=[{"event_id": 21, "target_user": "admin"}],
                    co_observation_satisfied=True,
                )
                decision = settle_hypothesis(db, si)
                # Should be blocked because weak single-source is not sufficient
                self.assertFalse(decision.allowed)
                self.assertIn("machine_sufficiency=", decision.gates_failed[0])

    def test_missing_required_entities_blocks_confirmed(self) -> None:
        """Confirmed blocked when required entities have no concrete values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    source_rule_ids=["rule-1"],
                    required_entities=["target_user", "src_ip"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002", source_family="evtx")
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="confirmed",
                    check_summary="test",
                    sample_rows=[
                        {
                            "event_id": 21,
                            "target_user": "admin",
                            "src_ip": "127.0.0.1",
                        }
                    ],
                    co_observation_satisfied=True,
                )
                decision = settle_hypothesis(db, si)
                # Should be blocked because src_ip is loopback
                self.assertFalse(decision.allowed)
                self.assertTrue(
                    any("required_entities" in f for f in decision.gates_failed)
                )

    def test_unknown_src_ip_blocks_confirmed(self) -> None:
        """Event 21 + 4624 with unknown src_ip does NOT confirm."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-003",
                    description="RDP lateral movement",
                    source_rule_ids=["rule-rdp"],
                    required_entities=["target_user", "src_ip"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002")
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="LogonType 5 / loopback only",
                    sample_rows=[
                        {
                            "event_id": 21,
                            "target_user": "admin",
                            "src_ip": "127.0.0.1",
                            "logon_type": 5,
                        },
                        {
                            "event_id": 4624,
                            "target_user": "admin",
                            "src_ip": "-",
                            "logon_type": 5,
                        },
                    ],
                    co_observation_satisfied=True,
                    is_benign_auth=False,
                )
                decision = settle_hypothesis(db, si)
                # Should NOT be confirmed because src_ip is loopback/unknown
                self.assertNotEqual(decision.verdict, "confirmed")

    def test_different_user_blocks_auto_confirm(self) -> None:
        """Event 21 + 4624 with different users does NOT auto-confirm."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-003",
                    description="RDP lateral movement",
                    source_rule_ids=["rule-rdp"],
                    required_entities=["target_user"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002")
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="different users",
                    sample_rows=[
                        {"event_id": 21, "target_user": "user_A"},
                        {"event_id": 4624, "target_user": "user_B"},
                    ],
                    co_observation_satisfied=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.verdict, "inconclusive")
                self.assertTrue(
                    any(
                        "differs across correlated events" in failure
                        for failure in decision.gates_failed
                    )
                )

    def test_unrelated_4732_4624_does_not_confirm_backdoor(self) -> None:
        """4720 target account + unrelated 4732/4624 on same host = not confirmed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-005",
                    description="Backdoor account creation via 4720",
                    source_rule_ids=["rule-4720"],
                    required_entities=["target_user", "target_group"],
                    confirm_when={
                        "co_observed_event_ids": [4720, 4732, 4624],
                        "same_host": True,
                    },
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002")
                _make_evidence_link(db, evidence_id="evtx-003")
                # 4720 target is "newuser", 4732/4624 are for unrelated "admin"
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="unrelated events on same host",
                    sample_rows=[
                        {
                            "event_id": 4720,
                            "target_user": "newuser",
                            "target_group": "Users",
                            "computer": "HOST-PC",
                        },
                        {
                            "event_id": 4732,
                            "target_user": "admin",
                            "target_group": "Administrators",
                            "computer": "HOST-PC",
                        },
                        {
                            "event_id": 4624,
                            "target_user": "admin",
                            "computer": "HOST-PC",
                        },
                    ],
                    co_observation_satisfied=True,
                    same_host=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.verdict, "inconclusive")
                self.assertTrue(
                    any(
                        "differs across correlated events" in failure
                        for failure in decision.gates_failed
                    )
                )


class PositiveSettlementTests(unittest.TestCase):
    """Test that valid evidence leads to confirmed."""

    def test_valid_evidence_confirms(self) -> None:
        """Required entities + correlation + EvidenceLink + sufficient = confirmed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="External RDP login",
                    source_rule_ids=["rule-rdp"],
                    required_entities=["target_user", "src_ip"],
                    confirm_when={
                        "co_observed_event_ids": [21, 4624],
                        "same_host": True,
                        "within_minutes": 5,
                    },
                )
                # Create multiple supporting evidence links from different families
                _make_evidence_link(db, evidence_id="evtx-001", source_family="evtx")
                _make_evidence_link(db, evidence_id="evtx-002", source_family="evtx")
                _make_evidence_link(
                    db, evidence_id="prefetch-001", source_family="prefetch"
                )

                # Insert sufficiency metadata
                db.execute(
                    "UPDATE hypotheses SET sufficiency_status = 'sufficient', "
                    "sufficiency_score = 0.8 WHERE hypothesis_id = 'H-001'"
                )

                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="co-observed events found",
                    sample_rows=[
                        {
                            "event_id": 21,
                            "target_user": "admin",
                            "src_ip": "192.168.1.100",
                            "computer": "HOST-PC",
                            "timestamp": "2024-01-15T10:30:00",
                        },
                        {
                            "event_id": 4624,
                            "target_user": "admin",
                            "src_ip": "192.168.1.100",
                            "computer": "HOST-PC",
                            "timestamp": "2024-01-15T10:30:01",
                        },
                    ],
                    co_observation_satisfied=True,
                    co_observation_reason="all co_observed_event_ids present",
                    same_host=True,
                    within_minutes=5,
                )
                decision = settle_hypothesis(db, si)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.verdict, "confirmed")
                self.assertIn("evidence_link_exists", decision.gates_passed)
                self.assertIn("required_entities_concrete", decision.gates_passed)

    def test_checker_confirmed_with_sufficient_is_confirmed(self) -> None:
        """Checker confirmed + machine sufficient = confirmed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                    required_entities=["target_user"],
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002")
                db.execute(
                    "UPDATE hypotheses SET sufficiency_status = 'sufficient', "
                    "sufficiency_score = 0.8 WHERE hypothesis_id = 'H-001'"
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="confirmed",
                    check_summary="confirmed by checker",
                    sample_rows=[{"event_id": 4624, "target_user": "admin"}],
                )
                decision = settle_hypothesis(db, si)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.verdict, "confirmed")

    def test_rdp_event_constraint_requires_logon_type_10(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-rdp",
                    description="RDP session",
                    source_rule_ids=["rule-rdp"],
                    required_entities=["target_user", "src_ip"],
                    confirm_when={
                        "co_observed_event_ids": [21, 4624],
                        "event_constraints": {4624: {"logon_type": ["10"]}},
                    },
                )
                _make_evidence_link(db, hypothesis_id="H-rdp", evidence_id="evtx-21")
                _make_evidence_link(db, hypothesis_id="H-rdp", evidence_id="evtx-4624")
                decision = settle_hypothesis(
                    db,
                    SettlementInput(
                        hypothesis=hyp,
                        checker_verdict="inconclusive",
                        check_summary="service logon only",
                        sample_rows=[
                            {
                                "event_id": 21,
                                "target_user": "admin",
                                "src_ip": "192.0.2.10",
                            },
                            {
                                "event_id": 4624,
                                "target_user": "admin",
                                "src_ip": "192.0.2.10",
                                "logon_type": 5,
                            },
                        ],
                        co_observation_satisfied=True,
                    ),
                )
                self.assertFalse(decision.allowed)
                self.assertTrue(
                    any("logon_type" in item for item in decision.gates_failed)
                )

    def test_build_settlement_input_preserves_zero_row_counter(self) -> None:
        settlement_input = build_settlement_input(
            hypothesis=_make_hypothesis(hid="H-input"),
            checker_verdict="inconclusive",
            check_summary="none",
            consecutive_zero_row_inconclusive=3,
        )
        self.assertEqual(settlement_input.consecutive_zero_row_inconclusive, 3)


class AutoConfirmOverrideTests(unittest.TestCase):
    """Test that auto-confirm cannot override refuted/untestable verdicts."""

    def test_refuted_not_overridden_by_auto_confirm(self) -> None:
        """Checker refuted cannot be overridden by auto-confirm."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002")
                db.execute(
                    "UPDATE hypotheses SET sufficiency_status = 'sufficient', "
                    "sufficiency_score = 0.8 WHERE hypothesis_id = 'H-001'"
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="refuted",  # checker says refuted
                    check_summary="refuted by checker",
                    sample_rows=[{"event_id": 21}, {"event_id": 4624}],
                    co_observation_satisfied=True,  # but co-observation is satisfied
                )
                decision = settle_hypothesis(db, si)
                # Should NOT be confirmed — checker refuted takes precedence
                self.assertEqual(decision.verdict, "refuted")

    def test_untestable_not_overridden_by_auto_confirm(self) -> None:
        """Checker untestable cannot be overridden by auto-confirm."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                    confirm_when={"co_observed_event_ids": [21, 4624]},
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="untestable",
                    check_summary="untestable",
                    sample_rows=[{"event_id": 21}, {"event_id": 4624}],
                    co_observation_satisfied=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertEqual(decision.verdict, "untestable")


class AutoRefuteTests(unittest.TestCase):
    """Test auto-refute and auto-untestable paths."""

    def test_zero_row_consecutive_refute(self) -> None:
        """3+ consecutive zero-row inconclusive with rule refute_when = refuted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="no results",
                    consecutive_zero_row_inconclusive=3,
                    has_rule_refute_when_zero_rows=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertEqual(decision.verdict, "refuted")

    def test_zero_row_consecutive_untestable(self) -> None:
        """3+ consecutive zero-row inconclusive without rule refute = untestable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="no results",
                    consecutive_zero_row_inconclusive=3,
                    has_rule_refute_when_zero_rows=False,
                )
                decision = settle_hypothesis(db, si)
                self.assertEqual(decision.verdict, "untestable")

    def test_same_missing_consecutive_refute(self) -> None:
        """3+ consecutive same-missing checks = refuted or untestable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="same missing",
                    consecutive_same_missing=3,
                    has_rule_refute_when_zero_rows=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertEqual(decision.verdict, "refuted")

    def test_unavailable_event_ids_untestable(self) -> None:
        """Missing event IDs that are unavailable in telemetry = untestable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="missing events",
                    unavailable_missing_event_ids=[4688, 4689],
                )
                decision = settle_hypothesis(db, si)
                self.assertEqual(decision.verdict, "untestable")
                self.assertIn("4688", decision.reason)


class BenignAuthTests(unittest.TestCase):
    """Test that benign auth blocks auto-confirm."""

    def test_benign_auth_blocks_confirmed(self) -> None:
        """All benign local auth rows should block confirmed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                    source_rule_ids=["rule-1"],
                    required_entities=["target_user"],
                    confirm_when={"co_observed_event_ids": [4624]},
                )
                _make_evidence_link(db)
                _make_evidence_link(db, evidence_id="evtx-002")
                db.execute(
                    "UPDATE hypotheses SET sufficiency_status = 'sufficient', "
                    "sufficiency_score = 0.8 WHERE hypothesis_id = 'H-001'"
                )
                si = SettlementInput(
                    hypothesis=hyp,
                    checker_verdict="inconclusive",
                    check_summary="local auth",
                    sample_rows=[
                        {
                            "event_id": 4624,
                            "target_user": "SYSTEM",
                            "src_ip": "-",
                            "logon_type": 5,
                        }
                    ],
                    co_observation_satisfied=True,
                    is_benign_auth=True,
                )
                decision = settle_hypothesis(db, si)
                self.assertNotEqual(decision.verdict, "confirmed")


class DBInvariantTests(unittest.TestCase):
    """Test DB invariant enforcement in resolve_hypothesis."""

    def test_confirmed_without_sufficient_becomes_needs_review(self) -> None:
        """confirmed + insufficient sufficiency → needs_review."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.ai.hypotheses.hypothesis_manager import resolve_hypothesis
            from forensia.core.case import Case
            from forensia.core.session import SessionState

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(
                    hid="H-001",
                    description="test",
                )
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "sufficiency_status) VALUES ('H-001', 'test', 'active', 'insufficient')"
                )
                state = SessionState(
                    session_id="test-session",
                    active_hypotheses=[hyp],
                    resolved_hypotheses=[],
                    findings_snapshot=[],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-001",
                    verdict="confirmed",
                    summary="test confirmed",
                    session_id="test-session",
                )
                # Should be needs_review because sufficiency is insufficient
                row = db.execute(
                    "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row[0], "needs_review")

    def test_confirmed_without_evidence_links_becomes_needs_review(self) -> None:
        """confirmed + no supporting EvidenceLink → needs_review."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.ai.hypotheses.hypothesis_manager import resolve_hypothesis
            from forensia.core.case import Case
            from forensia.core.session import SessionState

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hyp = _make_hypothesis(hid="H-001", description="test")
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "sufficiency_status) VALUES ('H-001', 'test', 'active', 'sufficient')"
                )
                state = SessionState(
                    session_id="test-session",
                    active_hypotheses=[hyp],
                    resolved_hypotheses=[],
                    findings_snapshot=[],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-001",
                    verdict="confirmed",
                    summary="test confirmed",
                    session_id="test-session",
                )
                # Should be needs_review because no evidence links
                row = db.execute(
                    "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row[0], "needs_review")


class MigrationTests(unittest.TestCase):
    """Test R8-01 migration re-queues legacy confirmed + insufficient."""

    def test_migration_requeues_confirmed_insufficient(self) -> None:
        """Legacy confirmed + insufficient → needs_review after migration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Simulate legacy data: confirmed + insufficient
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "sufficiency_status) VALUES "
                    "('H-001', 'legacy bad', 'confirmed', 'insufficient'), "
                    "('H-002', 'legacy sufficient', 'confirmed', 'sufficient'), "
                    "('H-003', 'legacy partial', 'confirmed', 'partial')"
                )
                # Add an evidence link for H-002 so it passes the evidence check
                create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-002",
                    evidence_id="evtx-001",
                    role="supporting",
                    query_id="Q-test",
                )
                # Manually trigger the migration
                db._apply_r8_01_settlement_invariant()

                # H-001 and H-003 should be needs_review (insufficient/partial)
                row1 = db.execute(
                    "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row1[0], "needs_review")

                row3 = db.execute(
                    "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-003'"
                ).fetchone()
                self.assertEqual(row3[0], "needs_review")

                # H-002 should remain confirmed (sufficient + has evidence)
                row2 = db.execute(
                    "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-002'"
                ).fetchone()
                self.assertEqual(row2[0], "confirmed")

    def test_migration_requeues_confirmed_no_evidence(self) -> None:
        """Legacy confirmed + no evidence links → needs_review after migration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.core.case import Case

            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Simulate legacy data: confirmed + sufficient but no evidence links
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "sufficiency_status) VALUES "
                    "('H-001', 'no evidence', 'confirmed', 'sufficient')"
                )
                # Manually trigger the migration
                db._apply_r8_01_settlement_invariant()

                # H-001 should be needs_review because no evidence links
                row = db.execute(
                    "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row[0], "needs_review")


class PartialStateTests(unittest.TestCase):
    """Test that no partial state leaks on settlement exceptions."""

    def test_settlement_decision_is_pure(self) -> None:
        """The decision core has no CaseDB dependency or side effects."""
        si = SettlementInput(
            hypothesis=_make_hypothesis(
                hid="H-001",
                source_rule_ids=["rule-1"],
                required_entities=["target_user"],
            ),
            checker_verdict="confirmed",
            check_summary="test",
            sample_rows=[{"event_id": 4624, "target_user": "admin"}],
        )
        decision1 = decide_settlement(si, links=[], coverage={})
        decision2 = decide_settlement(si, links=[], coverage={})
        self.assertEqual(decision1, decision2)


if __name__ == "__main__":
    unittest.main()
