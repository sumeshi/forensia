"""Unit tests for RPT-01: co-occurrence auto-confirm gate (progress.py).

Co-occurrence of event IDs is correlation, not proof of maliciousness.
Gap/follow-up-derived hypotheses (empty source_rule_ids) often get a
heuristically-filled confirm_when (e.g. via _propose_confirm_when) that can
match ubiquitous baseline events such as 4624/4634. Forcing such hypotheses
to "confirmed" purely on co-occurrence bypasses the LLM verdict and the
"don't trust the AI's output" design principle. Auto-confirm via
co_observed_event_ids must therefore be restricted to rule-seeded
hypotheses (non-empty source_rule_ids), where a vetted detection rule
backs the confirm_when.
"""

from __future__ import annotations

from forensia.ai.progress import HypothesisProgressTracker
from forensia.core.session import Hypothesis


def _rows_for_event_ids(event_ids: list[int]) -> list[dict]:
    return [
        {
            "event_id": eid,
            "computer": "HOST-A",
            "timestamp": f"2024-01-01T00:0{i}:00Z",
        }
        for i, eid in enumerate(event_ids)
    ]


class TestAutoConfirmCoobservationGate:
    def test_gap_derived_hypothesis_with_baseline_coobservation_not_auto_confirmed(
        self,
    ) -> None:
        """A gap-derived hypothesis (no source_rule_ids) whose confirm_when is
        satisfied purely by ubiquitous baseline events (4624/4634 logon/logoff)
        must not be force-confirmed: such co-occurrence is normal background
        noise, not evidence of the hypothesized malicious activity.
        """
        hypothesis = Hypothesis(
            id="h-gap-1",
            description="RDP lateral movement (gap-derived)",
            source_rule_ids=[],
            confirm_when={
                "co_observed_event_ids": [4624, 4634],
                "same_host": True,
                "within_minutes": 30,
            },
        )
        rows = _rows_for_event_ids([4624, 4634])

        tracker = HypothesisProgressTracker()
        assert tracker.should_auto_confirm(None, rows, hypothesis) is False

    def test_rule_seeded_hypothesis_with_satisfied_coobservation_still_auto_confirmed(
        self,
    ) -> None:
        """A rule-seeded hypothesis (non-empty source_rule_ids), backed by a
        vetted detection rule, retains the existing auto-confirm behavior
        when its confirm_when constraints are satisfied.
        """
        hypothesis = Hypothesis(
            id="h-rule-1",
            description="Brute-force followed by successful logon",
            source_rule_ids=["windows-security-4625-failed-logon"],
            confirm_when={
                "co_observed_event_ids": [4625, 4624],
                "same_host": True,
                "within_minutes": 30,
            },
        )
        rows = _rows_for_event_ids([4625, 4624])

        tracker = HypothesisProgressTracker()
        assert tracker.should_auto_confirm(None, rows, hypothesis) is True


class TestHeuristicConfirmWhenNeverAutoConfirms:
    """Code-backfilled confirm_when must not drive auto-confirm.

    Why: rule-declared follow-up hypotheses are created with non-empty
    source_rule_ids AND a heuristic confirm_when from _propose_confirm_when
    ({"co_observed_entity_names": [...], "heuristic": True}). An entity-only
    confirm_when has no event IDs to verify, so _co_observation_satisfied
    trivially returns True — without the heuristic guard the hypothesis
    would auto-confirm on any non-benign rows, bypassing the LLM verdict.
    """

    def test_rule_seeded_with_heuristic_confirm_when_not_auto_confirmed(self) -> None:
        hypothesis = Hypothesis(
            id="H-100",
            description="follow-up: suspicious service on HOST-A",
            source_rule_ids=["windows-some-rule"],
            confirm_when={
                "co_observed_entity_names": ["service_name"],
                "same_host": False,
                "heuristic": True,
            },
        )
        tracker = HypothesisProgressTracker()
        rows = [
            {
                "event_id": 7045,
                "computer": "HOST-A",
                "src_ip": "10.0.0.5",
                "timestamp": "2024-01-01T00:00:00Z",
            }
        ]
        assert (
            tracker.should_auto_confirm(None, rows, hypothesis) is False
        ), "heuristic confirm_when must never force a confirmed verdict"

    def test_vetted_confirm_when_unaffected_by_guard(self) -> None:
        """A rule-declared confirm_when (no heuristic marker) still confirms."""
        hypothesis = Hypothesis(
            id="H-101",
            description="rule-seeded with vetted criteria",
            source_rule_ids=["windows-some-rule"],
            confirm_when={"co_observed_event_ids": [7045]},
        )
        tracker = HypothesisProgressTracker()
        rows = [
            {
                "event_id": 7045,
                "computer": "HOST-A",
                "src_ip": "10.0.0.5",
                "timestamp": "2024-01-01T00:00:00Z",
            }
        ]
        assert tracker.should_auto_confirm(None, rows, hypothesis) is True
