"""Compact branch-contract tests for checker normalization and guardrails."""

from __future__ import annotations

import datetime
import unittest
from typing import Any

from forensia.ai.checking.check_guardrails import (
    annotate_benign_context,
    guardrail_check_payload,
    verify_verdict_consistency,
)
from forensia.ai.checking.check_normalize import (
    filter_memory_updates,
    validate_extracted_findings,
)
from forensia.core.session import Hypothesis


def _hypothesis(
    *, confirm_when: dict[str, Any] | None = None, required: list[str] | None = None
) -> Hypothesis:
    return Hypothesis(
        id="h-test",
        description="test hypothesis",
        confirm_when=confirm_when,
        required_entities=required or [],
    )


def _summary(rows: list[dict[str, Any]], event_ids: list[int]) -> dict[str, Any]:
    return {
        "row_count": len(rows),
        "sample_rows": rows,
        "event_id_set": event_ids,
        "evidence_ids": [row["evidence_id"] for row in rows if row.get("evidence_id")],
    }


class TestVerifyVerdictConsistency(unittest.TestCase):
    def test_event_and_required_entity_contracts(self) -> None:
        cases = (
            (
                "matching events",
                "confirmed",
                _hypothesis(confirm_when={"co_observed_event_ids": [4625, 4624]}),
                _summary(
                    [{"target_user": "alice", "evidence_id": "ev-1"}], [4625, 4624]
                ),
                "confirmed",
            ),
            (
                "missing event",
                "confirmed",
                _hypothesis(confirm_when={"co_observed_event_ids": [4625]}),
                _summary([{"target_user": "alice", "evidence_id": "ev-1"}], [2004]),
                "inconclusive",
            ),
            (
                "required values absent",
                "confirmed",
                _hypothesis(required=["target_user", "src_ip"]),
                _summary(
                    [{"target_user": "n/a", "src_ip": None, "evidence_id": "ev-1"}],
                    [4624],
                ),
                "inconclusive",
            ),
            (
                "required value present",
                "confirmed",
                _hypothesis(required=["target_user"]),
                _summary([{"target_user": "alice", "evidence_id": "ev-1"}], [4624]),
                "confirmed",
            ),
            ("refuted bypass", "refuted", _hypothesis(), _summary([], []), "refuted"),
            (
                "inconclusive bypass",
                "inconclusive",
                _hypothesis(),
                _summary([], []),
                "inconclusive",
            ),
        )
        for name, verdict, hypothesis, result, expected in cases:
            with self.subTest(name=name):
                actual, reason = verify_verdict_consistency(
                    verdict, "", hypothesis, result
                )
                assert actual == expected
                assert (reason is None) == (actual == verdict)

    def test_correlation_requires_time_and_host_proximity(self) -> None:
        base = datetime.datetime(2025, 1, 1, 10, 0)
        hypothesis = _hypothesis(
            confirm_when={
                "co_observed_event_ids": [25, 4624],
                "same_host": True,
                "within_minutes": 5,
            }
        )
        cases = (
            ("within window", 2, "PC-01", "confirmed"),
            ("outside window", 180, "PC-01", "inconclusive"),
            ("different host", 2, "PC-02", "inconclusive"),
        )
        for name, minutes, second_host, expected in cases:
            rows = [
                {
                    "event_id": 25,
                    "computer": "PC-01",
                    "timestamp": base.isoformat(),
                },
                {
                    "event_id": 4624,
                    "computer": second_host,
                    "timestamp": (
                        base + datetime.timedelta(minutes=minutes)
                    ).isoformat(),
                },
            ]
            with self.subTest(name=name):
                actual, _ = verify_verdict_consistency(
                    "confirmed", "", hypothesis, _summary(rows, [25, 4624])
                )
                assert actual == expected

    def test_benign_context_only_downgrades_fully_benign_support(self) -> None:
        benign = {"subject_user": "PC-01$", "evidence_id": "ev-1"}
        ordinary = {"subject_user": "administrator", "evidence_id": "ev-2"}
        cases = (
            ("all benign", "confirmed", [benign], "inconclusive"),
            ("mixed", "confirmed", [benign, ordinary], "confirmed"),
            ("ordinary", "confirmed", [ordinary], "confirmed"),
            ("empty", "confirmed", [], "confirmed"),
            ("non-confirmed bypass", "refuted", [benign], "refuted"),
        )
        for name, verdict, rows, expected in cases:
            with self.subTest(name=name):
                actual, _ = verify_verdict_consistency(
                    verdict, "", _hypothesis(), _summary(rows, [4624])
                )
                assert actual == expected


class TestPayloadGuardrails(unittest.TestCase):
    @staticmethod
    def _parsed(verdict: str) -> dict[str, Any]:
        return {
            "verdict": verdict,
            "finding_updates": [],
            "suspicious_evidence": [],
            "new_hypotheses": [],
            "memory_updates": {},
            "report_text": "test report",
            "extracted_findings": [],
            "query_id": "q-test",
        }

    def test_fallback_only_downgrades_confirmed(self) -> None:
        for verdict, expected in (
            ("confirmed", "newlead"),
            ("inconclusive", "inconclusive"),
            ("refuted", "refuted"),
            ("newlead", "newlead"),
        ):
            with self.subTest(verdict=verdict):
                guarded = guardrail_check_payload(
                    self._parsed(verdict),
                    finding_candidates=[],
                    result_summary=_summary([{"evidence_id": "ev-1"}], [4624]),
                    fallback_info={"phase": "keyword_search"},
                )
                assert guarded["verdict"] == expected

    def test_zero_evidence_cannot_support_positive_verdicts(self) -> None:
        for verdict in ("confirmed", "newlead"):
            with self.subTest(verdict=verdict):
                guarded = guardrail_check_payload(
                    self._parsed(verdict),
                    finding_candidates=[],
                    result_summary=_summary([], []),
                )
                assert guarded["verdict"] == "inconclusive"


class TestMemoryUpdateFiltering(unittest.TestCase):
    def test_entity_validation_matrix(self) -> None:
        sample_rows = [
            {
                "target_user": "alice",
                "computer": "pc-01",
                "file_path": r"C:\Users\jdoe\app.exe",
                "evidence_id": "ev-1",
            }
        ]
        cases = (
            ("exact", "user", "alice", True),
            ("path substring", "user", "jdoe", True),
            ("absent", "user", "nobody", False),
            ("too short", "host", "pc", False),
            ("invalid type", "garbage_type", "alice", False),
            ("placeholder", "user", "n/a", False),
        )
        for name, entity_type, value, expected in cases:
            updates = {
                "entities": [
                    {
                        "entity_type": entity_type,
                        "name": value,
                        "role": "actor_user",
                        "evidence_ids": ["ev-1"],
                    }
                ]
            }
            with self.subTest(name=name):
                filtered = filter_memory_updates(
                    updates, {"ev-1"}, sample_rows=sample_rows
                )
                assert bool(filtered.get("entities")) is expected


class TestExtractedFindingValidation(unittest.TestCase):
    def test_accepts_well_formed_and_rejects_unsupported_findings(self) -> None:
        items = [
            {"title": "Valid", "severity": "high", "evidence_ids": ["ev-1"]},
            {"title": "", "severity": "high", "evidence_ids": ["ev-1"]},
            {"title": "Bad severity", "severity": "urgent", "evidence_ids": ["ev-1"]},
            {"title": "Unknown evidence", "severity": "low", "evidence_ids": ["ev-9"]},
        ]
        assert validate_extracted_findings(items, {"ev-1"}) == [items[0]]

    def test_tolerates_absent_or_malformed_evidence_lists(self) -> None:
        cases = (
            ([], {"ev-1"}, []),
            ("not a list", {"ev-1"}, []),
            (
                [{"title": "No IDs", "severity": "medium", "evidence_ids": []}],
                {"ev-1"},
                1,
            ),
            (
                [{"title": "String ID", "severity": "low", "evidence_ids": "ev-1"}],
                {"ev-1"},
                0,
            ),
            (
                [
                    {
                        "title": "Unobserved",
                        "severity": "medium",
                        "evidence_ids": ["ev-9"],
                    }
                ],
                set(),
                0,
            ),
        )
        for items, observed, expected in cases:
            with self.subTest(items=items):
                result = validate_extracted_findings(items, observed)
                assert (
                    result == expected
                    if isinstance(expected, list)
                    else len(result) == expected
                )


class TestBenignAnnotation(unittest.TestCase):
    def test_matches_declared_row_rules(self) -> None:
        cases = (
            (
                [{"subject_user": "PC-01$"}, {"subject_user": "alice"}],
                {"column": "subject_user", "regex": r"\$$"},
                {0: ["machine-account"]},
            ),
            (
                [{"src_ip": "127.0.0.1"}, {"src_ip": "10.0.0.5"}],
                {"column": "src_ip", "regex": r"^(127\.0\.0\.1|::1)$"},
                {0: ["loopback"]},
            ),
            (
                [{"process_name": "svchost.exe"}, {"process_name": "pwsh.exe"}],
                {"column": "process_name", "regex": r"(?i)svchost\.exe$"},
                {0: ["os-process"]},
            ),
        )
        for rows, when, expected in cases:
            rule_id = next(iter(expected.values()))[0]
            with self.subTest(rule=rule_id):
                assert (
                    annotate_benign_context(
                        rows, [{"id": rule_id, "when": when, "note": "test"}]
                    )
                    == expected
                )

    def test_empty_missing_and_null_inputs_do_not_match(self) -> None:
        rule = {
            "id": "machine-account",
            "when": {"column": "subject_user", "regex": r"\$$"},
            "note": "test",
        }
        for rows, rules in (
            ([], [rule]),
            ([{"subject_user": "PC-01$"}], []),
            ([{"user_name": "alice"}], [rule]),
            ([{"subject_user": None}], [rule]),
        ):
            with self.subTest(rows=rows, rules=rules):
                assert annotate_benign_context(rows, rules) == {}
