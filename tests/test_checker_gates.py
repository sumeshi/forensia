"""Unit tests for checker.py guardrail gates (T-01 through T-04, R2-04)."""

from __future__ import annotations

import datetime
from typing import Any

from forensia.ai.checker import (
    _filter_memory_updates,
    _guardrail_check_payload,
    _validate_extracted_findings,
    _verify_verdict_consistency,
    annotate_benign_context,
)
from forensia.core.session import ENTITY_ROLES, ENTITY_TYPE_ALIASES, Hypothesis


# ==============================================================
# T-01: _verify_verdict_consistency
# ==============================================================


class TestVerifyVerdictConsistency:
    """_verify_verdict_consistency: confirmed-verdict gates."""

    @staticmethod
    def _make_hypothesis(
        *,
        confirm_when_co: list[int] | None = None,
        required_entities: list[str] | None = None,
    ) -> Hypothesis:
        cw: dict[str, Any] | None = None
        if confirm_when_co is not None:
            cw = {"co_observed_event_ids": confirm_when_co}
        return Hypothesis(
            id="h-test",
            description="test hypothesis",
            confirm_when=cw,
            required_entities=required_entities or [],
        )

    def test_consistency_claim_match(self) -> None:
        """confirmed + claimed event IDs present → unchanged."""
        h = self._make_hypothesis(confirm_when_co=[4625, 4624])
        result_summary: dict[str, Any] = {
            "event_id_set": [4625, 4624],
            "sample_rows": [
                {"target_user": "alice", "evidence_id": "ev-1"},
                {"target_user": "bob", "evidence_id": "ev-2"},
            ],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "confirmed"
        assert reason is None

    def test_consistency_claim_mismatch(self) -> None:
        """confirmed + claimed 4625 but observed {2004} → downgraded to inconclusive."""
        h = self._make_hypothesis(confirm_when_co=[4625])
        result_summary: dict[str, Any] = {
            "event_id_set": [2004],
            "sample_rows": [{"target_user": "alice", "evidence_id": "ev-1"}],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "inconclusive"
        assert reason is not None
        assert "4625" in reason

    def test_consistency_refuted_passthrough(self) -> None:
        """refuted verdict passes through regardless of event IDs."""
        h = self._make_hypothesis(confirm_when_co=[4625])
        result_summary: dict[str, Any] = {"event_id_set": [], "sample_rows": []}
        verdict, reason = _verify_verdict_consistency("refuted", "", h, result_summary)
        assert verdict == "refuted"
        assert reason is None

    def test_consistency_inconclusive_passthrough(self) -> None:
        """inconclusive verdict passes through regardless of event IDs."""
        h = self._make_hypothesis(confirm_when_co=[4625])
        result_summary: dict[str, Any] = {"event_id_set": [], "sample_rows": []}
        verdict, reason = _verify_verdict_consistency("inconclusive", "", h, result_summary)
        assert verdict == "inconclusive"
        assert reason is None

    def test_consistency_required_entities_all_null(self) -> None:
        """confirmed + required_entities columns all NULL → downgraded."""
        h = self._make_hypothesis(
            required_entities=["target_user", "src_ip"],
        )
        result_summary: dict[str, Any] = {
            "event_id_set": [4624],
            "sample_rows": [
                {"target_user": None, "src_ip": None, "evidence_id": "ev-1"},
                {"target_user": "n/a", "src_ip": "-", "evidence_id": "ev-2"},
            ],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "inconclusive"
        assert reason is not None
        assert "required_entities" in reason.lower() or "null/absent" in reason.lower()

    def test_consistency_required_entities_has_value(self) -> None:
        """confirmed + required_entities column has a real value → unchanged."""
        h = self._make_hypothesis(required_entities=["target_user"])
        result_summary: dict[str, Any] = {
            "event_id_set": [4624],
            "sample_rows": [
                {"target_user": "alice", "evidence_id": "ev-1"},
            ],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "confirmed"
        assert reason is None


# ==============================================================
# T-02: _guardrail_check_payload fallback_info
# ==============================================================


class TestGuardrailCheckPayload:
    """_guardrail_check_payload: fallback-info downgrade gate."""

    @staticmethod
    def _minimal_parsed(verdict: str) -> dict[str, Any]:
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

    @staticmethod
    def _minimal_result_summary() -> dict[str, Any]:
        return {
            "row_count": 3,
            "sample_rows": [{"evidence_id": "ev-1"}],
            "event_id_set": [4624],
            "evidence_ids": ["ev-1"],
        }

    def test_guardrail_fallback_downgrades_confirmed(self) -> None:
        """confirmed + fallback_info → downgraded to newlead."""
        parsed = self._minimal_parsed("confirmed")
        result_summary = self._minimal_result_summary()
        fallback_info = {"phase": "keyword_search"}
        guarded = _guardrail_check_payload(
            parsed,
            finding_candidates=[],
            result_summary=result_summary,
            fallback_info=fallback_info,
        )
        assert guarded["verdict"] == "newlead"
        notes: str = guarded.get("report_text", "") or ""
        # The downgrade note is injected into parsed["notes"] which is not
        # directly mapped to guarded output keys in this minimal path.
        # Instead verify that verdict changed.

    def test_guardrail_fallback_no_downgrade_for_inconclusive(self) -> None:
        """inconclusive passes through even with fallback_info."""
        parsed = self._minimal_parsed("inconclusive")
        result_summary = self._minimal_result_summary()
        fallback_info = {"phase": "keyword_search"}
        guarded = _guardrail_check_payload(
            parsed,
            finding_candidates=[],
            result_summary=result_summary,
            fallback_info=fallback_info,
        )
        assert guarded["verdict"] == "inconclusive"

    def test_guardrail_fallback_no_downgrade_for_refuted(self) -> None:
        """refuted passes through even with fallback_info."""
        parsed = self._minimal_parsed("refuted")
        result_summary = self._minimal_result_summary()
        guarded = _guardrail_check_payload(
            parsed,
            finding_candidates=[],
            result_summary=result_summary,
            fallback_info={"phase": "keyword_search"},
        )
        assert guarded["verdict"] == "refuted"

    def test_guardrail_fallback_no_downgrade_for_newlead(self) -> None:
        """newlead passes through even with fallback_info (not checked)."""
        parsed = self._minimal_parsed("newlead")
        result_summary = self._minimal_result_summary()
        guarded = _guardrail_check_payload(
            parsed,
            finding_candidates=[],
            result_summary=result_summary,
            fallback_info={"phase": "keyword_search"},
        )
        assert guarded["verdict"] == "newlead"

    def test_guardrail_zero_evidence_downgrades_confirmed(self) -> None:
        """zero-evidence confirmed → inconclusive (existing guard)."""
        parsed = self._minimal_parsed("confirmed")
        result_summary: dict[str, Any] = {
            "row_count": 0,
            "sample_rows": [],
            "event_id_set": [],
            "evidence_ids": [],
        }
        guarded = _guardrail_check_payload(
            parsed,
            finding_candidates=[],
            result_summary=result_summary,
        )
        assert guarded["verdict"] == "inconclusive"

    def test_guardrail_zero_evidence_downgrades_newlead(self) -> None:
        """zero-evidence newlead → inconclusive (existing guard)."""
        parsed = self._minimal_parsed("newlead")
        result_summary: dict[str, Any] = {
            "row_count": 0,
            "sample_rows": [],
            "event_id_set": [],
            "evidence_ids": [],
        }
        guarded = _guardrail_check_payload(
            parsed,
            finding_candidates=[],
            result_summary=result_summary,
        )
        assert guarded["verdict"] == "inconclusive"


# ==============================================================
# T-03: _filter_memory_updates entity-name validation
# ==============================================================


class TestFilterMemoryUpdatesEntityName:
    """_filter_memory_updates: entity name presence in sample rows."""

    def test_filter_memory_entity_name_validation(self) -> None:
        """entity entries with names absent from sample rows → dropped."""
        observed = {"ev-1"}
        sample_rows = [
            {"target_user": "alice", "computer": "pc-01", "evidence_id": "ev-1"},
        ]
        updates: dict[str, Any] = {
            "entities": [
                {
                    "entity_type": "user",
                    "name": "nonexistent_user",
                    "role": "actor_user",
                    "evidence_ids": ["ev-1"],
                },
            ],
        }
        filtered = _filter_memory_updates(updates, observed, sample_rows=sample_rows)
        assert len(filtered.get("entities", [])) == 0

    def test_filter_memory_entity_name_present(self) -> None:
        """entity entries with names present in sample rows → kept."""
        observed = {"ev-1"}
        sample_rows = [
            {"target_user": "alice", "computer": "pc-01", "evidence_id": "ev-1"},
        ]
        updates: dict[str, Any] = {
            "entities": [
                {
                    "entity_type": "user",
                    "name": "alice",
                    "role": "actor_user",
                    "evidence_ids": ["ev-1"],
                },
            ],
        }
        filtered = _filter_memory_updates(updates, observed, sample_rows=sample_rows)
        entities = filtered.get("entities", [])
        assert len(entities) == 1
        assert entities[0]["name"] == "alice"

    def test_filter_memory_entity_substring_in_blob(self) -> None:
        """entity name absent as exact match but present as blob substring → kept (>=3 chars)."""
        observed = {"ev-1"}
        sample_rows = [
            {"file_path": "C:\\Users\\jdoe\\app.exe", "evidence_id": "ev-1"},
        ]
        updates: dict[str, Any] = {
            "entities": [
                {
                    "entity_type": "user",
                    "name": "jdoe",
                    "role": "actor_user",
                    "evidence_ids": ["ev-1"],
                },
            ],
        }
        filtered = _filter_memory_updates(updates, observed, sample_rows=sample_rows)
        entities = filtered.get("entities", [])
        assert len(entities) == 1
        assert entities[0]["name"] == "jdoe"

    def test_filter_memory_entity_short_substring_skipped(self) -> None:
        """entity name < 3 chars not found as exact match → dropped (not in blob)."""
        observed = {"ev-1"}
        sample_rows = [
            {"file_path": "C:\\app.exe", "evidence_id": "ev-1"},
        ]
        updates: dict[str, Any] = {
            "entities": [
                {
                    "entity_type": "host",
                    "name": "pc",
                    "role": "source_host",
                    "evidence_ids": ["ev-1"],
                },
            ],
        }
        filtered = _filter_memory_updates(updates, observed, sample_rows=sample_rows)
        entities = filtered.get("entities", [])
        assert len(entities) == 0

    def test_filter_memory_entity_invalid_type_dropped(self) -> None:
        """entity with unrecognised entity_type → dropped before name check."""
        observed = {"ev-1"}
        sample_rows = [
            {"target_user": "alice", "evidence_id": "ev-1"},
        ]
        updates: dict[str, Any] = {
            "entities": [
                {
                    "entity_type": "garbage_type",
                    "name": "alice",
                    "role": "actor_user",
                    "evidence_ids": ["ev-1"],
                },
            ],
        }
        filtered = _filter_memory_updates(updates, observed, sample_rows=sample_rows)
        assert len(filtered.get("entities", [])) == 0

    def test_filter_memory_entity_placeholder_name_dropped(self) -> None:
        """entity with placeholder name (e.g. 'n/a') → dropped."""
        observed = {"ev-1"}
        sample_rows = [
            {"target_user": "n/a", "evidence_id": "ev-1"},
        ]
        updates: dict[str, Any] = {
            "entities": [
                {
                    "entity_type": "user",
                    "name": "n/a",
                    "role": "actor_user",
                    "evidence_ids": ["ev-1"],
                },
            ],
        }
        filtered = _filter_memory_updates(updates, observed, sample_rows=sample_rows)
        entities = filtered.get("entities", [])
        # "n/a" is in _ENTITY_PLACEHOLDER_VALUES so it's dropped before name check
        assert len(entities) == 0


# ==============================================================
# T-04: _validate_extracted_findings
# ==============================================================


class TestValidateExtractedFindings:
    """_validate_extracted_findings: title/severity/evidence gates."""

    def test_validate_findings_valid(self) -> None:
        """valid entries pass through unchanged."""
        items = [
            {"title": "Scheduled Task Created", "severity": "high", "evidence_ids": ["ev-1"]},
            {"title": "User Added to Admin Group", "severity": "critical", "evidence_ids": ["ev-2"]},
        ]
        observed = {"ev-1", "ev-2"}
        result = _validate_extracted_findings(items, observed)
        assert len(result) == 2
        assert result[0]["title"] == "Scheduled Task Created"
        assert result[1]["severity"] == "critical"

    def test_validate_findings_drops_invalid(self) -> None:
        """missing title, bad severity, unobserved evidence_ids → dropped."""
        items = [
            {"title": "", "severity": "high", "evidence_ids": ["ev-1"]},
            {"title": "Found X", "severity": "invalid", "evidence_ids": ["ev-1"]},
            {"title": "Found Y", "severity": "high", "evidence_ids": ["ev-999"]},
        ]
        observed = {"ev-1"}
        result = _validate_extracted_findings(items, observed)
        assert len(result) == 0

    def test_validate_findings_empty(self) -> None:
        """empty list → empty list."""
        result = _validate_extracted_findings([], {"ev-1"})
        assert result == []

    def test_validate_findings_no_observed_keeps_all(self) -> None:
        """no observed_evidence_ids → all well-formed entries kept."""
        items = [
            {"title": "Found X", "severity": "medium", "evidence_ids": ["ev-999"]},
        ]
        result = _validate_extracted_findings(items, set())
        assert len(result) == 1

    def test_validate_findings_no_evidence_ids_keeps(self) -> None:
        """no evidence_ids in entry and observed set non-empty → kept (branch)."""
        items = [
            {"title": "Found X", "severity": "medium", "evidence_ids": []},
        ]
        result = _validate_extracted_findings(items, {"ev-1"})
        assert len(result) == 1

    def test_validate_findings_non_list_evidence_ids(self) -> None:
        """evidence_ids is a string → coerced to empty list, kept."""
        items = [
            {"title": "Found X", "severity": "low", "evidence_ids": "ev-1"},
        ]
        result = _validate_extracted_findings(items, {"ev-1"})
        assert len(result) == 1

    def test_validate_findings_not_a_list(self) -> None:
        """items not a list → empty list."""
        result = _validate_extracted_findings("not a list", {"ev-1"})
        assert result == []


# ==============================================================
# R2-04: _verify_verdict_consistency — same_host / within_minutes
# ==============================================================


class TestVerdictConsistencyCorrelation:
    """_verify_verdict_consistency: same_host / within_minutes correlation gates."""

    @staticmethod
    def _make_corr_hypothesis(
        same_host: bool = True,
        within_minutes: int = 5,
    ) -> Hypothesis:
        return Hypothesis(
            id="h-corr",
            description="correlation hypothesis",
            confirm_when={
                "co_observed_event_ids": [25, 4624],
                "same_host": same_host,
                "within_minutes": within_minutes,
            },
        )

    def test_three_hours_apart_same_host(self) -> None:
        """same_host=true, within_minutes=5, 3 hours apart same host → inconclusive."""
        h = self._make_corr_hypothesis()
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        result_summary: dict[str, Any] = {
            "event_id_set": [25, 4624],
            "sample_rows": [
                {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
                {"event_id": 4624, "computer": "PC-01", "timestamp": (base + datetime.timedelta(hours=3)).isoformat()},
            ],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "inconclusive"
        assert reason is not None

    def test_two_minutes_apart_same_host(self) -> None:
        """same_host=true, within_minutes=5, 2 min apart same host → confirmed."""
        h = self._make_corr_hypothesis()
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        result_summary: dict[str, Any] = {
            "event_id_set": [25, 4624],
            "sample_rows": [
                {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
                {"event_id": 4624, "computer": "PC-01", "timestamp": (base + datetime.timedelta(minutes=2)).isoformat()},
            ],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "confirmed"
        assert reason is None

    def test_two_minutes_apart_different_hosts(self) -> None:
        """same_host=true, within_minutes=5, 2 min apart different hosts → inconclusive."""
        h = self._make_corr_hypothesis()
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        result_summary: dict[str, Any] = {
            "event_id_set": [25, 4624],
            "sample_rows": [
                {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
                {"event_id": 4624, "computer": "PC-02", "timestamp": (base + datetime.timedelta(minutes=2)).isoformat()},
            ],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "inconclusive"
        assert reason is not None


# ==============================================================
# R2-06: annotate_benign_context
# ==============================================================


class TestAnnotateBenignContext:
    """annotate_benign_context: row-level benign-context rule matching."""

    _MACHINE_ACCOUNT_RULES = [
        {"id": "machine-account-subject", "when": {"column": "subject_user", "regex": "\\$$"}, "note": "test"},
    ]
    _LOOPBACK_RULES = [
        {"id": "loopback-source", "when": {"column": "src_ip", "regex": r"^(127\.0\.0\.1|::1)$"}, "note": "test"},
    ]
    _OS_PROCESS_RULES = [
        {"id": "os-servicing-process", "when": {"column": "process_name", "regex": r"(?i)(winlogon|poqexec|services|svchost|taskhost|lsass)\.exe$"}, "note": "test"},
    ]

    def test_machine_account_subject(self) -> None:
        rows = [
            {"subject_user": "PC-01$", "evidence_id": "ev1"},
            {"subject_user": "alice", "evidence_id": "ev2"},
        ]
        result = annotate_benign_context(rows, self._MACHINE_ACCOUNT_RULES)
        assert result == {0: ["machine-account-subject"]}

    def test_loopback_source(self) -> None:
        rows = [{"src_ip": "127.0.0.1"}, {"src_ip": "::1"}, {"src_ip": "10.0.0.5"}]
        result = annotate_benign_context(rows, self._LOOPBACK_RULES)
        assert result == {0: ["loopback-source"], 1: ["loopback-source"]}

    def test_os_servicing_process(self) -> None:
        rows = [
            {"process_name": "winlogon.exe"},
            {"process_name": "powershell.exe"},
            {"process_name": "svchost.exe"},
        ]
        result = annotate_benign_context(rows, self._OS_PROCESS_RULES)
        assert result == {0: ["os-servicing-process"], 2: ["os-servicing-process"]}

    def test_empty_rows(self) -> None:
        assert annotate_benign_context([], self._MACHINE_ACCOUNT_RULES) == {}

    def test_empty_rules(self) -> None:
        rows = [{"subject_user": "PC-01$", "evidence_id": "ev1"}]
        assert annotate_benign_context(rows, []) == {}

    def test_column_missing(self) -> None:
        """Row lacks the rule's target column → no match."""
        rows = [{"user_name": "alice", "evidence_id": "ev1"}]
        result = annotate_benign_context(rows, self._MACHINE_ACCOUNT_RULES)
        assert result == {}

    def test_null_column_value(self) -> None:
        """Rule target column is None → no match."""
        rows = [{"subject_user": None, "evidence_id": "ev1"}]
        result = annotate_benign_context(rows, self._MACHINE_ACCOUNT_RULES)
        assert result == {}


# ==============================================================
# R2-06: _verify_verdict_consistency — benign context gate
# ==============================================================


class TestBenignContextGate:
    """_verify_verdict_consistency: benign-context downgrade gate (Check 4)."""

    @staticmethod
    def _make_hypothesis() -> Hypothesis:
        return Hypothesis(id="h-test", description="test hypothesis")

    def test_all_rows_benign_downgrade(self) -> None:
        """Every supporting row matches a benign-context rule → downgraded."""
        h = self._make_hypothesis()
        rows = [
            {"subject_user": "PC-01$", "target_user": "alice", "evidence_id": "ev1"},
            {"subject_user": "HOST$", "target_user": "bob", "evidence_id": "ev2"},
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [4624],
            "evidence_ids": ["ev1", "ev2"],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "inconclusive"
        assert reason is not None
        assert "benign-context" in reason

    def test_mixed_rows_pass_through(self) -> None:
        """Some rows match, some don't → confirmed unchanged."""
        h = self._make_hypothesis()
        rows = [
            {"subject_user": "PC-01$", "target_user": "alice", "evidence_id": "ev1"},
            {"subject_user": "administrator", "target_user": "bob", "evidence_id": "ev2"},
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [4624],
            "evidence_ids": ["ev1", "ev2"],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "confirmed"
        assert reason is None

    def test_no_rows_pass_through(self) -> None:
        """No rows match any benign rule → confirmed unchanged."""
        h = self._make_hypothesis()
        rows = [
            {"subject_user": "administrator", "target_user": "bob", "evidence_id": "ev1"},
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [4624],
            "evidence_ids": ["ev1"],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "confirmed"
        assert reason is None

    def test_empty_sample_rows_pass_through(self) -> None:
        """No sample rows → confirmed unchanged (no-op)."""
        h = self._make_hypothesis()
        result_summary: dict[str, Any] = {
            "sample_rows": [],
            "event_id_set": [4624],
            "evidence_ids": [],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", h, result_summary)
        assert verdict == "confirmed"
        assert reason is None

    def test_refuted_passthrough(self) -> None:
        """Refuted verdict not affected by benign-context check."""
        h = self._make_hypothesis()
        rows = [
            {"subject_user": "PC-01$", "evidence_id": "ev1"},
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [],
            "evidence_ids": ["ev1"],
        }
        verdict, reason = _verify_verdict_consistency("refuted", "", h, result_summary)
        assert verdict == "refuted"
        assert reason is None
