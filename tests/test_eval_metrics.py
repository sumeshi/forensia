"""Pure-function tests for eval_run.py metrics.

Tests compute expected numbers from a miniature synthetic case directory
without any LLM or DB dependency.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from scripts.eval_run import (
    _family_from_description,
    _find_placeholder_lines,
    _INSTRUCTION_TONE_RE,
    _jaccard,
    _load_hypotheses,
    _load_overview,
    _load_facts,
    _load_report,
    _parse_hypothesis_file,
    _token_set,
    evaluate,
    hypothesis_family_diversity,
    instruction_tone_ratio,
    placeholder_leak_count,
    memory_duplication_ratio,
    report_hygiene,
    evidence_traceability,
    per_phase_llm_call_counts,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def synthetic_case(tmp_path: Path) -> Path:
    """Build a miniature synthetic case directory."""
    case = tmp_path / "synthetic_case"
    case.mkdir()

    # memory/hypotheses/
    hyp_dir = case / "memory" / "hypotheses"
    hyp_dir.mkdir(parents=True)

    _write_hypothesis(hyp_dir / "H-001.md", "refuted", "refuted",
        "RDP session from external IP may indicate lateral movement")
    _write_hypothesis(hyp_dir / "H-002.md", "active", "confirmed",
        "Credential reuse via service logon observed on workstation")
    _write_hypothesis(hyp_dir / "H-003.md", "refuted", "refuted",
        "Scheduled task creation for persistence")
    _write_hypothesis(hyp_dir / "H-004.md", "active", "confirmed",
        "Cloud sync tool accessing sensitive files")
    _write_hypothesis(hyp_dir / "gap-a1b2c3d4.md", "active", "confirmed",
        "Is {src_ip} consistent with the original session on {computer}?")

    # memory/overview.md — includes near-duplicate lines
    overview_lines = [
        "# Investigation Overview",
        "",
        "Logon events observed on host.",
        "Logon events were observed on the host.",
        "Multiple logon events were seen.",
        "Service installations observed on host informant-PC.",
        "Service installs found on the target host.",
        "A password reset was observed on the target host.",
        "Two password resets were observed involving users informant and admin.",
        "Findings related to cloud sync were identified.",
    ]
    (case / "memory" / "overview.md").write_text("\n".join(overview_lines), encoding="utf-8")

    # memory/facts.md — includes a placeholder leak
    facts_lines = [
        "# Facts",
        "",
        "- [fact-001] Credential use observed [confirmed]",
        "- [fact-002] Is {src_ip} consistent with the original session? — confirmed [confirmed]",
        "- [fact-003] File rename detected [provisional]",
    ]
    (case / "memory" / "facts.md").write_text("\n".join(facts_lines), encoding="utf-8")

    # memory/timeline.md — one entry
    (case / "memory" / "timeline.md").write_text(
        "# Timeline\n\n- 2024-01-15T10:00:00Z: Logon event on host.\n",
        encoding="utf-8",
    )

    # findings/
    find_dir = case / "findings"
    find_dir.mkdir()
    _write_finding(find_dir / "rule-001.json", "rule-001-finding", ["evtx-host-001", "evtx-host-002"])
    _write_finding(find_dir / "rule-002.json", "rule-002-finding", ["evtx-host-003"])

    # reports/report.md — with some traceable and some bare IDs
    report_text = (
        "# Report\n\n"
        "## Unresolved Hypotheses\n\n"
        "| Hypothesis | State |\n"
        "| --- | --- |\n"
        "| H-001 | inconclusive |\n"
        "| gap-a1b2c3d4 | inconclusive |\n"
        "| H-009 | inconclusive |\n\n"
        "finding_id=rule-001-finding with evidence_id=evtx-host-001\n"
        "An sqlglot error occurred during planning.\n"
        "finding_id=rule-002-finding with evidence_id=evtx-host-003\n"
        "Another finding_id=nonexistent-finding\n"
    )
    (case / "reports").mkdir()
    (case / "reports" / "report.md").write_text(report_text, encoding="utf-8")

    # ai_logs/session-abc123/
    log_dir = case / "ai_logs" / "session-abc123"
    log_dir.mkdir(parents=True)
    phases = ["plan-broad-draft"] * 3 + ["plan-hypothesis"] * 5 + ["check-verdict"] * 2
    for i, phase in enumerate(phases, 1):
        _write_llm_log(log_dir / f"{i:02d}-{phase}-call-{i:02d}.json", phase, i)

    # manifest.yaml
    (case / "manifest.yaml").write_text(
        "case_name: synthetic\ncreated_at: '2024-01-01T00:00:00'\n", encoding="utf-8"
    )

    return case


def _write_hypothesis(path: Path, status: str, verdict: str, description: str):
    path.write_text(
        f"# Hypothesis {path.stem}\n"
        f"\n## Status\n- {status}\n"
        f"\n## Verdict\n- {verdict}\n"
        f"\n## Description\n{description}\n"
        f"\n## Summary\nSome summary text.\n",
        encoding="utf-8",
    )


def _write_finding(path: Path, finding_id: str, evidence_ids: list[str]):
    data = {
        "finding_id": finding_id,
        "rule_id": "some-rule",
        "title": "Test finding",
        "severity": "high",
        "confidence": 0.75,
        "evidence": [{"evidence_id": eid, "timestamp": "2024-01-15T10:00:00"} for eid in evidence_ids],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_llm_log(path: Path, phase: str, call_index: int):
    data = {
        "input": [{"role": "system", "content": "test"}],
        "output": {},
        "meta": {
            "model": "test-model",
            "session_id": "session-abc123",
            "phase": phase,
            "call_index": call_index,
        },
    }
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_family_from_description(self):
        assert _family_from_description("RDP logon observed") == "account"
        assert _family_from_description("Service driver installed") == "persistence"
        assert _family_from_description("MFT file rename on desktop") == "mft"
        assert _family_from_description("Browser history analysis") == "ioc"
        assert _family_from_description("Antiforensic tool eraser") == "gaps"
        assert _family_from_description("Prefetch execution listing") == "host"
        assert _family_from_description("Generic unknown topic") == "other"

    def test_placeholder_detection(self):
        text = "normal line\nIs {src_ip} consistent?\nSQL had [src_ip_placeholder]\nclean\n[start_time] is used"
        leaks = _find_placeholder_lines(text)
        assert len(leaks) == 3
        assert "{src_ip}" in leaks[0]
        assert "[src_ip_placeholder]" in leaks[1]
        assert "[start_time]" in leaks[2]

    def test_token_set(self):
        assert _token_set("Hello World") == {"hello", "world"}
        assert _token_set("Multiple   spaces and-dashes") == {"multiple", "spaces", "and", "dashes"}
        assert _token_set("") == set()

    def test_jaccard(self):
        a = {"hello", "world"}
        b = {"hello", "there"}
        assert _jaccard(a, b) == pytest.approx(1 / 3)
        assert _jaccard(a, a) == 1.0
        assert _jaccard(set(), {"a"}) == 0.0

    def test_parse_hypothesis_file(self, tmp_path: Path):
        hyp_file = tmp_path / "H-999.md"
        _write_hypothesis(hyp_file, "active", "confirmed", "Test hypothesis for lateral movement")
        meta = _parse_hypothesis_file(hyp_file)
        assert meta["id"] == "H-999"
        assert meta["status"] == "active"
        assert meta["verdict"] == "confirmed"
        assert "lateral movement" in meta["description"]

    def test_load_hypotheses(self, synthetic_case: Path):
        hyps = _load_hypotheses(synthetic_case / "memory")
        assert len(hyps) == 5
        ids = [h["id"] for h in hyps]
        assert "H-001" in ids
        assert "gap-a1b2c3d4" in ids

    def test_load_overview(self, synthetic_case: Path):
        lines = _load_overview(synthetic_case / "memory")
        assert len(lines) == 8  # non-heading lines
        assert any("Logon events observed" in l for l in lines)

    def test_load_facts(self, synthetic_case: Path):
        facts = _load_facts(synthetic_case / "memory")
        assert len(facts) == 3
        assert any("credential" in f.lower() for f in facts)

    def test_load_report(self, synthetic_case: Path):
        text = _load_report(synthetic_case)
        assert "Unresolved Hypotheses" in text


class TestMetrics:
    def test_hypothesis_family_diversity(self, synthetic_case: Path):
        hyps = _load_hypotheses(synthetic_case / "memory")
        result = hypothesis_family_diversity(hyps)
        assert result["total_hypotheses"] == 5
        assert "account" in result["families"]
        assert result["dominant_family_share"] > 0

    def test_placeholder_leak_count(self, synthetic_case: Path):
        # facts.md has one {src_ip} leak
        result = placeholder_leak_count(
            synthetic_case / "memory",
            synthetic_case / "ai_logs" / "session-abc123",
        )
        assert result["total_leak_lines"] >= 1
        assert "facts" in result["sources_with_leaks"]

    def test_memory_duplication_ratio(self, synthetic_case: Path):
        lines = _load_overview(synthetic_case / "memory")
        result = memory_duplication_ratio(lines)
        assert result["total_lines"] == 8
        assert result["pairwise_comparisons"] > 0
        assert result["high_similarity_pairs"] >= 1

    def test_memory_duplication_ratio_single_line(self):
        result = memory_duplication_ratio(["Only one line"])
        assert result["duplication_ratio"] == 0.0
        assert result["pairwise_comparisons"] == 0

    def test_report_hygiene(self, synthetic_case: Path):
        hyps = _load_hypotheses(synthetic_case / "memory")
        result = report_hygiene(synthetic_case, hyps)
        assert result["error_string_leaks"] >= 1  # "sqlglot error" in report
        assert result["bare_id_count"] >= 3  # H-001, gap-a1b2c3d4, H-009
        assert result["days_with_findings"] >= 1  # 2024-01-15 from finding timestamps

    def test_evidence_traceability(self, synthetic_case: Path):
        result = evidence_traceability(synthetic_case)
        assert result["finding_ids_in_report"] >= 3  # rule-001-finding, rule-002-finding, nonexistent-finding
        assert result["resolvable_finding_ids"] >= 2  # rule-001-finding and rule-002-finding
        assert result["traceability_ratio"] > 0

    def test_per_phase_llm_call_counts(self, synthetic_case: Path):
        log_dir = synthetic_case / "ai_logs" / "session-abc123"
        result = per_phase_llm_call_counts(log_dir)
        assert result["total_calls"] == 10
        assert result["phases"]["plan-broad-draft"] == 3
        assert result["phases"]["plan-hypothesis"] == 5
        assert result["phases"]["check-verdict"] == 2

    def test_per_phase_llm_call_counts_missing_dir(self, tmp_path: Path):
        missing = tmp_path / "nonexistent"
        result = per_phase_llm_call_counts(missing)
        assert result["total_calls"] == 0
        assert "note" in result

    def test_evaluate_integration(self, synthetic_case: Path):
        metrics = evaluate(synthetic_case)
        assert metrics["case_dir"] == str(synthetic_case)
        assert "hypothesis_family_diversity" in metrics
        assert "placeholder_leak_count" in metrics
        assert "memory_duplication_ratio" in metrics
        assert "report_hygiene" in metrics
        assert "evidence_traceability" in metrics
        assert "per_phase_llm_call_counts" in metrics
        assert metrics["confirmed_while_benign_rate"]["total_confirmed"] == 3  # H-002, H-004, gap-a1b2c3d4

    def test_flag_single_family(self):
        # all hypotheses in same family → flagged
        hyps = [
            {"id": "H-001", "description": "RDP logon observed"},
            {"id": "H-002", "description": "Credential reuse detected"},
        ]
        result = hypothesis_family_diversity(hyps)
        assert result["flag_single_family_over_70pct"]

    def test_no_flag_diverse_families(self):
        hyps = [
            {"id": "H-001", "description": "RDP logon observed"},
            {"id": "H-002", "description": "Service driver installed"},
            {"id": "H-003", "description": "MFT file rename on desktop"},
        ]
        result = hypothesis_family_diversity(hyps)
        assert not result["flag_single_family_over_70pct"]


class TestR311Metrics:
    """Tests for R3-11: instruction-tone ratio, UI consistency, block language, invalid IDs."""

    def test_instruction_tone_ratio_clean(self):
        assert instruction_tone_ratio("") == 0.0
        assert instruction_tone_ratio("Clean normal text without any instructions.") == 0.0
        assert instruction_tone_ratio("通常の日本語テキストです。") == 0.0

    def test_instruction_tone_ratio_flagged(self):
        text = "確認する必要があります。"
        assert instruction_tone_ratio(text) > 0

    def test_instruction_tone_ratio_mixed(self):
        text = "通常の文です。確認する必要があります。別の通常文。評価してください。"
        r = instruction_tone_ratio(text)
        assert r == 0.5, f"expected 0.5, got {r}"

    def test_instruction_tone_ratio_do_not_treat(self):
        text = "do not treat this as evidence"
        assert instruction_tone_ratio(text) > 0

    def test_instruction_tone_ratio_should_be_verified(self):
        text = "This should be verified against other sources."
        assert instruction_tone_ratio(text) > 0

    def test_invalid_evidence_ids_no_db(self, tmp_path: Path):
        from scripts.eval_run import count_invalid_evidence_ids
        result = count_invalid_evidence_ids(str(tmp_path / "nonexistent.json"), str(tmp_path / "nonexistent.duckdb"))
        assert result["status"] == "missing_files"
        assert result["invalid_count"] == 0

    def test_block_language_conformity_no_file(self, tmp_path: Path):
        from scripts.eval_run import block_language_conformity
        result = block_language_conformity(str(tmp_path / "nonexistent.json"))
        assert result["status"] == "missing_file"
        assert result["blocks"] == 0

    def test_ui_file_consistency_missing_files(self, tmp_path: Path):
        from scripts.eval_run import ui_file_consistency
        result = ui_file_consistency(str(tmp_path / "a.json"), str(tmp_path / "b.md"))
        assert result["status"] == "missing_files"
