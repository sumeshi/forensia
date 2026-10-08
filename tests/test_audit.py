"""Transcript persistence, call identity and reported usage share one audit path."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from forensia.ai.audit import LLMCallLogger


def test_audit_persists_distinct_calls_and_summary(tmp_path) -> None:
    logger = LLMCallLogger(SimpleNamespace(ai_logs_dir=tmp_path), "S-audit")
    assert logger.total_calls == 0
    assert logger.count_by_phase() == {}
    call = dict(
        iteration=1,
        phase="plan",
        input_messages=[{"role": "user", "content": "case evidence"}],
        output="bounded query",
        model="local-model",
        base_url="http://local.invalid",
        input_tokens=7,
        output_tokens=3,
    )
    with patch("forensia.ai.audit.get_last_completion_metadata", return_value=None):
        logger.write(**call)
        logger.write(**call)
        logger.write(**{**call, "phase": "check", "suffix": "repair"})
    transcripts = sorted(logger.base_dir.glob("*.json"))
    assert {path.name for path in transcripts} == {
        "01-plan-unknown-01.json",
        "01-plan-unknown-02.json",
        "01-check-repair-01.json",
    }
    first = json.loads((logger.base_dir / "01-plan-unknown-01.json").read_text())
    second = json.loads((logger.base_dir / "01-plan-unknown-02.json").read_text())
    assert first["input"] == call["input_messages"]
    assert first["output"] == call["output"]
    assert first["meta"]["usage_source"] == "local_estimate"
    assert first["meta"]["repeated_request"] is False
    assert second["meta"]["repeated_request"] is True
    assert second["meta"]["repeated_action"] is True
    assert logger.total_calls == 3
    assert logger.count_by_phase() == {"plan-unknown": 2, "check-repair": 1}
    logger.write_summary()
    summary = json.loads((logger.base_dir / "summary.json").read_text())
    assert summary["total_calls"] == 3
    assert summary["total_input_tokens"] == 21
    assert summary["total_output_tokens"] == 9
    assert summary["per_phase"] == logger.count_by_phase()
