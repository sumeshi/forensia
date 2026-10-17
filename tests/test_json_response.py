"""Public-contract tests for parsing JSON returned by an LLM."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import pytest

from forensia.llm.json_response import parse_llm_json


class ParseLlmJsonTests(unittest.TestCase):
    def test_accepts_plain_and_fenced_objects(self) -> None:
        cases = (
            ('{"a": 1}', {"a": 1}),
            ('```json\n{"a": 1}\n```', {"a": 1}),
            ('Result:\n```\n{"items": [{"id": 1}]}\n```', {"items": [{"id": 1}]}),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(
                    expected,
                    parse_llm_json(
                        text, base_url="http://llm-repair.invalid", model="test"
                    ),
                )

    def test_repairs_representative_model_json_defects(self) -> None:
        cases = (
            ('{"a": {"b": [1, 2,]},}', {"a": {"b": [1, 2]}}),
            ('{"a": 1 // comment\n}', {"a": 1}),
            (
                '{"url": "http://example.com", "enabled": true,}',
                {"url": "http://example.com", "enabled": True},
            ),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(
                    expected,
                    parse_llm_json(
                        text, base_url="http://llm-repair.invalid", model="test"
                    ),
                )

    def test_rejects_non_object_top_level(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not an object"):
            parse_llm_json(
                "[1, 2, 3]", base_url="http://llm-repair.invalid", model="test"
            )


def test_repeated_invalid_response_closes_owned_logical_call(tmp_path) -> None:
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.llm import json_response
    from forensia.llm.telemetry import (
        LLMTelemetry,
        reset_active_telemetry,
        set_active_telemetry,
    )

    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        telemetry = LLMTelemetry(db, session_id="invalid-json")
        token = set_active_telemetry(telemetry)
        outputs = iter(("not-json",))
        try:
            with (
                patch.object(
                    json_response,
                    "chat_completion",
                    side_effect=lambda **_: next(outputs),
                ),
                patch.object(
                    json_response,
                    "parse_llm_json",
                    side_effect=ValueError("invalid object"),
                ),
            ):
                with pytest.raises(RuntimeError, match="one bounded correction"):
                    json_response.request_llm_json(
                        [{"role": "user", "content": "return JSON"}],
                        base_url="http://llm-repair.invalid",
                        model="test",
                    )
        finally:
            reset_active_telemetry(token)

        assert db.execute(
            "SELECT status FROM trace.llm_logical_calls WHERE session_id = ?",
            ("invalid-json",),
        ).fetchall() == [("failed",)]


def test_json_repair_uses_one_shared_correction_and_original_output_cap() -> None:
    from forensia.llm import json_response

    calls: list[dict] = []
    budget = [1]

    def completion(**kwargs):
        calls.append(kwargs)
        return '{"a": 1}'

    with patch.object(json_response, "chat_completion", side_effect=completion):
        parsed = json_response.parse_llm_json(
            '{"a": }',
            base_url="http://llm-repair.invalid",
            model="test",
            correction_budget=budget,
            max_tokens=37,
        )

    assert parsed == {"a": 1}
    assert budget == [0]
    assert len(calls) == 1
    assert calls[0]["max_tokens"] == 37
    assert calls[0]["phase"] == "json_repair"


def test_failed_json_repair_does_not_regenerate_original_request() -> None:
    from forensia.llm import json_response

    outputs = iter(("{bad", "still bad"))
    budget = [1]
    with patch.object(
        json_response, "chat_completion", side_effect=lambda **_: next(outputs)
    ) as completion:
        with pytest.raises(RuntimeError, match="one bounded correction"):
            json_response.request_llm_json(
                [{"role": "user", "content": "return JSON"}],
                base_url="http://llm-repair.invalid",
                model="test",
                correction_budget=budget,
            )

    assert completion.call_count == 2
    assert budget == [0]


def test_truncation_retry_shares_budget_and_keeps_original_output_cap() -> None:
    from forensia.llm import json_response
    from forensia.llm.llm_client import LLMOutputTruncatedError

    requests: list[dict] = []

    def completion(**kwargs):
        requests.append(kwargs)
        if len(requests) == 1:
            raise LLMOutputTruncatedError("truncated", content='{"a":')
        return '{"a": 1}'

    budget = [1]
    with patch.object(json_response, "chat_completion", side_effect=completion):
        parsed = json_response.request_llm_json(
            [{"role": "user", "content": "return JSON"}],
            base_url="http://llm-repair.invalid",
            model="test",
            max_tokens=41,
            correction_budget=budget,
        )

    assert parsed == {"a": 1}
    assert budget == [0]
    assert [request["max_tokens"] for request in requests] == [41, 41]


def test_generated_output_failure_retries_once_with_same_schema() -> None:
    from forensia.llm import json_response
    from forensia.llm.llm_client import LLMStructuredOutputError

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    calls: list[dict] = []

    def completion(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise LLMStructuredOutputError(
                status_code=500,
                error_code="generated_output_parse_failed",
                body="Failed to parse input: model returned prose before JSON",
            )
        return '{"ok": true}'

    budget = [1]
    with patch.object(json_response, "chat_completion", side_effect=completion):
        assert json_response.request_llm_json(
            [{"role": "user", "content": "Return the result."}],
            base_url="http://llm-repair.invalid",
            model="test",
            json_schema=schema,
            correction_budget=budget,
        ) == {"ok": True}

    assert budget == [0]
    assert len(calls) == 2
    assert all(call["json_schema"] == schema for call in calls)
    assert (
        "provider could not parse the generated output"
        not in calls[0]["messages"][-1]["content"]
    )
    assert (
        "provider could not parse the generated output"
        in calls[1]["messages"][-1]["content"]
    )


def test_generated_output_retry_exhaustion_and_schema_rejection_are_terminal(
    tmp_path,
) -> None:
    from forensia.llm import json_response
    from forensia.llm.llm_client import LLMStructuredOutputError

    schema = {"type": "object"}
    for error_code, budget_value in (
        ("generated_output_parse_failed", 0),
        ("response_schema_rejected", 1),
    ):
        calls = []

        def fail(**kwargs):
            calls.append(kwargs)
            raise LLMStructuredOutputError(
                status_code=500, error_code=error_code, body="provider error"
            )

        with patch.object(json_response, "chat_completion", side_effect=fail):
            with pytest.raises(LLMStructuredOutputError) as caught:
                json_response.request_llm_json(
                    [{"role": "user", "content": "Return the result."}],
                    base_url="http://llm-repair.invalid",
                    model="test",
                    json_schema=schema,
                    correction_budget=[budget_value],
                )
        assert caught.value.error_code == error_code
        assert len(calls) == 1

    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.llm.telemetry import (
        LLMTelemetry,
        reset_active_telemetry,
        set_active_telemetry,
    )

    budget = [1]
    error = LLMStructuredOutputError(
        status_code=500,
        error_code="generated_output_parse_failed",
        body="Failed to parse input",
    )
    with CaseDB(Case.init(tmp_path / "case")) as db:
        token = set_active_telemetry(LLMTelemetry(db, session_id="parse-exhausted"))
        try:
            with patch.object(
                json_response, "chat_completion", side_effect=(error, error)
            ) as completion:
                with pytest.raises(LLMStructuredOutputError) as caught:
                    json_response.request_llm_json(
                        [{"role": "user", "content": "Return the result."}],
                        base_url="http://llm-repair.invalid",
                        model="test",
                        json_schema=schema,
                        correction_budget=budget,
                    )
            call_status = db.execute(
                "SELECT status FROM trace.llm_logical_calls "
                "WHERE session_id = 'parse-exhausted'"
            ).fetchone()[0]
        finally:
            reset_active_telemetry(token)

    assert caught.value.error_code == "generated_output_parse_failed"
    assert completion.call_count == 2
    assert budget == [0]
    assert call_status == "failed"


def test_context_rejection_without_reduced_input_is_not_replayed() -> None:
    from forensia.llm import json_response
    from forensia.llm.llm_client import LLMContextWindowError

    requests: list[dict] = []

    def completion(**kwargs):
        requests.append(kwargs)
        raise LLMContextWindowError("context too large", status_code=400, body="")

    with (
        patch.object(json_response, "chat_completion", side_effect=completion),
        patch.object(
            json_response,
            "_compact_messages_after_context_rejection",
            return_value=None,
        ),
    ):
        with pytest.raises(LLMContextWindowError):
            json_response.request_llm_json(
                [{"role": "user", "content": "return JSON"}],
                base_url="http://llm-repair.invalid",
                model="test",
            )

    assert len(requests) == 1


def test_request_recovery_retries_the_same_json_repair_request(monkeypatch) -> None:
    from types import SimpleNamespace

    from forensia.llm import json_response
    from forensia.llm.llm_client import LLMRequestTimeoutError

    request = {
        "base_url": "http://llama.test",
        "messages": [{"role": "user", "content": "repair"}],
    }
    seen = []
    waited = []
    statuses = []

    def flaky_chat_completion(**kwargs):
        seen.append(kwargs)
        if len(seen) == 1:
            raise LLMRequestTimeoutError("timed out")
        return '{"ok": true}'

    monkeypatch.setattr(json_response, "chat_completion", flaky_chat_completion)
    monkeypatch.setattr(
        json_response,
        "get_settings",
        lambda: SimpleNamespace(
            llm_outage_wall_clock_budget_s=10, llm_outage_probe_interval_s=0
        ),
    )
    monkeypatch.setattr(
        json_response,
        "outage_wait_until_recovered_sync",
        lambda url, status_callback=None, *, budget_s=None: waited.append(url),
    )

    assert (
        json_response._chat_completion_resuming_outage(
            status_callback=statuses.append, **request
        )
        == '{"ok": true}'
    )
    assert len(seen) == 2
    assert seen[0] == request | {"status_callback": statuses.append}
    assert seen[1]["messages"] == seen[0]["messages"]
    assert seen[1]["retry_class"] == "outage_recovery"
    assert seen[1]["policy_decision"] == "resume_same_request"
    assert waited == ["http://llama.test"]
    assert seen[1]["status_callback"] == statuses.append
    assert statuses == ["LLM unavailable; waiting before resuming the same request"]


def test_exhausted_inner_outage_budget_does_not_restart_outer_call(monkeypatch) -> None:
    import asyncio
    from types import SimpleNamespace

    from forensia.investigation import investigation_session
    from forensia.llm.llm_client import LLMOutageBudgetExceededError

    calls = []

    def exhausted(**kwargs):
        calls.append(kwargs)
        raise LLMOutageBudgetExceededError("outage budget exceeded")

    monkeypatch.setattr(
        investigation_session,
        "get_settings",
        lambda: SimpleNamespace(
            llm_outage_wall_clock_budget_s=1, llm_outage_probe_interval_s=0
        ),
    )
    monkeypatch.setattr(
        investigation_session,
        "outage_wait_until_recovered",
        lambda *args, **kwargs: pytest.fail(
            "terminal budget must not restart recovery"
        ),
    )

    with pytest.raises(LLMOutageBudgetExceededError):
        asyncio.run(
            investigation_session._call_with_outage_recovery(
                exhausted, "http://llama.test", "model"
            )
        )
    assert len(calls) == 1
