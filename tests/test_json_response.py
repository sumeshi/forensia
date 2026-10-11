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
