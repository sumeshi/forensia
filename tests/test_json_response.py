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
        outputs = iter(("not-json", "not-json"))
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
                with pytest.raises(
                    RuntimeError, match="repeated identical invalid JSON"
                ):
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
