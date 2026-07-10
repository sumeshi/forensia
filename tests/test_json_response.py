"""Public-contract tests for parsing JSON returned by an LLM."""

from __future__ import annotations

import unittest

from forensia.ai.llm.json_response import parse_llm_json


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
