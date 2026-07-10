from __future__ import annotations

import json
import unittest

from forensia.ai.llm.json_response import (
    _cheap_repair,
    _extract_candidate,
    parse_llm_json,
)


class CheapRepairTests(unittest.TestCase):
    def test_trailing_comma_in_object(self) -> None:
        self.assertEqual(_cheap_repair('{"a": 1,}'), '{"a": 1}')

    def test_trailing_comma_in_nested_object(self) -> None:
        self.assertEqual(_cheap_repair('{"a": {"b": 2,}}'), '{"a": {"b": 2}}')

    def test_trailing_comma_in_array(self) -> None:
        self.assertEqual(_cheap_repair("[1, 2, 3,]"), "[1, 2, 3]")

    def test_trailing_comma_in_nested_array(self) -> None:
        self.assertEqual(_cheap_repair('{"a": [1,]}'), '{"a": [1]}')

    def test_multiple_trailing_commas(self) -> None:
        self.assertEqual(_cheap_repair('{"a": 1,,}'), '{"a": 1,}')

    def test_line_comment_removed(self) -> None:
        text = '{"a": 1 // this is a comment\n}'
        self.assertEqual(json.loads(_cheap_repair(text)), {"a": 1})

    def test_line_comment_with_string_colon(self) -> None:
        text = '{"url": "http://example.com/path"}'
        self.assertEqual(
            json.loads(_cheap_repair(text)), {"url": "http://example.com/path"}
        )

    def test_line_comment_before_value(self) -> None:
        text = '{"a": //comment\n 1}'
        result = _cheap_repair(text)
        parsed = json.loads(result)
        self.assertEqual(parsed, {"a": 1})

    def test_multiple_line_comments(self) -> None:
        text = '{"a": 1 // first\n, "b": 2 // second\n}'
        result = _cheap_repair(text)
        parsed = json.loads(result)
        self.assertEqual(parsed, {"a": 1, "b": 2})

    def test_comment_with_trailing_comma(self) -> None:
        text = '{"a": 1 // comment\n,}'
        result = _cheap_repair(text)
        parsed = json.loads(result)
        self.assertEqual(parsed, {"a": 1})

    def test_already_valid_json_object(self) -> None:
        text = '{"a": 1, "b": "hello"}'
        self.assertEqual(_cheap_repair(text), text)

    def test_already_valid_json_array(self) -> None:
        text = "[1, 2, 3]"
        self.assertEqual(_cheap_repair(text), text)

    def test_empty_string(self) -> None:
        self.assertEqual(_cheap_repair(""), "")

    def test_whitespace_only(self) -> None:
        self.assertEqual(_cheap_repair("   "), "   ")

    def test_only_trailing_comma(self) -> None:
        self.assertEqual(_cheap_repair(","), ",")

    def test_only_line_comment(self) -> None:
        self.assertEqual(_cheap_repair("// comment\n"), "\n")

    def test_comment_at_end_no_newline(self) -> None:
        text = '{"a": 1} // trailing'
        result = _cheap_repair(text)
        self.assertEqual(result, '{"a": 1} // trailing')

    def test_string_containing_trailing_comma_pattern(self) -> None:
        text = '{"msg": "values: [1, 2,3] still fine"}'
        result = _cheap_repair(text)
        parsed = json.loads(result)
        self.assertEqual(parsed, {"msg": "values: [1, 2,3] still fine"})

    def test_string_containing_comment_slash(self) -> None:
        text = '{"url": "http://example.com"}'
        result = _cheap_repair(text)
        parsed = json.loads(result)
        self.assertEqual(parsed, {"url": "http://example.com"})

    def test_deeply_nested_trailing_commas(self) -> None:
        text = '{"a": {"b": {"c": [1, 2,]}},}'
        result = _cheap_repair(text)
        parsed = json.loads(result)
        self.assertEqual(parsed, {"a": {"b": {"c": [1, 2]}}})


class ExtractCandidateTests(unittest.TestCase):
    def test_json_in_fence(self) -> None:
        text = '```json\n{"a": 1}\n```'
        self.assertEqual(_extract_candidate(text), '{"a": 1}')

    def test_json_in_fence_no_lang(self) -> None:
        text = '```\n{"a": 1}\n```'
        self.assertEqual(_extract_candidate(text), '{"a": 1}')

    def test_top_level_json_no_fence(self) -> None:
        text = '{"a": 1}'
        self.assertEqual(_extract_candidate(text), '{"a": 1}')

    def test_multiple_json_blocks_uses_first_brace_pair(self) -> None:
        text = 'some text {"a": 1} trailing {"b": 2}'
        self.assertEqual(_extract_candidate(text), '{"a": 1} trailing {"b": 2}')

    def test_text_with_no_json(self) -> None:
        text = "just some text without any braces"
        self.assertEqual(_extract_candidate(text), text)

    def test_text_with_only_opening_brace(self) -> None:
        text = "just { a"
        self.assertEqual(_extract_candidate(text), "just { a")

    def test_text_with_only_closing_brace(self) -> None:
        text = "just } a"
        self.assertEqual(_extract_candidate(text), "just } a")

    def test_text_with_unmatched_braces(self) -> None:
        text = '{"a": 1'
        self.assertEqual(_extract_candidate(text), '{"a": 1')

    def test_inner_braces_inside_string(self) -> None:
        text = '{"msg": "hello {world}"}'
        self.assertEqual(_extract_candidate(text), '{"msg": "hello {world}"}')

    def test_empty_string(self) -> None:
        self.assertEqual(_extract_candidate(""), "")

    def test_multiple_fences_only_last_json(self) -> None:
        text = '```json\n{"a": 1}\n```\n```json\n{"b": 2}\n```'
        self.assertEqual(_extract_candidate(text), '{"a": 1}')

    def test_fence_with_surrounding_text(self) -> None:
        text = 'Here is the result:\n```json\n{"key": "value"}\n```\nEnd.'
        self.assertEqual(_extract_candidate(text), '{"key": "value"}')

    def test_array_json(self) -> None:
        text = '```json\n[{"a": 1}, {"b": 2}]\n```'
        result = _extract_candidate(text)
        self.assertIn('{"a": 1}', result)
        self.assertIn('{"b": 2}', result)

    def test_fence_with_whitespace(self) -> None:
        text = '  \n  ```json  \n  {"a": 1}  \n  ```  '
        self.assertEqual(_extract_candidate(text), '{"a": 1}')

    def test_no_braces_but_fence(self) -> None:
        text = "```json\njust text\n```"
        self.assertEqual(_extract_candidate(text), "just text")


class ParseLlmJsonPureTests(unittest.TestCase):
    def test_valid_json_object(self) -> None:
        dummy_url = "http://llm-repair.invalid"
        result = parse_llm_json('{"a": 1}', base_url=dummy_url, model="test")
        self.assertEqual(result, {"a": 1})

    def test_valid_json_with_fence(self) -> None:
        dummy_url = "http://llm-repair.invalid"
        result = parse_llm_json(
            '```json\n{"a": 1}\n```', base_url=dummy_url, model="test"
        )
        self.assertEqual(result, {"a": 1})

    def test_valid_json_with_trailing_comma_repaired(self) -> None:
        dummy_url = "http://llm-repair.invalid"
        result = parse_llm_json('{"a": 1,}', base_url=dummy_url, model="test")
        self.assertEqual(result, {"a": 1})

    def test_valid_json_with_line_comment_repaired(self) -> None:
        dummy_url = "http://llm-repair.invalid"
        result = parse_llm_json(
            '{"a": 1 // comment\n}', base_url=dummy_url, model="test"
        )
        self.assertEqual(result, {"a": 1})

    def test_raises_on_array_top_level(self) -> None:
        dummy_url = "http://llm-repair.invalid"
        with self.assertRaises(RuntimeError) as ctx:
            parse_llm_json("[1, 2, 3]", base_url=dummy_url, model="test")
        self.assertIn("not an object", str(ctx.exception))
