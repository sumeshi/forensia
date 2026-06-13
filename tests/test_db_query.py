from __future__ import annotations

import unittest
from datetime import datetime
from unittest.mock import MagicMock

from forensia.db.query import fetch_records, normalize_value


class NormalizeValueTests(unittest.TestCase):
    def test_none_returns_none(self) -> None:
        self.assertIsNone(normalize_value(None))

    def test_datetime_to_isoformat(self) -> None:
        dt = datetime(2025, 1, 15, 8, 30, 45)
        self.assertEqual(normalize_value(dt), "2025-01-15T08:30:45")

    def test_datetime_with_microseconds(self) -> None:
        dt = datetime(2025, 6, 1, 12, 0, 0, 123456)
        self.assertEqual(normalize_value(dt), "2025-06-01T12:00:00.123456")

    def test_int_preserved(self) -> None:
        self.assertEqual(normalize_value(42), 42)

    def test_float_preserved(self) -> None:
        self.assertEqual(normalize_value(3.14), 3.14)

    def test_bool_true_preserved(self) -> None:
        self.assertTrue(normalize_value(True))

    def test_bool_false_preserved(self) -> None:
        self.assertFalse(normalize_value(False))

    def test_int_zero_preserved(self) -> None:
        self.assertEqual(normalize_value(0), 0)

    def test_plain_string_unchanged(self) -> None:
        self.assertEqual(normalize_value("hello world"), "hello world")

    def test_empty_string_unchanged(self) -> None:
        self.assertEqual(normalize_value(""), "")

    def test_whitespace_string_unchanged(self) -> None:
        self.assertEqual(normalize_value("   "), "   ")

    def test_string_json_array_parsed(self) -> None:
        result = normalize_value("[1, 2, 3]")
        self.assertEqual(result, [1, 2, 3])

    def test_string_json_object_parsed(self) -> None:
        result = normalize_value('{"a": 1}')
        self.assertEqual(result, {"a": 1})

    def test_string_json_array_nested(self) -> None:
        result = normalize_value('[{"x": 1}, {"x": 2}]')
        self.assertEqual(result, [{"x": 1}, {"x": 2}])

    def test_string_invalid_json_starts_bracket(self) -> None:
        result = normalize_value("[1, 2, broken")
        self.assertEqual(result, "[1, 2, broken")

    def test_string_invalid_json_starts_brace(self) -> None:
        result = normalize_value('{"a": broken')
        self.assertEqual(result, '{"a": broken')

    def test_string_just_bracket_returns_self(self) -> None:
        self.assertEqual(normalize_value("["), "[")

    def test_string_just_brace_returns_self(self) -> None:
        self.assertEqual(normalize_value("{"), "{")

    def test_list_recursive(self) -> None:
        result = normalize_value([None, datetime(2025, 1, 1), [1, "hi"]])
        self.assertEqual(result, [None, "2025-01-01T00:00:00", [1, "hi"]])

    def test_empty_list(self) -> None:
        self.assertEqual(normalize_value([]), [])

    def test_dict_recursive(self) -> None:
        result = normalize_value({1: datetime(2025, 1, 1), "key": None})
        self.assertEqual(result, {"1": "2025-01-01T00:00:00", "key": None})

    def test_empty_dict(self) -> None:
        self.assertEqual(normalize_value({}), {})

    def test_nested_dict_in_list(self) -> None:
        value = [{"time": datetime(2025, 1, 1), "tags": ["a", "b"]}]
        expected = [{"time": "2025-01-01T00:00:00", "tags": ["a", "b"]}]
        self.assertEqual(normalize_value(value), expected)

    def test_deeply_nested_json_string(self) -> None:
        result = normalize_value('{"outer": {"inner": [1, 2, {"flag": true}]}}')
        self.assertEqual(result, {"outer": {"inner": [1, 2, {"flag": True}]}})

    def test_very_long_string(self) -> None:
        long_str = "x" * 100_000
        result = normalize_value(long_str)
        self.assertEqual(result, long_str)
        self.assertEqual(len(result), 100_000)


class FetchRecordsTests(unittest.TestCase):
    def _make_db(self, columns: list[str], rows: list[tuple]) -> MagicMock:
        db = MagicMock()
        result = MagicMock()
        result.description = [(c,) for c in columns]
        result.fetchall.return_value = rows
        db.execute.return_value = result
        return db

    def test_basic_query(self) -> None:
        db = self._make_db(["id", "name"], [(1, "alice"), (2, "bob")])
        got = fetch_records(db, "SELECT * FROM t")
        self.assertEqual(got, [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}])
        db.execute.assert_called_once_with("SELECT * FROM t", None)

    def test_with_params(self) -> None:
        db = self._make_db(["id"], [(1,)])
        got = fetch_records(db, "SELECT * FROM t WHERE id = ?", [1])
        self.assertEqual(got, [{"id": 1}])
        db.execute.assert_called_once_with("SELECT * FROM t WHERE id = ?", [1])

    def test_empty_results(self) -> None:
        db = self._make_db(["id", "name"], [])
        got = fetch_records(db, "SELECT * FROM t WHERE 1=0")
        self.assertEqual(got, [])

    def test_row_with_none(self) -> None:
        db = self._make_db(["a", "b"], [(1, None)])
        got = fetch_records(db, "SELECT * FROM t")
        self.assertEqual(got, [{"a": 1, "b": None}])

    def test_multiple_columns(self) -> None:
        db = self._make_db(
            ["c1", "c2", "c3"],
            [(10, "foo", True), (20, "bar", False)],
        )
        got = fetch_records(db, "SELECT c1, c2, c3 FROM t")
        self.assertEqual(
            got,
            [
                {"c1": 10, "c2": "foo", "c3": True},
                {"c1": 20, "c2": "bar", "c3": False},
            ],
        )

    def test_execute_raises_propagated(self) -> None:
        db = MagicMock()
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            fetch_records(db, "SELECT * FROM t")
