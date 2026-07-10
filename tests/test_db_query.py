"""Behavioral tests for database value and row normalization."""

from __future__ import annotations

import unittest
from datetime import datetime
from unittest.mock import MagicMock

from forensia.db.query import fetch_records, normalize_value


class NormalizeValueTests(unittest.TestCase):
    def test_scalar_normalization_matrix(self) -> None:
        cases = (
            (None, None),
            (datetime(2025, 1, 15, 8, 30, 45), "2025-01-15T08:30:45"),
            (
                datetime(2025, 6, 1, 12, 0, 0, 123456),
                "2025-06-01T12:00:00.123456",
            ),
            (42, 42),
            (3.14, 3.14),
            (True, True),
            (False, False),
            ("", ""),
            ("   ", "   "),
            ("hello world", "hello world"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(expected, normalize_value(value))

    def test_json_strings_and_invalid_lookalikes(self) -> None:
        cases = (
            ("[1, 2, 3]", [1, 2, 3]),
            ('{"a": 1}', {"a": 1}),
            ('[{"x": 1}, {"x": 2}]', [{"x": 1}, {"x": 2}]),
            ('{"outer": {"inner": [1, {"flag": true}]}}', {"outer": {"inner": [1, {"flag": True}]}}),
            ("[1, 2, broken", "[1, 2, broken"),
            ('{"a": broken', '{"a": broken'),
            ("[", "["),
            ("{", "{"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(expected, normalize_value(value))

    def test_containers_are_normalized_recursively(self) -> None:
        value = {
            1: datetime(2025, 1, 1),
            "items": [None, {"time": datetime(2025, 1, 2), "tags": ["a", "b"]}],
            "empty": {},
        }
        self.assertEqual(
            {
                "1": "2025-01-01T00:00:00",
                "items": [
                    None,
                    {"time": "2025-01-02T00:00:00", "tags": ["a", "b"]},
                ],
                "empty": {},
            },
            normalize_value(value),
        )


class FetchRecordsTests(unittest.TestCase):
    @staticmethod
    def _db(columns: list[str], rows: list[tuple]) -> MagicMock:
        db = MagicMock()
        result = MagicMock()
        result.description = [(column,) for column in columns]
        result.fetchall.return_value = rows
        db.execute.return_value = result
        return db

    def test_maps_rows_and_forwards_params(self) -> None:
        db = self._db(["id", "name"], [(1, "alice"), (2, None)])
        self.assertEqual(
            [{"id": 1, "name": "alice"}, {"id": 2, "name": None}],
            fetch_records(db, "SELECT * FROM t WHERE id > ?", [0]),
        )
        db.execute.assert_called_once_with("SELECT * FROM t WHERE id > ?", [0])

    def test_empty_results_and_database_errors(self) -> None:
        self.assertEqual([], fetch_records(self._db(["id"], []), "SELECT 1"))
        db = MagicMock()
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaisesRegex(RuntimeError, "db error"):
            fetch_records(db, "SELECT * FROM t")
