from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock

from forensia.api.service import (
    get_case_dto,
    list_event_volume_dto,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


def _make_mock_result(columns, rows):
    mock = MagicMock()
    mock.description = [(c,) for c in columns]
    mock.fetchall.return_value = rows
    mock.fetchone.return_value = rows[0] if rows else None
    return mock


class TestGetCaseDto(unittest.TestCase):
    def test_handles_empty_manifest_file(self):
        case = MagicMock(spec=Case)
        case.path = MagicMock()
        case.path.name = "bare"
        case.manifest_path.read_text.return_value = ""
        result = get_case_dto(case)
        self.assertEqual(result.paths, {})
        self.assertEqual(result.manifest, {})


class TestListEventVolumeDto(unittest.TestCase):
    def test_detected_source_returns_detected_volume(self):
        db = MagicMock(spec=CaseDB)
        evidence_json = json.dumps([{"timestamp": "2024-01-15T10:30:00"}])
        db.execute.return_value = _make_mock_result(
            ["evidence", "created_at"],
            [(evidence_json, "2024-01-15T12:00:00")],
        )
        result = list_event_volume_dto(db, bucket="day", source="detected")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].series, "detected")
        self.assertEqual(result[0].bucket, "2024-01-15T00:00:00")
        self.assertEqual(result[0].count, 1)

    def test_detected_uses_created_at_fallback(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            ["evidence", "created_at"],
            [("[]", "2024-06-01T12:00:00")],
        )
        result = list_event_volume_dto(db, bucket="month", source="detected")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-06-01T00:00:00")

    def test_all_source_combines_evtx_and_mft(self):
        db = MagicMock(spec=CaseDB)
        evtx_row = ("2024-01-01 00:00:00", "Security", 10)
        mft_row = ("2024-01-01 00:00:00", "mft:modified", 5)
        db.execute.side_effect = [
            _make_mock_result(["bucket", "series", "count"], [evtx_row]),
            _make_mock_result(["bucket", "series", "count"], [mft_row]),
        ]
        result = list_event_volume_dto(db, bucket="day", source="all")
        self.assertEqual(len(result), 2)
        series_set = {r.series for r in result}
        self.assertIn("Security", series_set)
        self.assertIn("mft:modified", series_set)

    def test_all_source_empty_both(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(["bucket", "series", "count"], []),
            _make_mock_result(["bucket", "series", "count"], []),
        ]
        result = list_event_volume_dto(db, bucket="day", source="all")
        self.assertEqual(result, [])

    def test_falls_back_to_day_for_invalid_bucket(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            ["bucket", "series", "count"],
            [("2024-01-01 00:00:00", "Security", 1)],
        )
        result = list_event_volume_dto(db, bucket="invalid", source="evtx")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")


if __name__ == "__main__":
    unittest.main()
