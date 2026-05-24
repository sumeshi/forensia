from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize.mft import normalize_mft


class NormalizeMftTests(unittest.TestCase):
    def test_normalize_mft_uses_duckdb_projection_and_preserves_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            mft_path = case.raw_dir / "mft.jsonl"
            source_file = "disk-image-1/$MFT"
            evidence_id = "mft-000000000001-01"

            mft_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "evidence_id": evidence_id,
                                "source_file": source_file,
                                "header": {
                                    "record_number": "1",
                                    "is_directory": "yes",
                                    "is_deleted": "0",
                                    "allocated_size": 0,
                                    "size": "42",
                                },
                                "attributes": {
                                    "StandardInformation": {
                                        "data": {
                                            "created": "2024-01-02T03:04:05Z",
                                            "modified": "bad-ts",
                                            "accessed": None,
                                            "mft_modified": "2024-01-02 04:05:06",
                                        }
                                    },
                                    "FileName": {
                                        "data": {
                                            "path": "/Windows/System32/calc.exe",
                                            "created": "2024-01-03T01:02:03Z",
                                            "modified": "",
                                            "accessed": "2024-01-04T01:02:03Z",
                                            "mft_modified": "not-a-date",
                                        }
                                    },
                                },
                            },
                            ensure_ascii=False,
                        )
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                entries, timeline_rows = normalize_mft(case, db)
                entry = db.execute(
                    """
                    SELECT
                        evidence_id, source_file, record_number, file_path, file_name, extension,
                        is_directory, is_deleted, size, si_created, si_modified, si_accessed,
                        si_mft_modified, fn_created, fn_modified, fn_accessed, fn_mft_modified
                    FROM mft_entries
                    """
                ).fetchone()
                timeline = db.execute(
                    """
                    SELECT timeline_id, timestamp_type, description, timestamp
                    FROM mft_timeline
                    ORDER BY timestamp_type
                    """
                ).fetchall()

            self.assertEqual(1, entries)
            self.assertEqual(4, timeline_rows)
            self.assertEqual(evidence_id, entry[0])
            self.assertEqual(source_file, entry[1])
            self.assertEqual(1, entry[2])
            self.assertEqual("/Windows/System32/calc.exe", entry[3])
            self.assertEqual("calc.exe", entry[4])
            self.assertEqual("exe", entry[5])
            self.assertTrue(entry[6])
            self.assertFalse(entry[7])
            self.assertEqual(42, entry[8])
            self.assertEqual(datetime(2024, 1, 2, 3, 4, 5), entry[9])
            self.assertIsNone(entry[10])
            self.assertIsNone(entry[11])
            self.assertEqual(datetime(2024, 1, 2, 4, 5, 6), entry[12])
            self.assertEqual(datetime(2024, 1, 3, 1, 2, 3), entry[13])
            self.assertIsNone(entry[14])
            self.assertEqual(datetime(2024, 1, 4, 1, 2, 3), entry[15])
            self.assertIsNone(entry[16])
            self.assertEqual(
                [
                    (
                        f"{evidence_id}-fn_accessed",
                        "FN_ACCESSED",
                        "FN_ACCESSED for /Windows/System32/calc.exe",
                        datetime(2024, 1, 4, 1, 2, 3),
                    ),
                    (
                        f"{evidence_id}-fn_created",
                        "FN_CREATED",
                        "FN_CREATED for /Windows/System32/calc.exe",
                        datetime(2024, 1, 3, 1, 2, 3),
                    ),
                    (
                        f"{evidence_id}-si_created",
                        "SI_CREATED",
                        "SI_CREATED for /Windows/System32/calc.exe",
                        datetime(2024, 1, 2, 3, 4, 5),
                    ),
                    (
                        f"{evidence_id}-si_mft_modified",
                        "SI_MFT_MODIFIED",
                        "SI_MFT_MODIFIED for /Windows/System32/calc.exe",
                        datetime(2024, 1, 2, 4, 5, 6),
                    ),
                ],
                timeline,
            )

            mft_path.write_text(
                json.dumps(
                    {
                        "evidence_id": evidence_id,
                        "source_file": source_file,
                        "header": {
                            "record_number": 1,
                            "is_directory": False,
                            "is_deleted": True,
                            "allocated_size": "100",
                        },
                        "attributes": {
                            "FileName": {
                                "data": {
                                    "path": "/Windows/System32/notepad.exe",
                                    "created": "2024-02-01T00:00:00Z",
                                }
                            }
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                entries, timeline_rows = normalize_mft(case, db)
                counts = db.execute(
                    "SELECT COUNT(*), COUNT(DISTINCT file_path) FROM mft_entries WHERE source_file = ?",
                    (source_file,),
                ).fetchone()
                timeline = db.execute(
                    """
                    SELECT timeline_id, timestamp_type, description
                    FROM mft_timeline
                    WHERE evidence_id = ?
                    ORDER BY timestamp_type
                    """,
                    (evidence_id,),
                ).fetchall()

            self.assertEqual(1, entries)
            self.assertEqual(1, timeline_rows)
            self.assertEqual((1, 1), counts)
            self.assertEqual(
                [
                    (
                        f"{evidence_id}-fn_created",
                        "FN_CREATED",
                        "FN_CREATED for /Windows/System32/notepad.exe",
                    )
                ],
                timeline,
            )


if __name__ == "__main__":
    unittest.main()
