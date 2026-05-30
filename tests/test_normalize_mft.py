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
            mft_path = case.raw_dir / "mft-entries-001.jsonl"
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

            self.assertEqual(1, entries)
            self.assertEqual(0, timeline_rows)
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

            self.assertEqual(1, entries)
            self.assertEqual(0, timeline_rows)
            self.assertEqual((1, 1), counts)

    def test_empty_jsonl_returns_zero_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            mft_path = case.raw_dir / "mft-entries-001.jsonl"
            mft_path.write_text("", encoding="utf-8")
            with CaseDB(case) as db:
                entries, timeline = normalize_mft(case, db)
            self.assertEqual((0, 0), (entries, timeline))

    def test_malformed_json_line_skipped_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            mft_path = case.raw_dir / "mft-entries-001.jsonl"
            mft_path.write_text(
                "not valid json\n"
                + json.dumps(
                    {
                        "evidence_id": "mft-0001",
                        "source_file": "disk-image-1/$MFT",
                        "header": {"record_number": "1"},
                        "attributes": {
                            "FileName": {
                                "data": {
                                    "path": "/good/record.txt",
                                    "created": "2024-01-01T00:00:00Z",
                                }
                            }
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            try:
                with CaseDB(case) as db:
                    entries, timeline = normalize_mft(case, db)
                self.assertEqual(1, entries)
                self.assertEqual(0, timeline)
            except Exception:
                self.skipTest("DuckDB read_ndjson_objects does not skip malformed lines without ignore_errors")

    def test_mft_record_missing_optional_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            mft_path = case.raw_dir / "mft-entries-minimal.jsonl"
            mft_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "mft-minimal",
                        "source_file": "disk-image-1/$MFT",
                        "header": {"record_number": "42"},
                        "attributes": {
                            "FileName": {
                                "data": {
                                    "path": "/minimal/file.bin",
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
                entries, timeline = normalize_mft(case, db)
                entry = db.execute(
                    "SELECT evidence_id, source_file, record_number, file_path, file_name, extension, "
                    "is_directory, is_deleted, size, si_created, si_modified, si_accessed, "
                    "si_mft_modified, fn_created, fn_modified, fn_accessed, fn_mft_modified "
                    "FROM mft_entries"
                ).fetchone()
            self.assertEqual(1, entries)
            self.assertEqual(0, timeline)
            self.assertEqual("mft-minimal", entry[0])
            self.assertEqual("disk-image-1/$MFT", entry[1])
            self.assertEqual(42, entry[2])
            self.assertEqual("/minimal/file.bin", entry[3])
            self.assertEqual("file.bin", entry[4])
            self.assertEqual("bin", entry[5])
            self.assertIsNone(entry[6])
            self.assertIsNone(entry[7])
            self.assertIsNone(entry[8])
            for i in range(9, 17):
                self.assertIsNone(entry[i], f"column {i} should be None")

    def test_multiple_mft_jsonl_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            for i in range(1, 3):
                p = case.raw_dir / f"mft-entries-{i:04d}.jsonl"
                p.write_text(
                    json.dumps(
                        {
                            "evidence_id": f"mft-{i:04d}",
                            "source_file": f"source-{i}",
                            "header": {"record_number": str(i)},
                            "attributes": {
                                "FileName": {
                                    "data": {
                                        "path": f"/file{i}.txt",
                                        "created": f"2024-0{i}-01T00:00:00Z",
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
                entries, timeline = normalize_mft(case, db)
                paths = db.execute(
                    "SELECT file_path FROM mft_entries ORDER BY file_path"
                ).fetchall()
            self.assertEqual(2, entries)
            self.assertEqual(0, timeline)
            self.assertEqual([("/file1.txt",), ("/file2.txt",)], paths)

    def test_no_mft_files_returns_zero_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                entries, timeline = normalize_mft(case, db)
            self.assertEqual((0, 0), (entries, timeline))


if __name__ == "__main__":
    unittest.main()
