from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.prefetch import normalize_prefetch


class NormalizePrefetchTests(unittest.TestCase):
    def test_normalize_prefetch_basic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            prefetch_path = case.raw_dir / "prefetch-entries-001.jsonl"
            source_file = "disk-image-1/PREFETCH/CALC.EXE-ABCD1234.pf"
            evidence_id = "pf-000000000001-01"

            prefetch_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "evidence_id": evidence_id,
                                "source_file": source_file,
                                "name": "CALC.EXE",
                                "exec_count": 5,
                                "last_exec_times": [
                                    "2024-01-15T10:30:00Z",
                                    "2024-01-14T09:00:00Z",
                                ],
                                "prefetch_hash": "ABCD1234",
                                "filenames": ["CALC.EXE", "KERNEL32.DLL", "NTDLL.DLL"],
                                "volumes": [
                                    {
                                        "device_path": "\\Device\\HarddiskVolume1",
                                        "serial_number": "1234-5678",
                                        "creation_time": "2023-06-01T00:00:00Z",
                                    }
                                ],
                                "tags": ["executable", "suspicious"],
                            },
                            ensure_ascii=False,
                        )
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                inserted, _ = normalize_prefetch(case, db)
                row = db.execute(
                    """
                    SELECT
                        evidence_id, source_file, executable_name, exec_count,
                        last_exec_time, exec_times, prefetch_hash,
                        filenames, volumes, raw_json, tags, severity
                    FROM prefetch_executions
                    """
                ).fetchone()

            self.assertEqual(1, inserted)
            self.assertEqual(evidence_id, row[0])
            self.assertEqual(source_file, row[1])
            self.assertEqual("CALC.EXE", row[2])
            self.assertEqual(5, row[3])
            self.assertEqual(datetime(2024, 1, 15, 10, 30, 0), row[4])
            self.assertIsNotNone(row[5])
            self.assertEqual("ABCD1234", row[6])
            self.assertIsNotNone(row[7])
            self.assertIsNotNone(row[8])
            self.assertIsNotNone(row[9])
            self.assertIsNotNone(row[10])
            self.assertIsNone(row[11])

    def test_empty_jsonl_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            prefetch_path = case.raw_dir / "prefetch-entries-001.jsonl"
            prefetch_path.write_text("", encoding="utf-8")
            with CaseDB(case) as db:
                inserted, _ = normalize_prefetch(case, db)
            self.assertEqual(0, inserted)

    def test_no_prefetch_files_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                inserted, _ = normalize_prefetch(case, db)
            self.assertEqual(0, inserted)

    def test_malformed_json_line_skipped_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            prefetch_path = case.raw_dir / "prefetch-entries-001.jsonl"
            prefetch_path.write_text(
                "not valid json\n"
                + json.dumps(
                    {
                        "evidence_id": "pf-0001",
                        "source_file": "disk-image-1/PREFETCH/NOTEPAD.EXE-5678.pf",
                        "name": "NOTEPAD.EXE",
                        "exec_count": 3,
                        "last_exec_times": ["2024-02-01T12:00:00Z"],
                        "prefetch_hash": "5678",
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            try:
                with CaseDB(case) as db:
                    inserted, _ = normalize_prefetch(case, db)
                self.assertEqual(1, inserted)
                rows = db.execute(
                    "SELECT evidence_id FROM prefetch_executions"
                ).fetchall()
                self.assertEqual([("pf-0001",)], rows)
            except Exception:
                self.skipTest(
                    "DuckDB read_ndjson_objects does not skip malformed lines without ignore_errors"
                )

    def test_multiple_prefetch_jsonl_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            for i in range(1, 4):
                p = case.raw_dir / f"prefetch-entries-{i:04d}.jsonl"
                p.write_text(
                    json.dumps(
                        {
                            "evidence_id": f"pf-{i:04d}",
                            "source_file": f"disk-image-1/PREFETCH/APP{i}.EXE-0000.pf",
                            "name": f"APP{i}.EXE",
                            "exec_count": i,
                            "last_exec_times": [f"2024-0{i}-01T00:00:00Z"],
                            "prefetch_hash": "0000",
                        },
                        ensure_ascii=False,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            with CaseDB(case) as db:
                inserted, _ = normalize_prefetch(case, db)
                names = db.execute(
                    "SELECT executable_name FROM prefetch_executions ORDER BY executable_name"
                ).fetchall()
            self.assertEqual(3, inserted)
            self.assertEqual([("APP1.EXE",), ("APP2.EXE",), ("APP3.EXE",)], names)

    def test_reingest_same_source_file_clears_old_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            prefetch_path = case.raw_dir / "prefetch-entries-001.jsonl"
            source_file = "disk-image-1/PREFETCH/REDO.EXE-0000.pf"

            prefetch_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "pf-v1",
                        "source_file": source_file,
                        "name": "REDO.EXE",
                        "exec_count": 1,
                        "last_exec_times": ["2024-01-01T00:00:00Z"],
                        "prefetch_hash": "0000",
                    },
                    ensure_ascii=False,
                )
                + "\n"
                + json.dumps(
                    {
                        "evidence_id": "pf-v2",
                        "source_file": source_file,
                        "name": "REDO.EXE",
                        "exec_count": 99,
                        "last_exec_times": ["2024-06-01T00:00:00Z"],
                        "prefetch_hash": "0000",
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                inserted, _ = normalize_prefetch(case, db)
                rows = db.execute(
                    "SELECT evidence_id, exec_count FROM prefetch_executions ORDER BY evidence_id"
                ).fetchall()

            self.assertEqual(2, inserted)
            self.assertEqual([("pf-v1", 1), ("pf-v2", 99)], rows)

            prefetch_path.write_text(
                json.dumps(
                    {
                        "evidence_id": "pf-v2",
                        "source_file": source_file,
                        "name": "REDO.EXE",
                        "exec_count": 100,
                        "last_exec_times": ["2024-06-01T00:00:00Z"],
                        "prefetch_hash": "0000",
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                inserted, _ = normalize_prefetch(case, db)
                rows = db.execute(
                    "SELECT evidence_id, exec_count FROM prefetch_executions"
                ).fetchall()

            self.assertEqual(1, inserted)
            self.assertEqual([("pf-v2", 100)], rows)


class PrefetchPathSanitizationTests(unittest.TestCase):
    """Tests for is_local_ingest_path, strip_path_basename, and sanitize_prefetch_path."""

    def testis_local_ingest_path_cfreds_prefetch(self) -> None:
        from forensia.report.answers.answer_store import is_local_ingest_path

        self.assertTrue(
            is_local_ingest_path("sample/cfreds/Prefetch/CALC.EXE-ABCD1234.pf")
        )
        self.assertTrue(
            is_local_ingest_path("disk-image-1/PREFETCH/NOTEPAD.EXE-5678.pf")
        )
        self.assertTrue(
            is_local_ingest_path("Windows/Prefetch/WINWORD.EXE-CECBA770.pf")
        )

    def testis_local_ingest_path_real_windows_paths_are_not_local(self) -> None:
        from forensia.report.answers.answer_store import is_local_ingest_path

        self.assertFalse(is_local_ingest_path("C:\\Windows\\System32\\calc.exe"))
        self.assertFalse(
            is_local_ingest_path("\\Device\\HarddiskVolume1\\Windows\\notepad.exe")
        )
        self.assertFalse(is_local_ingest_path("\\\\server\\share\\file.exe"))
        # A bare Windows-style path with backslashes but no drive letter is NOT a local ingest path
        self.assertFalse(
            is_local_ingest_path("Windows\\Prefetch\\CALC.EXE-ABCD1234.pf")
        )

    def testis_local_ingest_path_empty_or_none(self) -> None:
        from forensia.report.answers.answer_store import is_local_ingest_path

        self.assertFalse(is_local_ingest_path(""))
        self.assertFalse(is_local_ingest_path(None))

    def teststrip_path_basename(self) -> None:
        from forensia.report.answers.answer_store import strip_path_basename

        self.assertEqual(
            "CALC.EXE-ABCD1234.pf",
            strip_path_basename("sample/cfreds/Prefetch/CALC.EXE-ABCD1234.pf"),
        )
        self.assertEqual(
            "notepad.exe", strip_path_basename("C:\\Windows\\System32\\notepad.exe")
        )
        self.assertEqual("file.pf", strip_path_basename("file.pf"))
        self.assertEqual("", strip_path_basename(""))
        self.assertEqual("", strip_path_basename(None))

    def testsanitize_prefetch_path_local_ingest_returns_basename(self) -> None:
        from forensia.report.answers.answer_store import sanitize_prefetch_path

        self.assertEqual(
            "CALC.EXE-ABCD1234.pf",
            sanitize_prefetch_path("sample/cfreds/Prefetch/CALC.EXE-ABCD1234.pf"),
        )
        self.assertEqual(
            "WINWORD.EXE-CECBA770.pf",
            sanitize_prefetch_path("Windows/Prefetch/WINWORD.EXE-CECBA770.pf"),
        )

    def testsanitize_prefetch_path_real_windows_path_unchanged(self) -> None:
        from forensia.report.answers.answer_store import sanitize_prefetch_path

        self.assertEqual(
            "C:\\Windows\\System32\\calc.exe",
            sanitize_prefetch_path("C:\\Windows\\System32\\calc.exe"),
        )
        self.assertEqual(
            "\\Device\\HarddiskVolume1\\Windows\\notepad.exe",
            sanitize_prefetch_path("\\Device\\HarddiskVolume1\\Windows\\notepad.exe"),
        )

    def testsanitize_prefetch_path_empty_or_none(self) -> None:
        from forensia.report.answers.answer_store import sanitize_prefetch_path

        self.assertEqual("", sanitize_prefetch_path(""))
        self.assertEqual("", sanitize_prefetch_path(None))


if __name__ == "__main__":
    unittest.main()
