from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from forensia.cli import app as cli_module
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.artifacts import MftArtifactAdapter, PrefetchArtifactAdapter
from forensia.evidence.evtx import normalize_evtx
from forensia.evidence.ingest import ingest_all
from forensia.evidence.mft import normalize_mft
from forensia.evidence.normalize import normalize_all


class IngestTests(unittest.TestCase):
    """Ingest, artifact adapters, and normalize pipeline behavior."""

    def test_ingest_all_is_incremental_and_force_reingests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            for name, content in (
                ("a.evtx", "alpha"),
                ("b.evtx", "bravo"),
                ("MFT", "charlie"),
            ):
                (input_dir / name).write_text(content, encoding="utf-8")

            def fake_ingest(
                case_obj: Case,
                source_path: str | Path,
                source_sha: str | None = None,
                progress_callback=None,
            ):
                suffix = Path(source_path).suffix.lower()
                output = (
                    case_obj.raw_dir / f"{(source_sha or 'x')[:12]}{suffix or '.jsonl'}"
                )
                output.write_text("{}", encoding="utf-8")
                return output, None

            with (
                patch("forensia.evidence.evtx.ingest_evtx_file", side_effect=fake_ingest),
                patch(
                    "forensia.evidence.mft.ingest_mft_file",
                    side_effect=fake_ingest,
                ),
            ):
                first = ingest_all(case, input_dir)
                second = ingest_all(case, input_dir)
                (input_dir / "c.evtx").write_text("delta", encoding="utf-8")
                third = ingest_all(case, input_dir)
                forced = ingest_all(case, input_dir, force=True)

            with CaseDB(case) as db:
                ingested_count = db.execute(
                    "SELECT COUNT(*) FROM ingested_files"
                ).fetchone()[0]

            self.assertEqual(3, first["new_files"])
            self.assertEqual(3, len(first["new_source_keys"]))
            self.assertEqual(0, first["skipped_files"])
            self.assertEqual(0, second["new_files"])
            self.assertEqual([], second["new_source_keys"])
            self.assertEqual(3, second["skipped_files"])
            self.assertEqual(1, third["new_files"])
            self.assertEqual(4, forced["new_files"])
            self.assertEqual(4, ingested_count)

    def test_ingest_all_counts_prefetch_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "APP.EXE-12345678.pf").write_text("prefetch", encoding="utf-8")

            def fake_ingest(
                case_obj: Case,
                source_path: str | Path,
                source_sha: str | None = None,
                progress_callback=None,
            ):
                output = (
                    case_obj.raw_dir
                    / f"prefetch-entries-{(source_sha or 'x')[:12]}.jsonl"
                )
                output.write_text("{}", encoding="utf-8")
                return output, None

            with patch(
                "forensia.evidence.prefetch.ingest_prefetch_file", side_effect=fake_ingest
            ):
                counts = ingest_all(case, input_dir)

            self.assertEqual(1, counts["new_files"])
            self.assertEqual(1, counts["prefetch_files"])
            self.assertEqual(0, counts["evtx_files"])
            self.assertEqual(0, counts["mft_files"])

    def test_prefetch_adapter_only_claims_pf_files(self) -> None:
        adapter = PrefetchArtifactAdapter()
        prefetch_dir = Path("/tmp/Prefetch")

        self.assertTrue(adapter.can_handle(prefetch_dir / "APP.EXE-12345678.pf"))
        self.assertFalse(adapter.can_handle(prefetch_dir))

    def test_mft_adapter_accepts_names_containing_mft(self) -> None:
        adapter = MftArtifactAdapter()

        self.assertTrue(adapter.can_handle(Path("/tmp/$MFT")))
        self.assertTrue(adapter.can_handle(Path("/tmp/MFT")))
        self.assertTrue(adapter.can_handle(Path("/tmp/MFT_C")))
        self.assertTrue(adapter.can_handle(Path("/tmp/exported_mft.bin")))

    def test_normalize_all_includes_prefetch_execution_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch("forensia.evidence.evtx.normalize_evtx", return_value=0),
                patch(
                    "forensia.evidence.mft.normalize_mft",
                    return_value=(0, 0),
                ),
                patch(
                    "forensia.evidence.prefetch.normalize_prefetch",
                    return_value=(3, 0),
                ),
            ):
                counts = normalize_all(case, db)

            self.assertEqual(3, counts["prefetch_executions"])
            self.assertEqual(0, counts["prefetch_timeline"])
            self.assertEqual(0, counts["evtx_rows"])
            self.assertEqual(0, counts["mft_entries"])

    def test_normalize_evtx_ignores_prefetch_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.raw_dir / "prefetch-test.jsonl").write_text(
                json.dumps(
                    {
                        "source_type": "prefetch",
                        "source_file": "sample/Prefetch/APP.EXE-12345678.pf",
                        "name": "APP.EXE",
                        "evidence_id": "prefetch-app-1234",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                inserted = normalize_evtx(case, db)
                row_count = db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]

            self.assertEqual(0, inserted)
            self.assertEqual(0, row_count)

    def test_normalize_evtx_can_process_only_new_source_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)

            def write_event(key: str, record_id: int) -> Path:
                path = case.raw_dir / f"evtx-{key}-security.jsonl"
                path.write_text(
                    json.dumps(
                        {
                            "evidence_id": f"evtx-security-{record_id}",
                            "source_file": f"source-{key}.evtx",
                            "winlog": {
                                "channel": "Security",
                                "event_id": 4624,
                                "record_id": record_id,
                            },
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return path

            old_path = write_event("aaaaaaaaaaaa", 1)
            write_event("bbbbbbbbbbbb", 2)
            with CaseDB(case) as db:
                self.assertEqual(
                    1, normalize_evtx(case, db, source_keys={"aaaaaaaaaaaa"})
                )
                # If differential selection regresses, this malformed old file
                # makes the second normalization fail instead of being skipped.
                old_path.write_text("not-json\n", encoding="utf-8")
                self.assertEqual(
                    1, normalize_evtx(case, db, source_keys={"bbbbbbbbbbbb"})
                )
                rows = db.execute(
                    "SELECT record_id FROM evtx_events ORDER BY record_id"
                ).fetchall()

            self.assertEqual([(1,), (2,)], rows)

    def test_normalize_mft_uses_sql_projection_for_entries_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            record = {
                "header": {
                    "flags": "EntryFlags(ALLOCATED)",
                    "record_number": 42,
                    "is_directory": False,
                },
                "attributes": {
                    "StandardInformation": {
                        "data": {
                            "created": "2015-03-25T11:08:36.956950Z",
                            "modified": "2015-03-25T11:08:36.956950Z",
                            "mft_modified": "2015-03-25T11:08:36.956950Z",
                            "accessed": "2015-03-25T11:08:36.956950Z",
                        }
                    },
                    "FileName": {
                        "data": {
                            "created": "2015-03-25T11:08:36.956950Z",
                            "modified": "2015-03-25T11:08:36.956950Z",
                            "mft_modified": "2015-03-25T11:08:36.956950Z",
                            "accessed": "2015-03-25T11:08:36.956950Z",
                            "name": "example.txt",
                            "path": "C:\\Users\\informant\\Desktop\\example.txt",
                        }
                    },
                },
                "source_type": "mft",
                "source_file": "sample/cfreds/MFT_C",
                "evidence_id": "mft-000000000042-00",
            }
            (case.raw_dir / "mft-entries-test.jsonl").write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )

            with CaseDB(case) as db:
                entries, timeline = normalize_mft(case, db)
                entry = db.execute(
                    "SELECT record_number, file_name, extension, is_directory, is_deleted FROM mft_entries"
                ).fetchone()

            self.assertEqual(1, entries)
            self.assertEqual(8, timeline)
            self.assertEqual((42, "example.txt", "txt", False, False), entry)

    def test_cli_add_and_run_surface_prefetch_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case-add")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            runner = CliRunner()

            with patch(
                "forensia.cli.app.ingest_all",
                return_value={
                    "new_files": 1,
                    "skipped_files": 0,
                    "evtx_files": 0,
                    "mft_files": 0,
                    "prefetch_files": 1,
                },
            ):
                add_result = runner.invoke(
                    cli_module.app, ["add", str(case.path), str(input_dir)]
                )

            self.assertEqual(0, add_result.exit_code, add_result.output)
            self.assertIn("prefetch=1", add_result.output)

            output_dir = Path(tmpdir) / "case-run"
            with (
                patch(
                    "forensia.cli.stages.ingest_all",
                    return_value={
                        "new_files": 1,
                        "skipped_files": 0,
                        "evtx_files": 0,
                        "mft_files": 0,
                        "prefetch_files": 1,
                    },
                ),
                patch(
                    "forensia.cli.stages.normalize_all",
                    return_value={
                        "evtx_rows": 0,
                        "mft_entries": 0,
                        "mft_timeline_rows": 0,
                        "prefetch_executions": 2,
                    },
                ),
                patch("forensia.cli.app.resolve_llm_config", return_value=(None, None)),
                patch(
                    "forensia.cli.stages.load_rules_from_dir",
                    return_value=[],
                ),
                patch(
                    "forensia.cli.stages.render_written_report",
                    return_value=(
                        output_dir / "reports" / "report.md",
                        output_dir / "reports" / "report.html",
                    ),
                ),
                patch("forensia.cli.stages.write_all_snapshots"),
                patch("forensia.cli.support.write_all_snapshots"),
            ):
                run_result = runner.invoke(
                    cli_module.app, ["investigate", str(output_dir), str(input_dir)]
                )

            self.assertEqual(0, run_result.exit_code, run_result.output)
            self.assertIn("prefetch_files=1", run_result.output)
            self.assertIn("prefetch_executions=2", run_result.output)

    # ─── R2-10 tests ───────────────────────────────────────────────────────────


if __name__ == "__main__":
    unittest.main()
