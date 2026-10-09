from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.core.case import Case
from forensia.core.evidence import make_evtx_evidence_id
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import lookup_evidence_record
from forensia.evidence.artifacts import MftArtifactAdapter, PrefetchArtifactAdapter
from forensia.evidence.evtx import ingest_evtx_file, normalize_evtx
from forensia.evidence.ingest import ingest_all
from forensia.evidence.mft import normalize_mft
from forensia.evidence.normalize import normalize_all
from forensia.pipeline import _run_normalize_stage


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
                source_sha: str,
                progress_callback=None,
            ):
                suffix = Path(source_path).suffix.lower()
                output = case_obj.raw_dir / f"{source_sha}{suffix or '.jsonl'}"
                output.write_text("{}", encoding="utf-8")
                return output

            with (
                patch(
                    "forensia.evidence.evtx.ingest_evtx_file", side_effect=fake_ingest
                ),
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
            self.assertTrue(all(len(key) == 64 for key in first["new_source_keys"]))
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
                source_sha: str,
                progress_callback=None,
            ):
                output = case_obj.raw_dir / f"prefetch-entries-{source_sha}.jsonl"
                output.write_text("{}", encoding="utf-8")
                return output, None

            with patch(
                "forensia.evidence.prefetch.ingest_prefetch_file",
                side_effect=fake_ingest,
            ):
                counts = ingest_all(case, input_dir)

            self.assertEqual(1, counts["new_files"])
            self.assertEqual(1, counts["prefetch_files"])
            self.assertEqual(0, counts["evtx_files"])
            self.assertEqual(0, counts["mft_files"])

    def test_evtx_reimport_is_stable_and_source_replacement_is_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            source_path = input_dir / "Security.evtx"
            source_path.write_text("first capture", encoding="utf-8")

            class FakeEvtxParser:
                def __init__(self, path):
                    self.message = Path(path).read_text(encoding="utf-8")

                def gen_records(self, **kwargs):
                    del kwargs
                    yield [
                        {
                            "@timestamp": "2015-06-15T10:00:00Z",
                            "winlog": {
                                "channel": "Security",
                                "record_id": 7,
                                "event_id": 4624,
                                "computer_name": "HOST-A",
                                "event_data": {"Message": self.message},
                            },
                        }
                    ]

            with (
                CaseDB(case) as db,
                patch("forensia.evidence.evtx.Evtx2es", FakeEvtxParser),
            ):
                first_ingest = ingest_all(case, input_dir, db=db)
                first_source = first_ingest["new_source_keys"][0]
                first_raw = case.raw_dir / f"evtx-{first_source}-security.jsonl"
                _run_normalize_stage(
                    case,
                    db,
                    init=True,
                    ingest_counts=first_ingest,
                    push_progress=lambda *args, **kwargs: None,
                    status=None,
                )
                first_id = make_evtx_evidence_id(first_source, "Security", 7)
                self.assertEqual(
                    first_id, lookup_evidence_record(db, first_id)["evidence_id"]
                )

                same_ingest = ingest_all(case, input_dir, db=db)
                self.assertEqual([], same_ingest["new_source_keys"])
                self.assertEqual(
                    first_id, lookup_evidence_record(db, first_id)["evidence_id"]
                )

                source_path.write_text("replacement capture", encoding="utf-8")
                replacement_ingest = ingest_all(case, input_dir, db=db)
                replacement_source = replacement_ingest["new_source_keys"][0]
                replacement_id = make_evtx_evidence_id(
                    replacement_source, "Security", 7
                )
                _run_normalize_stage(
                    case,
                    db,
                    init=True,
                    ingest_counts=replacement_ingest,
                    push_progress=lambda *args, **kwargs: None,
                    status=None,
                )

                self.assertNotEqual(first_source, replacement_source)
                self.assertNotEqual(first_id, replacement_id)
                self.assertTrue(first_raw.exists())
                self.assertIsNone(lookup_evidence_record(db, first_id))
                self.assertEqual(
                    replacement_id,
                    lookup_evidence_record(db, replacement_id)["evidence_id"],
                )
                normalize_all(case, db)
                self.assertEqual(
                    [(replacement_id,)],
                    db.execute(
                        "SELECT evidence_id FROM evtx_events WHERE source_file = ?",
                        [replacement_source],
                    ).fetchall(),
                )

    def test_evtx_streams_batches_and_replaces_raw_output_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            source = Path(tmpdir) / "Security.evtx"
            source.write_bytes(b"fixture")
            source_sha = "a" * 64
            output = case.raw_dir / f"evtx-{source_sha}-security.jsonl"
            output.write_text("previous raw data\n", encoding="utf-8")

            records = [
                {
                    "winlog": {"channel": "Security", "record_id": index},
                    "payload": index,
                }
                for index in (1, 2, 3)
            ]
            self_outer = self

            class ChunkedParser:
                def __init__(self, path):
                    del path

                def gen_records(self, **kwargs):
                    self.kwargs = kwargs
                    yield records[:1]
                    temporary = list(case.raw_dir.glob(".*.tmp"))
                    self_outer.assertEqual(1, len(temporary))
                    self_outer.assertEqual(
                        1, len(temporary[0].read_text().splitlines())
                    )
                    self_outer.assertEqual("previous raw data\n", output.read_text())
                    yield records[1:]

            with patch("forensia.evidence.evtx.Evtx2es", ChunkedParser):
                result = ingest_evtx_file(case, source, source_sha)

            self.assertEqual(output, result)
            parsed = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual([1, 2, 3], [row["payload"] for row in parsed])
            self.assertTrue(all(row["source_file"] == source_sha for row in parsed))
            self.assertEqual([output], list(case.raw_dir.glob("evtx-*.jsonl")))

    def test_evtx_parser_failure_preserves_existing_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            source = Path(tmpdir) / "Security.evtx"
            source.write_bytes(b"fixture")
            source_sha = "b" * 64
            output = case.raw_dir / f"evtx-{source_sha}-security.jsonl"
            output.write_text("preserve me\n", encoding="utf-8")

            class BrokenParser:
                def __init__(self, path):
                    del path

                def gen_records(self, **kwargs):
                    del kwargs
                    yield [{"winlog": {"channel": "Security", "record_id": 1}}]
                    raise ValueError("malformed trailing record")

            with patch("forensia.evidence.evtx.Evtx2es", BrokenParser):
                with self.assertRaisesRegex(ValueError, "malformed trailing"):
                    ingest_evtx_file(case, source, source_sha)

            self.assertEqual("preserve me\n", output.read_text(encoding="utf-8"))
            self.assertEqual([output], list(case.raw_dir.glob("evtx-*.jsonl")))

    def test_evtx_empty_parser_writes_empty_atomic_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            source = Path(tmpdir) / "System.evtx"
            source.write_bytes(b"fixture")
            source_sha = "c" * 64

            class EmptyParser:
                def __init__(self, path):
                    del path

                def gen_records(self, **kwargs):
                    del kwargs
                    if False:
                        yield []

            with patch("forensia.evidence.evtx.Evtx2es", EmptyParser):
                result = ingest_evtx_file(case, source, source_sha)

            self.assertEqual(case.raw_dir / f"evtx-{source_sha}-system.jsonl", result)
            self.assertEqual("", result.read_text(encoding="utf-8"))
            self.assertEqual([result], list(case.raw_dir.glob("evtx-*.jsonl")))

    def test_artifact_adapters_claim_only_matching_files(self) -> None:
        adapter = PrefetchArtifactAdapter()
        prefetch_dir = Path("/tmp/Prefetch")

        self.assertTrue(adapter.can_handle(prefetch_dir / "APP.EXE-12345678.pf"))
        self.assertFalse(adapter.can_handle(prefetch_dir))
        adapter = MftArtifactAdapter()
        self.assertTrue(adapter.can_handle(Path("/tmp/$MFT")))
        self.assertTrue(adapter.can_handle(Path("/tmp/MFT")))
        self.assertTrue(adapter.can_handle(Path("/tmp/MFT_C")))
        self.assertTrue(adapter.can_handle(Path("/tmp/exported_mft.bin")))

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

            def write_event(source_sha: str, record_id: int) -> Path:
                path = case.raw_dir / f"evtx-{source_sha}-security.jsonl"
                path.write_text(
                    json.dumps(
                        {
                            "evidence_id": make_evtx_evidence_id(
                                source_sha, "Security", record_id
                            ),
                            "source_file": source_sha,
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

            old_source = "a" * 64
            new_source = "b" * 64
            old_path = write_event(old_source, 1)
            write_event(new_source, 2)
            with CaseDB(case) as db:
                self.assertEqual(1, normalize_evtx(case, db, source_keys={old_source}))
                # If differential selection regresses, this malformed old file
                # makes the second normalization fail instead of being skipped.
                old_path.write_text("not-json\n", encoding="utf-8")
                self.assertEqual(1, normalize_evtx(case, db, source_keys={new_source}))
                rows = db.execute(
                    "SELECT record_id, evidence_id, source_file "
                    "FROM evtx_events ORDER BY record_id"
                ).fetchall()

            self.assertEqual(
                [
                    (1, make_evtx_evidence_id(old_source, "Security", 1), old_source),
                    (2, make_evtx_evidence_id(new_source, "Security", 2), new_source),
                ],
                rows,
            )

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
                "evidence_id": "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000042-00",
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

    # ─── R2-10 tests ───────────────────────────────────────────────────────────


if __name__ == "__main__":
    unittest.main()
