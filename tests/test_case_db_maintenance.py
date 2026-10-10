from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import duckdb

from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import record_progress_event
from forensia.pipeline import (
    progress_pusher,
    reset_case_tables,
    run_investigation,
)


class CaseDbMaintenanceTests(unittest.TestCase):
    """Current schema/reopen and unsupported-case rejection, settings cache, progress pusher, report-only run."""

    def tearDown(self) -> None:
        reload_settings()

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def test_current_schema_reopens_without_rewriting_case_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id) VALUES ('E1', 4624)"
                )
                db.execute(
                    "INSERT INTO trace.hypothesis_reasoning (entry_id, body) VALUES ('R1', 'prior attempt')"
                )
            with CaseDB(case) as reopened:
                self.assertEqual(
                    ("E1", 4624),
                    reopened.execute(
                        "SELECT evidence_id, event_id FROM evtx_events"
                    ).fetchone(),
                )
                self.assertEqual(
                    ("R1", "prior attempt"),
                    reopened.execute(
                        "SELECT entry_id, body FROM trace.hypothesis_reasoning"
                    ).fetchone(),
                )
                self.assertEqual(
                    [("main",)],
                    reopened.execute(
                        "SELECT table_schema FROM information_schema.tables "
                        "WHERE table_name = 'forensia_schema'"
                    ).fetchall(),
                )
            self.assertTrue(case.database_path.is_file())
            self.assertFalse((case.db_dir / "trace.duckdb").exists())

    def test_unsupported_schema_is_rejected_without_changing_original_databases(
        self,
    ) -> None:
        for invalid in (
            "unversioned",
            "unsupported_version",
            "legacy_split",
        ):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as tmpdir:
                case = Case.init(tmpdir)
                if invalid == "unversioned":
                    case.db_dir.mkdir(parents=True, exist_ok=True)
                    with duckdb.connect(str(case.database_path)) as conn:
                        conn.execute(
                            "CREATE TABLE original_evidence AS SELECT 'keep me' AS value"
                        )
                else:
                    with CaseDB(case):
                        pass
                    if invalid == "unsupported_version":
                        with duckdb.connect(str(case.database_path)) as conn:
                            conn.execute("UPDATE forensia_schema SET version = -1")
                    else:
                        with duckdb.connect(str(case.db_dir / "trace.duckdb")):
                            pass
                originals = {
                    path: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (case.database_path, case.db_dir / "trace.duckdb")
                    if path.exists()
                }
                with self.assertRaisesRegex(
                    ValueError,
                    "Unsupported case schema|Unsupported split case databases",
                ):
                    CaseDB(case)
                self.assertEqual(
                    originals,
                    {
                        path: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in originals
                    },
                )
                self.assertEqual(
                    invalid == "legacy_split", (case.db_dir / "trace.duckdb").exists()
                )

    def test_read_only_case_db_does_not_initialize_or_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case(Path(tmpdir) / "missing")
            with self.assertRaises(FileNotFoundError):
                CaseDB(case, read_only=True)
            self.assertFalse(case.database_path.exists())
            self.assertFalse(case.db_dir.exists())
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with db.transaction():
                    db.execute(
                        "INSERT INTO trace.hypothesis_reasoning (entry_id, body) "
                        "VALUES ('R1', 'committed only if transaction succeeds')"
                    )
            with CaseDB(case, read_only=True) as db:
                with self.assertRaises(PermissionError):
                    with db.transaction():
                        pass
                with self.assertRaises(duckdb.InvalidInputException):
                    db.execute(
                        "INSERT INTO trace.hypothesis_reasoning (entry_id) VALUES ('R2')"
                    )
                self.assertEqual(
                    1,
                    db.execute(
                        "SELECT COUNT(*) FROM trace.hypothesis_reasoning"
                    ).fetchone()[0],
                )

    def test_trace_and_case_updates_share_transaction_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with self.assertRaises(RuntimeError):
                    with db.transaction():
                        db.execute("INSERT INTO findings (finding_id) VALUES ('F1')")
                        db.execute(
                            "INSERT INTO trace.hypothesis_reasoning (entry_id) VALUES ('R1')"
                        )
                        raise RuntimeError("abort both writes")
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                )
                self.assertEqual(
                    0,
                    db.execute(
                        "SELECT COUNT(*) FROM trace.hypothesis_reasoning"
                    ).fetchone()[0],
                )

    def test_progress_pusher_persists_compact_semantic_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch("forensia.pipeline.record_progress_event") as record_progress,
            ):
                push = progress_pusher(db)
                push(
                    progress_event(
                        "finding.created",
                        "completed",
                        severity="success",
                        refs={"finding_ids": ["F-1"]},
                        summary="Detection rule matched",
                        rule_id="R-1",
                    )
                )

            event = record_progress.call_args.args[1]
            self.assertEqual("finding.created", event["kind"])
            self.assertEqual({"finding_ids": ["F-1"]}, event["refs"])
            self.assertEqual({"rule_id": "R-1"}, event["attributes"])
            self.assertNotIn("counts", event)
            self.assertNotIn("recent_log_entries", event)
            self.assertNotIn("hypotheses", event)

    def test_reset_clears_derived_state_and_preserves_source_registrations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO ingested_files (sha256, path, source_kind, size, ingested_at)
                    VALUES ('sha-1', '/tmp/a.evtx', 'evtx', 10, now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO claims (
                        claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
                        support_status, created_at, updated_at
                    ) VALUES ('C-1', '1_overview', 'claim', '[]', '[]', '[]', 'supported', now(), now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO prefetch_timeline (
                        timeline_id, evidence_id, executable_name, prefetch_hash, exec_time, exec_index, source_file, tags
                    ) VALUES ('PT-1', 'prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool-abc123', 'tool.exe', 'abc123', now(), 0, 'TOOL.EXE.pf', '[]')
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_facts (
                        fact_id, fact_type, fact_key, fact_value, evidence_ids, source_query,
                        source_section, confidence, created_at, updated_at
                    ) VALUES ('SF-1', 'universal_question', 'host_identity', '{}', '[]', 'structured:host_identity', '1_overview', 0.9, now(), now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_evidence (
                        section_key, block_heading, evidence_id, role, source_query, created_at
                    ) VALUES ('1_overview', 'Scope', 'evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001', 'supporting', 'overview_hosts', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO query_cache (sql_hash, sql_text, result_json, executed_at)
                    VALUES ('hash-1', 'SELECT 1', '[{"x":1}]', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_runs (run_id, section_key, block_heading, iteration, phase, payload, verdict, created_at)
                    VALUES ('SR-1', '1_overview', 'Scope', 1, 'query', '{}', 'sufficient', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_questions (
                        question_id, section_key, block_heading, question_text, question_type,
                        answer_spec, intent, confidence, matched_rule, required_evidence,
                        status, created_at, updated_at
                    ) VALUES ('SQ-1', '1_overview', 'Scope', 'question', 'host_identity',
                              'host_identity', 'List hosts', 1.0, 'host_identity', '{}', 'resolved', now(), now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO trace.hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H-1', 'S-1', 1, 'check', 'confirmed', 'Q-1', 'body', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO trace.retrieval_events (
                        event_id, session_id, scope_kind, scope_id, phase, source_kind,
                        query_terms, candidate_count, selected_refs, rejected_refs,
                        selected_chars, budget, created_at
                    ) VALUES ('RE-1', 'S-1', 'hypothesis', 'H-1', 'index', 'memory',
                              '[]', 1, '[]', '[]', 0, 1024, now())
                    """
                )
                record_progress_event(
                    db,
                    progress_event(
                        "investigation.completed",
                        "completed",
                        session_id="S-1",
                        summary="prior run receipt",
                    ),
                )

                rebuild_tables = (
                    ("registry_artifacts", "artifact_id"),
                    ("registry_timeline", "timeline_id"),
                    ("case_timeline", "entry_id"),
                    ("llm_logical_calls", "logical_call_id"),
                    ("llm_provider_attempts", "attempt_id"),
                    ("llm_deterministic_ops", "op_id"),
                )
                for table, key in rebuild_tables:
                    schema = "trace." if table.startswith("llm_") else ""
                    db.execute(
                        f"INSERT INTO {schema}{table} ({key}) VALUES ('reset-target')"
                    )

                reset_case_tables(db)

                for table, _key in rebuild_tables:
                    schema = "trace." if table.startswith("llm_") else ""
                    self.assertEqual(
                        0,
                        db.execute(f"SELECT COUNT(*) FROM {schema}{table}").fetchone()[
                            0
                        ],
                        table,
                    )

                self.assertEqual(
                    1, db.execute("SELECT COUNT(*) FROM ingested_files").fetchone()[0]
                )
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
                )
                self.assertEqual(
                    0,
                    db.execute("SELECT COUNT(*) FROM prefetch_timeline").fetchone()[0],
                )
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM section_facts").fetchone()[0]
                )
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM section_evidence").fetchone()[0]
                )
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM query_cache").fetchone()[0]
                )
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM section_runs").fetchone()[0]
                )
                self.assertEqual(
                    0,
                    db.execute("SELECT COUNT(*) FROM section_questions").fetchone()[0],
                )
                self.assertEqual(
                    0,
                    db.execute(
                        "SELECT COUNT(*) FROM trace.hypothesis_reasoning"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    db.execute(
                        "SELECT COUNT(*) FROM trace.retrieval_events"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    db.execute("SELECT COUNT(*) FROM trace.progress_events").fetchone()[
                        0
                    ],
                )

    def test_run_renders_report_once_via_render_written_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "a.evtx").write_text("alpha", encoding="utf-8")
            output_dir = Path(tmpdir) / "case"

            with (
                patch(
                    "forensia.pipeline.ingest_all",
                    return_value={
                        "new_files": 1,
                        "skipped_files": 0,
                        "evtx_files": 1,
                        "mft_files": 0,
                        "prefetch_files": 0,
                    },
                ),
                patch(
                    "forensia.pipeline.normalize_all",
                    return_value={
                        "evtx_rows": 1,
                        "mft_entries": 0,
                        "mft_timeline_rows": 0,
                        "prefetch_executions": 0,
                    },
                ),
                patch("forensia.cli.app.resolve_llm_config", return_value=(None, None)),
                patch("forensia.pipeline.load_rules", return_value=[]),
                patch(
                    "forensia.pipeline.render_written_report",
                    return_value=(
                        output_dir / "reports" / "report.md",
                        output_dir / "reports" / "report.html",
                    ),
                ) as mock_render_written,
            ):
                run_investigation(
                    str(output_dir),
                    input_dir=str(input_dir),
                    llm_base_url=None,
                    model=None,
                )

            mock_render_written.assert_called_once()


if __name__ == "__main__":
    unittest.main()
