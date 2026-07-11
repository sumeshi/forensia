from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.cli import app as cli_module
from forensia.cli.support import (
    _progress_pusher,
    _reset_case_tables,
)
from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


class CaseDbMaintenanceTests(unittest.TestCase):
    """DB schema migration/backfill, settings cache, progress pusher, report-only run."""

    def tearDown(self) -> None:
        reload_settings()

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def test_schema_backfill_migration_runs_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                applied_count = db.execute(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_key = 'legacy_schema_backfill'"
                ).fetchone()[0]
            with CaseDB(case) as db:
                applied_count_reopen = db.execute(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_key = 'legacy_schema_backfill'"
                ).fetchone()[0]

            self.assertEqual(1, applied_count)
            self.assertEqual(1, applied_count_reopen)

    def test_schema_creates_indexes_for_lookup_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                names = {
                    row[0]
                    for row in db.execute(
                        """
                        SELECT index_name
                        FROM duckdb_indexes()
                        WHERE index_name IN (
                            'findings_by_id',
                            'findings_by_status_confidence',
                            'evtx_events_by_evidence_id',
                            'mft_entries_by_evidence_id',
                            'investigation_steps_by_session_hypothesis',
                            'ai_reviews_by_finding'
                        )
                        """
                    ).fetchall()
                }

            self.assertEqual(
                {
                    "findings_by_id",
                    "findings_by_status_confidence",
                    "evtx_events_by_evidence_id",
                    "mft_entries_by_evidence_id",
                    "investigation_steps_by_session_hypothesis",
                    "ai_reviews_by_finding",
                },
                names,
            )

    def test_progress_pusher_writes_progress_snapshot_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch("forensia.cli.support.write_progress_snapshot") as mock_progress,
                patch("forensia.cli.support.write_api_snapshots") as mock_full,
            ):
                push = _progress_pusher(
                    db,
                    {
                        "stage": "investigate",
                        "status": "running",
                        "iteration": 0,
                        "summary": "start",
                        "recent_logs": [],
                    },
                )
                push("tick", stage="investigate")

            mock_progress.assert_called_once()
            mock_full.assert_not_called()

    def test_reset_case_tables_clears_derived_report_and_ingest_tables(self) -> None:
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
                    ) VALUES ('PT-1', 'prefetch-tool-abc123', 'tool.exe', 'abc123', now(), 0, 'TOOL.EXE.pf', '[]')
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
                    ) VALUES ('1_overview', 'Scope', 'evtx-security-000000000001', 'supporting', 'overview_hosts', now())
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
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H-1', 'S-1', 1, 'check', 'confirmed', 'Q-1', 'body', now())
                    """
                )

                _reset_case_tables(db)

                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM ingested_files").fetchone()[0]
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
                    db.execute("SELECT COUNT(*) FROM hypothesis_reasoning").fetchone()[
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
                    "forensia.cli.stages.ingest_all",
                    return_value={
                        "new_files": 1,
                        "skipped_files": 0,
                        "evtx_files": 1,
                        "mft_files": 0,
                        "prefetch_files": 0,
                    },
                ),
                patch(
                    "forensia.cli.stages.normalize_all",
                    return_value={
                        "evtx_rows": 1,
                        "mft_entries": 0,
                        "mft_timeline_rows": 0,
                        "prefetch_executions": 0,
                    },
                ),
                patch("forensia.cli.app.resolve_llm_config", return_value=(None, None)),
                patch("forensia.cli.stages.load_rules_from_dir", return_value=[]),
                patch(
                    "forensia.cli.stages.render_written_report",
                    return_value=(
                        output_dir / "reports" / "report.md",
                        output_dir / "reports" / "report.html",
                    ),
                ) as mock_render_written,
                patch("forensia.cli.app.render_html_report") as mock_render_html,
                patch("forensia.cli.stages.write_api_snapshots"),
                patch("forensia.cli.support.write_api_snapshots"),
            ):
                cli_module.investigate(
                    case_dir=str(output_dir),
                    input_dir=str(input_dir),
                    profile="windows-basic",
                    llm_base_url=None,
                    model=None,
                )

            mock_render_written.assert_called_once()
            mock_render_html.assert_not_called()


if __name__ == "__main__":
    unittest.main()
