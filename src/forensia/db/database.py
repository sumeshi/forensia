from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import duckdb

from forensia.core.case import Case
from forensia.db.schema import CORE_SCHEMA_SQL, TRACE_SCHEMA_SQL, TRACE_TABLES


class CaseDB:
    def __init__(self, case: Case):
        """Connect to the case DuckDB database, attach trace DB, and initialize schema."""
        self.case = case
        self.case.db_dir.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(case.database_path))
        self.conn.execute(f"ATTACH '{case.trace_database_path.as_posix()}' AS trace")
        self.init_schema()

    def init_schema(self) -> None:
        """Apply core and trace schema SQL, then run pending migrations."""
        self.conn.execute(CORE_SCHEMA_SQL)
        self.conn.execute(TRACE_SCHEMA_SQL)
        for table_name in sorted(TRACE_TABLES):
            self.conn.execute(
                f"CREATE OR REPLACE TEMP VIEW {table_name} AS SELECT * FROM trace.{table_name}"
            )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_key VARCHAR PRIMARY KEY,
                applied_at TIMESTAMP
            )
            """
        )
        self._apply_migration_once(
            "legacy_schema_backfill", self._apply_legacy_schema_backfill
        )
        self._apply_migration_once(
            "investigation_steps_hypothesis_id",
            self._apply_investigation_steps_hypothesis_id,
        )
        self._apply_migration_once(
            "hypotheses_target_keypoint_id", self._apply_hypotheses_target_keypoint_id
        )
        self._apply_migration_once("section_questions", self._apply_section_questions)
        self._apply_migration_once(
            "hypotheses_source_decl_id", self._apply_hypotheses_source_decl_id
        )
        self._apply_migration_once(
            "mft_entries_fn_name", self._apply_mft_entries_fn_name
        )
        self._apply_migration_once(
            "m1_investigation_state", self._apply_m1_investigation_state
        )
        self._apply_migration_once(
            "harness_state_v2_backfill", self._apply_harness_state_v2_backfill
        )

    def _apply_migration_once(
        self, migration_key: str, callback: Callable[[], None]
    ) -> None:
        """Execute a migration callback only if it has not been applied before."""
        existing = self.conn.execute(
            "SELECT 1 FROM schema_migrations WHERE migration_key = ? LIMIT 1",
            (migration_key,),
        ).fetchone()
        if existing is not None:
            return
        callback()
        self.conn.execute(
            "INSERT INTO schema_migrations (migration_key, applied_at) VALUES (?, now())",
            (migration_key,),
        )

    def _apply_legacy_schema_backfill(self) -> None:
        """Backfill legacy columns for evtx_events and migrate old status/verdict values."""
        self.conn.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack JSON")
        self.conn.execute(
            "ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'draft'"
        )
        self.conn.execute(
            "ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS update_count INTEGER DEFAULT 0"
        )
        for column_name, column_type in (
            ("dst_ip", "VARCHAR"),
            ("dst_port", "VARCHAR"),
            ("protocol", "VARCHAR"),
            ("process_id", "VARCHAR"),
            ("exception_code", "VARCHAR"),
            ("object_dn", "VARCHAR"),
            ("attribute", "VARCHAR"),
            ("target_server", "VARCHAR"),
            ("target_group", "VARCHAR"),
            ("task_name", "VARCHAR"),
            ("session_id", "VARCHAR"),
            ("share_name", "VARCHAR"),
            ("access_mask", "VARCHAR"),
            ("normalized_src_ip", "VARCHAR"),
            ("normalized_target_user", "VARCHAR"),
            ("parent_process", "VARCHAR"),
            ("parent_process_id", "VARCHAR"),
            ("parent_cmd", "VARCHAR"),
            ("child_process", "VARCHAR"),
            ("child_process_id", "VARCHAR"),
            ("child_cmd", "VARCHAR"),
            ("parent_guid", "VARCHAR"),
            ("child_guid", "VARCHAR"),
            ("clear_time", "TIMESTAMP"),
            ("clear_event_id", "INTEGER"),
            ("reason", "VARCHAR"),
        ):
            self.conn.execute(
                f"ALTER TABLE evtx_events ADD COLUMN IF NOT EXISTS {column_name} {column_type}"
            )
        self.conn.execute(
            "UPDATE report_sections SET status = 'ai_exhausted' WHERE status = 'approved'"
        )
        legacy_verdict = "new" + "_finding"
        self.conn.execute(
            "UPDATE trace.ai_reviews SET verdict = 'newlead' WHERE verdict = ?",
            (legacy_verdict,),
        )
        self.conn.execute(
            "UPDATE hypotheses SET verdict = 'newlead' WHERE verdict = ?",
            (legacy_verdict,),
        )

    def _apply_investigation_steps_hypothesis_id(self) -> None:
        """Add hypothesis_id column to the investigation_steps trace table."""
        self.conn.execute(
            "ALTER TABLE trace.investigation_steps ADD COLUMN IF NOT EXISTS hypothesis_id VARCHAR"
        )

    def _apply_hypotheses_target_keypoint_id(self) -> None:
        """Add target_keypoint_id column to the hypotheses table."""
        self.conn.execute(
            "ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS target_keypoint_id VARCHAR"
        )

    def _apply_hypotheses_source_decl_id(self) -> None:
        """Add source_decl_id column to the hypotheses table."""
        self.conn.execute(
            "ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS source_decl_id VARCHAR"
        )

    def _apply_mft_entries_fn_name(self) -> None:
        """Add fn_name column to the mft_entries table."""
        self.conn.execute(
            "ALTER TABLE mft_entries ADD COLUMN IF NOT EXISTS fn_name VARCHAR"
        )

    def _apply_section_questions(self) -> None:
        """Create semantic question registry table for report blocks."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS section_questions (
                question_id VARCHAR PRIMARY KEY,
                section_key VARCHAR,
                block_heading VARCHAR,
                question_text VARCHAR,
                question_type VARCHAR,
                answer_spec VARCHAR,
                intent VARCHAR,
                confidence DOUBLE,
                matched_rule VARCHAR,
                required_evidence JSON,
                status VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_section_questions_section ON section_questions(section_key, block_heading)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_section_questions_spec ON section_questions(answer_spec)"
        )

    def _apply_m1_investigation_state(self) -> None:
        """Add investigation harness tables and hypothesis enrichment columns."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_sources (
                source_id VARCHAR PRIMARY KEY,
                artifact_family VARCHAR,
                display_path VARCHAR,
                ingest_status VARCHAR,
                parser_name VARCHAR,
                parser_version VARCHAR,
                row_count INTEGER,
                channel VARCHAR,
                hosts JSON,
                volume_id VARCHAR,
                min_time TIMESTAMP,
                max_time TIMESTAMP,
                error_code VARCHAR,
                error_summary VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_sources_family ON evidence_sources(artifact_family)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_sources_status ON evidence_sources(ingest_status)"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_coverage (
                capability VARCHAR,
                host VARCHAR,
                channel VARCHAR,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                source_family VARCHAR,
                state VARCHAR,
                reason_code VARCHAR,
                source_ids JSON,
                confidence DOUBLE,
                derived_at TIMESTAMP,
                UNIQUE(capability, host, channel, source_family)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_coverage_capability ON evidence_coverage(capability)"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_state (
                state_id VARCHAR PRIMARY KEY DEFAULT 'case',
                objective VARCHAR,
                status VARCHAR DEFAULT 'active',
                termination_policy JSON,
                stop_reason_code VARCHAR,
                stop_reason VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS report_gaps (
                gap_id VARCHAR PRIMARY KEY,
                section_key VARCHAR,
                block_heading VARCHAR,
                description VARCHAR,
                kind VARCHAR,
                status VARCHAR DEFAULT 'open',
                source_claim_id VARCHAR,
                hypothesis_id VARCHAR,
                task_id VARCHAR,
                coverage_reason VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_report_gaps_status ON report_gaps(status)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_report_gaps_section ON report_gaps(section_key)"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_tasks (
                task_id VARCHAR PRIMARY KEY,
                kind VARCHAR,
                description VARCHAR,
                status VARCHAR DEFAULT 'open',
                gap_id VARCHAR,
                hypothesis_id VARCHAR,
                required_capability VARCHAR,
                reason VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_investigation_tasks_status ON investigation_tasks(status)"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hypothesis_relations (
                from_hypothesis_id VARCHAR,
                to_hypothesis_id VARCHAR,
                relation_type VARCHAR,
                origin VARCHAR,
                confidence DOUBLE,
                rationale VARCHAR,
                created_session VARCHAR,
                created_at TIMESTAMP,
                UNIQUE(from_hypothesis_id, to_hypothesis_id, relation_type)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hypothesis_relations_from ON hypothesis_relations(from_hypothesis_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hypothesis_relations_to ON hypothesis_relations(to_hypothesis_id)"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hypothesis_evidence (
                link_id VARCHAR PRIMARY KEY,
                hypothesis_id VARCHAR,
                evidence_id VARCHAR,
                finding_id VARCHAR,
                query_id VARCHAR,
                assessment_id VARCHAR,
                role VARCHAR,
                source_family VARCHAR,
                source_file VARCHAR,
                derivation_group VARCHAR,
                strength VARCHAR,
                created_session VARCHAR,
                created_at TIMESTAMP
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hypothesis_evidence_hypothesis ON hypothesis_evidence(hypothesis_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hypothesis_evidence_evidence ON hypothesis_evidence(evidence_id)"
        )
        for col, typ in (
            ("source_gap_id", "VARCHAR"),
            ("selection_count", "INTEGER DEFAULT 0"),
            ("last_selected_at", "TIMESTAMP"),
            ("next_eligible_at", "TIMESTAMP"),
            ("blocked_reason", "VARCHAR"),
            ("sufficiency_status", "VARCHAR"),
            ("sufficiency_score", "DOUBLE"),
            ("sufficiency_reason", "VARCHAR"),
            ("sufficiency_policy_id", "VARCHAR"),
            ("human_review_required", "BOOLEAN DEFAULT FALSE"),
            ("evidence_requirements", "JSON"),
        ):
            self.conn.execute(
                f"ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS {col} {typ}"
            )

    def _apply_harness_state_v2_backfill(self) -> None:
        """Backfill authoritative harness state for cases created before M1."""
        self.conn.execute(
            "ALTER TABLE hypotheses ADD COLUMN IF NOT EXISTS evidence_requirements JSON"
        )
        source_rows = self.conn.execute(
            "SELECT sha256, path, source_kind FROM ingested_files"
        ).fetchall()
        for source_id, path, family in source_rows:
            source_path = str(path or "")
            lookup_path = (
                source_path.rsplit("/", 1)[-1]
                if str(family or "") == "prefetch"
                else source_path
            )
            table = {
                "evtx": "evtx_events",
                "mft": "mft_entries",
                "prefetch": "prefetch_executions",
            }.get(str(family or ""))
            count = 0
            channel = ""
            hosts: list[str] = []
            min_time = None
            max_time = None
            if table:
                count = int(
                    self.conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE source_file = ?",
                        [lookup_path],
                    ).fetchone()[0]
                )
            if family == "evtx":
                metadata = self.conn.execute(
                    "SELECT MIN(timestamp), MAX(timestamp), list(DISTINCT channel), "
                    "list(DISTINCT computer) FROM evtx_events WHERE source_file = ?",
                    [lookup_path],
                ).fetchone()
                min_time, max_time = metadata[0], metadata[1]
                channels = [str(item) for item in (metadata[2] or []) if item]
                channel = channels[0] if len(channels) == 1 else ""
                hosts = [str(item) for item in (metadata[3] or []) if item]
            self.conn.execute(
                "INSERT INTO evidence_sources (source_id, artifact_family, display_path, "
                "ingest_status, parser_name, row_count, channel, hosts, min_time, "
                "max_time, created_at, updated_at) "
                "VALUES (?, ?, ?, 'normalized', ?, ?, ?, ?, ?, ?, now(), now()) "
                "ON CONFLICT (source_id) DO NOTHING",
                [
                    source_id,
                    family,
                    source_path,
                    family,
                    count,
                    channel,
                    json.dumps(hosts),
                    min_time,
                    max_time,
                ],
            )

        for section_key, raw_gaps in self.conn.execute(
            "SELECT section_key, gaps FROM report_sections WHERE gaps IS NOT NULL"
        ).fetchall():
            gaps = raw_gaps
            if isinstance(gaps, str):
                try:
                    gaps = json.loads(gaps)
                except TypeError, ValueError:
                    gaps = []
            for description in gaps if isinstance(gaps, list) else []:
                text = str(description).strip()
                if not text:
                    continue
                gap_id = "GAP-" + hashlib.sha256(text.encode()).hexdigest()[:16]
                self.conn.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, description, kind, "
                    "status, created_at, updated_at) VALUES (?, ?, ?, "
                    "'internal_db_check', 'open', now(), now()) "
                    "ON CONFLICT (gap_id) DO NOTHING",
                    [gap_id, section_key, text],
                )

    def _route_trace_write(self, query: str) -> str:
        """Rewrite unqualified INSERT/UPDATE/DELETE to use the trace schema prefix."""
        stripped = query.lstrip()
        lowered = stripped.lower()
        if not lowered.startswith(("insert", "update", "delete")):
            return query
        for prefix in ("insert into ", "update ", "delete from "):
            if not lowered.startswith(prefix):
                continue
            for table_name in TRACE_TABLES:
                pattern = rf"(?i)\b{prefix.strip()}\s+{table_name}\b"
                if re.search(pattern, stripped):
                    return re.sub(
                        rf"(?i)\b{table_name}\b",
                        f"trace.{table_name}",
                        stripped,
                        count=1,
                    )
        return query

    def execute(
        self, query: str, params: Sequence[Any] | None = None
    ) -> duckdb.DuckDBPyConnection:
        """Execute a SQL query, routing trace writes automatically."""
        routed_query = self._route_trace_write(query)
        if params is None:
            return self.conn.execute(routed_query)
        return self.conn.execute(routed_query, params)

    def insert_many(self, query: str, rows: Iterable[Sequence[Any]]) -> None:
        """Execute a parameterized INSERT for multiple rows using executemany."""
        rows = list(rows)
        if not rows:
            return
        self.conn.executemany(query, rows)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit a group of writes atomically, rolling back on failure."""
        self.conn.execute("BEGIN TRANSACTION")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    @contextmanager
    def bulk_load_mode(self) -> Iterator[None]:
        """Bound memory during wide JSON loads, then restore connection settings."""
        previous_threads = int(
            self.conn.execute("SELECT current_setting('threads')").fetchone()[0]
        )
        previous_order = bool(
            self.conn.execute(
                "SELECT current_setting('preserve_insertion_order')"
            ).fetchone()[0]
        )
        self.conn.execute("SET threads = 1")
        self.conn.execute("SET preserve_insertion_order = false")
        try:
            yield
        finally:
            self.conn.execute(f"SET threads = {previous_threads}")
            self.conn.execute(
                "SET preserve_insertion_order = "
                + ("true" if previous_order else "false")
            )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> CaseDB:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
