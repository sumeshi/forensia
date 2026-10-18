"""Public-contract tests for the reusable investigation SQL templates."""

from __future__ import annotations

import tempfile
import unittest

import duckdb

from forensia.context.sql_templates import (
    query_template_catalog,
    render_query_template,
    validate_select_sql,
    validate_select_sql_with_dryrun,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


class DryRunValidationTests(unittest.TestCase):
    def test_dry_run_propagates_operational_duckdb_errors(self) -> None:
        for error_type in (
            duckdb.IOException,
            duckdb.ConnectionException,
            duckdb.InterruptException,
            duckdb.InternalException,
            duckdb.OutOfMemoryException,
        ):
            with self.subTest(error_type=error_type.__name__):

                class BrokenConnection:
                    def execute(self, _sql: str) -> None:
                        raise error_type("database execution failed")

                with self.assertRaises(error_type):
                    validate_select_sql_with_dryrun(
                        "SELECT x FROM t", BrokenConnection()
                    )

    def test_reports_binder_errors_and_returns_valid_sql(self) -> None:
        with duckdb.connect(":memory:") as conn:
            conn.execute("CREATE TABLE t (x INTEGER)")
            self.assertEqual(
                "SELECT x FROM t",
                validate_select_sql_with_dryrun("SELECT x FROM t", conn),
            )
            with self.assertRaises(ValueError):
                validate_select_sql_with_dryrun("SELECT nonexistent_func(1)", conn)


class QueryTemplateCatalogTests(unittest.TestCase):
    def test_catalog_declares_the_supported_public_templates(self) -> None:
        catalog = query_template_catalog()
        self.assertEqual(
            {
                "q_failed_logon_by_ip_window",
                "q_logon_by_user_window",
                "q_powershell_after_logon",
                "q_service_or_task_after_host_logon",
                "q_registry_timeline_recent",
            },
            {entry["template_id"] for entry in catalog},
        )
        for entry in catalog:
            self.assertTrue(entry["description"])
            self.assertTrue(
                all(isinstance(value, str) for value in entry["required_params"])
            )


class RenderQueryTemplateTests(unittest.TestCase):
    def test_every_template_renders_binder_valid_sql(self) -> None:
        cases = {
            "q_failed_logon_by_ip_window": (
                {"hours": 12, "threshold": 10},
                (
                    "event_id = 4625",
                    "12 hours",
                    "HAVING COUNT(*) >= 10",
                    "SELECT MAX(timestamp) FROM evtx_events",
                ),
            ),
            "q_logon_by_user_window": (
                {"user": "alice", "hours": 48},
                ("event_id = 4624", "lower('alice')", "48 hours"),
            ),
            "q_powershell_after_logon": (
                {"user": "alice", "hours": 24},
                (
                    "event_id = 4688",
                    "event_id = 4104",
                    "15 minutes",
                    "JOIN logons",
                ),
            ),
            "q_service_or_task_after_host_logon": (
                {"computer": "PC-01", "hours": 6},
                (
                    "event_id = 4697",
                    "event_id = 7045",
                    "event_id = 4698",
                    "lower('PC-01')",
                    "6 hours",
                ),
            ),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                for template_id, (params, fragments) in cases.items():
                    with self.subTest(template_id=template_id):
                        sql = render_query_template(template_id, params)
                        self.assertEqual(sql, validate_select_sql_with_dryrun(sql, db))
                        for fragment in fragments:
                            self.assertIn(fragment, sql)

    def test_powershell_recipe_excludes_reused_event_ids_from_other_contexts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, event_id, channel, timestamp, computer,
                        target_user, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "logon",
                        4624,
                        "Security",
                        "2015-03-22 14:00:00",
                        "PC-01",
                        "alice",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                    ),
                )
                candidates = (
                    (
                        4104,
                        "Application",
                        "Microsoft-Windows-Winlogon",
                        "wrong-channel",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-Winlogon",
                        "wrong-provider",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-PowerShell",
                        "powershell-event",
                    ),
                    (
                        4688,
                        "Security",
                        "Microsoft-Windows-Security-Auditing",
                        "process-event",
                    ),
                )
                for event_id, channel, provider, evidence_id in candidates:
                    db.execute(
                        """
                        INSERT INTO evtx_events (
                            evidence_id, event_id, channel, timestamp, computer,
                            process_name, raw_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            evidence_id,
                            event_id,
                            channel,
                            "2015-03-22 14:05:00",
                            "PC-01",
                            evidence_id,
                            f'{{"winlog":{{"provider":{{"name":"{provider}"}}}}}}',
                        ),
                    )

                sql = render_query_template(
                    "q_powershell_after_logon", {"user": "alice", "hours": 24}
                )
                rows = db.execute(sql).fetchall()

            self.assertEqual(
                {"powershell-event", "process-event"}, {row[4] for row in rows}
            )

    def test_required_params_and_unknown_ids_are_rejected(self) -> None:
        cases = (
            ("q_failed_logon_by_ip_window", {"hours": 24}),
            ("q_logon_by_user_window", {"user": "", "hours": 24}),
            ("q_powershell_after_logon", {"user": "alice"}),
            ("q_service_or_task_after_host_logon", {"computer": "PC-01"}),
            ("unknown", {}),
        )
        for template_id, params in cases:
            with self.subTest(template_id=template_id), self.assertRaises(ValueError):
                render_query_template(template_id, params)

    def test_text_params_are_sql_escaped(self) -> None:
        cases = (
            ("q_logon_by_user_window", {"user": "bob's", "hours": 24}),
            (
                "q_service_or_task_after_host_logon",
                {"computer": "dev's", "hours": 24},
            ),
        )
        for template_id, params in cases:
            with self.subTest(template_id=template_id):
                self.assertIn("''", render_query_template(template_id, params))


class HostValidationTests(unittest.TestCase):
    def test_host_limits_and_bounded_catalog(self) -> None:
        with self.assertRaises(ValueError):
            validate_select_sql("SELECT * FROM evtx_events LIMIT 100000")
        sql = "SELECT event_id FROM evtx_events LIMIT 50"
        self.assertEqual(sql, validate_select_sql(sql))
        for query in (
            "SELECT 1 UNION ALL SELECT 2",
            "WITH q AS (SELECT 1 LIMIT 1) SELECT * FROM q UNION ALL SELECT 2",
        ):
            self.assertEqual(query, validate_select_sql(query))
        for query in (
            "SELECT 1 LIMIT 1001 UNION ALL SELECT 2",
            "WITH q AS (SELECT 1 LIMIT 1001) SELECT * FROM q",
        ):
            with self.assertRaisesRegex(ValueError, "exceeds the host maximum"):
                validate_select_sql(query)
        catalog = query_template_catalog()
        self.assertGreaterEqual(len(catalog), 3)
        self.assertLessEqual(len(catalog), 7)
        for entry in catalog:
            self.assertIn("template_id", entry)
            self.assertIn("description", entry)

    def test_cte_names_cannot_authorize_schema_qualified_tables(self) -> None:
        queries = (
            "WITH trace AS (SELECT 1 AS x) "
            "SELECT * FROM trace.investigation_steps LIMIT 1",
            'WITH "trace" AS (SELECT 1 AS x) '
            'SELECT * FROM "trace"."investigation_steps" LIMIT 1',
            "SELECT * FROM main.evtx_events LIMIT 1",
            "SELECT * FROM memory.main.evtx_events LIMIT 1",
        )
        for query in queries:
            with (
                self.subTest(query=query),
                self.assertRaisesRegex(ValueError, "Schema-qualified table references"),
            ):
                validate_select_sql(query)
        unrelated_cte = (
            "WITH safe AS (SELECT 1 AS x), outer_q AS ("
            "SELECT * FROM hypothesis_reasoning WHERE EXISTS ("
            "WITH hypothesis_reasoning AS (SELECT 1) SELECT 1)) "
            "SELECT * FROM safe LIMIT 1"
        )
        with self.assertRaisesRegex(ValueError, "Unknown table"):
            validate_select_sql(unrelated_cte)

    def test_allowlist_parser_keeps_ctes_and_rejects_table_functions(self) -> None:
        sql = (
            "WITH matched AS (SELECT evidence_id FROM evtx_events) "
            "SELECT evidence_id FROM matched LIMIT 10"
        )
        self.assertEqual(sql, validate_select_sql(sql))
        with self.assertRaisesRegex(ValueError, "Table functions are not allowed"):
            validate_select_sql("SELECT * FROM read_csv('evidence.csv') LIMIT 1")
        with self.assertRaisesRegex(ValueError, "SQL could not be parsed"):
            validate_select_sql("SELECT * FROM")

    def test_trace_allowlist_rejection_also_holds_during_case_dry_run(self) -> None:
        query = (
            "WITH trace AS (SELECT 1 AS x) "
            "SELECT * FROM trace.investigation_steps LIMIT 1"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                with self.assertRaisesRegex(
                    ValueError, "Schema-qualified table references"
                ):
                    validate_select_sql(query)
                valid = validate_select_sql(
                    "WITH matched AS (SELECT evidence_id FROM evtx_events) "
                    "SELECT evidence_id FROM matched LIMIT 10"
                )
                self.assertEqual(valid, validate_select_sql_with_dryrun(valid, db))
