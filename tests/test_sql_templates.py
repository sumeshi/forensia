"""Public-contract tests for the reusable investigation SQL templates."""

from __future__ import annotations

import tempfile
import unittest

import duckdb

from forensia.ai.prompts.sql_templates import (
    query_template_catalog,
    render_query_template,
    validate_select_sql_with_dryrun,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


class DryRunValidationTests(unittest.TestCase):
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
                ("event_id IN (4688, 4104)", "15 minutes", "JOIN logons"),
            ),
            "q_service_or_task_after_host_logon": (
                {"computer": "PC-01", "hours": 6},
                ("event_id IN (4697, 7045, 4698)", "lower('PC-01')", "6 hours"),
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
