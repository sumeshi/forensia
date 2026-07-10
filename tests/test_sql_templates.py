from __future__ import annotations

import unittest

import duckdb

from forensia.ai.prompts.sql_templates import (
    _template_failed_logon_by_ip_window,
    _template_logon_by_user_window,
    _template_powershell_after_logon,
    _template_service_or_task_after_host_logon,
    coerce_list,
    query_template_catalog,
    validate_select_sql_with_dryrun,
)


class DryRunValidationTests(unittest.TestCase):
    def test_raises_on_nonexistent_function(self):
        conn = duckdb.connect(":memory:")
        try:
            with self.assertRaises(ValueError):
                validate_select_sql_with_dryrun("SELECT nonexistent_func(1)", conn)
        finally:
            conn.close()

    def test_passes_on_valid_sql(self):
        conn = duckdb.connect(":memory:")
        try:
            conn.execute("CREATE TABLE t (x INTEGER)")
            result = validate_select_sql_with_dryrun("SELECT x FROM t", conn)
            self.assertEqual("SELECT x FROM t", result)
        finally:
            conn.close()


class CoerceListTests(unittest.TestCase):
    def test_passthrough_list(self):
        self.assertEqual(coerce_list([1, 2, 3]), [1, 2, 3])

    def test_wraps_dict(self):
        self.assertEqual(coerce_list({"a": 1}), [{"a": 1}])

    def test_nonempty_string(self):
        self.assertEqual(coerce_list("hello"), ["hello"])

    def test_empty_string(self):
        self.assertEqual(coerce_list(""), [])

    def test_none(self):
        self.assertEqual(coerce_list(None), [])

    def test_int(self):
        self.assertEqual(coerce_list(42), [])

    def test_float(self):
        self.assertEqual(coerce_list(3.14), [])

    def test_boolean(self):
        self.assertEqual(coerce_list(True), [])

    def test_empty_dict(self):
        self.assertEqual(coerce_list({}), [{}])

    def test_empty_list(self):
        self.assertEqual(coerce_list([]), [])


class QueryTemplateCatalogTests(unittest.TestCase):
    def test_returns_non_empty_list(self):
        catalog = query_template_catalog()
        self.assertIsInstance(catalog, list)
        self.assertGreater(len(catalog), 0)

    def test_all_entries_have_expected_keys(self):
        catalog = query_template_catalog()
        for entry in catalog:
            self.assertIn("template_id", entry)
            self.assertIn("description", entry)
            self.assertIn("required_params", entry)

    def test_known_template_ids_present(self):
        catalog = query_template_catalog()
        ids = {e["template_id"] for e in catalog}
        expected = {
            "q_failed_logon_by_ip_window",
            "q_logon_by_user_window",
            "q_powershell_after_logon",
            "q_service_or_task_after_host_logon",
        }
        self.assertEqual(ids, expected)

    def test_all_catalog_descriptions_are_strings(self):
        catalog = query_template_catalog()
        for entry in catalog:
            self.assertIsInstance(entry["description"], str)
            self.assertGreater(len(entry["description"]), 0)

    def test_all_required_params_are_lists_of_strings(self):
        catalog = query_template_catalog()
        for entry in catalog:
            self.assertIsInstance(entry["required_params"], list)
            for p in entry["required_params"]:
                self.assertIsInstance(p, str)


class FailedLogonByIpWindowTests(unittest.TestCase):
    def test_default_params(self):
        sql = _template_failed_logon_by_ip_window({})
        self.assertIn("evtx_events", sql)
        self.assertIn("event_id = 4625", sql)
        self.assertIn("24 hours", sql)
        self.assertIn("src_ip", sql)
        self.assertIn("failed_count", sql)
        self.assertIn("HAVING COUNT(*) >= 5", sql)

    def test_custom_params(self):
        sql = _template_failed_logon_by_ip_window(
            {"event_id": 4630, "hours": 12, "threshold": 10}
        )
        self.assertIn("event_id = 4630", sql)
        self.assertIn("12 hours", sql)
        self.assertIn("HAVING COUNT(*) >= 10", sql)

    def test_hours_floor_is_one(self):
        sql = _template_failed_logon_by_ip_window({"hours": 0, "threshold": 1})
        self.assertIn("1 hours", sql)

    def test_threshold_floor_is_one(self):
        sql = _template_failed_logon_by_ip_window({"hours": 1, "threshold": 0})
        self.assertIn("HAVING COUNT(*) >= 1", sql)

    def test_empty_src_ip_filtered(self):
        sql = _template_failed_logon_by_ip_window({})
        self.assertIn("coalesce(src_ip, '') != ''", sql)

    def test_contains_from_evtx_events(self):
        sql = _template_failed_logon_by_ip_window({})
        self.assertIn("FROM evtx_events", sql)

    def test_contains_order_by_and_limit(self):
        sql = _template_failed_logon_by_ip_window({})
        self.assertIn("ORDER BY failed_count DESC", sql)
        self.assertIn("LIMIT 50", sql)

    def test_event_id_from_params(self):
        sql = _template_failed_logon_by_ip_window({"event_id": "4625"})
        self.assertIn("event_id = 4625", sql)

    def test_non_int_event_id_falls_back_to_default(self):
        sql = _template_failed_logon_by_ip_window({"event_id": "notanumber"})
        self.assertIn("event_id = 4625", sql)


class LogonByUserWindowTests(unittest.TestCase):
    def test_raises_on_missing_user(self):
        with self.assertRaises(ValueError):
            _template_logon_by_user_window({})

    def test_raises_on_empty_user(self):
        with self.assertRaises(ValueError):
            _template_logon_by_user_window({"user": ""})

    def test_basic_sql_structure(self):
        sql = _template_logon_by_user_window({"user": "alice"})
        self.assertIn("FROM evtx_events", sql)
        self.assertIn("target_user", sql)
        self.assertIn("src_ip", sql)
        self.assertIn("logon_type", sql)

    def test_event_id_default_4624(self):
        sql = _template_logon_by_user_window({"user": "alice"})
        self.assertIn("event_id = 4624", sql)

    def test_event_id_custom(self):
        sql = _template_logon_by_user_window({"user": "alice", "event_id": 4625})
        self.assertIn("event_id = 4625", sql)

    def test_user_lower_in_where_clause(self):
        sql = _template_logon_by_user_window({"user": "Admin"})
        self.assertIn("lower('Admin')", sql)

    def test_hours_in_sql(self):
        sql = _template_logon_by_user_window({"user": "alice", "hours": 48})
        self.assertIn("48 hours", sql)

    def test_hours_default_24(self):
        sql = _template_logon_by_user_window({"user": "alice"})
        self.assertIn("24 hours", sql)

    def test_sql_injection_escape(self):
        sql = _template_logon_by_user_window({"user": "bob's"})
        self.assertIn("lower('bob''s')", sql)

    def test_limit_and_order(self):
        sql = _template_logon_by_user_window({"user": "alice"})
        self.assertIn("ORDER BY timestamp DESC", sql)
        self.assertIn("LIMIT 100", sql)


class PowershellAfterLogonTests(unittest.TestCase):
    def test_raises_on_missing_user(self):
        with self.assertRaises(ValueError):
            _template_powershell_after_logon({})

    def test_raises_on_empty_user(self):
        with self.assertRaises(ValueError):
            _template_powershell_after_logon({"user": ""})

    def test_contains_cte(self):
        sql = _template_powershell_after_logon({"user": "alice"})
        self.assertIn("WITH logons AS", sql)
        self.assertIn("ps AS", sql)

    def test_logon_cte_structure(self):
        sql = _template_powershell_after_logon({"user": "alice"})
        self.assertIn("FROM evtx_events", sql)
        self.assertIn("event_id = 4624", sql)
        self.assertIn("target_user", sql)

    def test_powershell_cte_event_ids(self):
        sql = _template_powershell_after_logon({"user": "alice"})
        self.assertIn("event_id IN (4688, 4104)", sql)

    def test_join_on_computer_and_timestamp_window(self):
        sql = _template_powershell_after_logon({"user": "alice"})
        self.assertIn("ON ps.computer = logons.computer", sql)
        self.assertIn("15 minutes", sql)

    def test_user_lower_in_logon_cte(self):
        sql = _template_powershell_after_logon({"user": "Admin"})
        self.assertIn("lower('Admin')", sql)

    def test_hours_default_24(self):
        sql = _template_powershell_after_logon({"user": "alice"})
        self.assertIn("24 hours", sql)

    def test_limit_and_order(self):
        sql = _template_powershell_after_logon({"user": "alice"})
        self.assertIn("ORDER BY ps.timestamp DESC", sql)
        self.assertIn("LIMIT 100", sql)

    def test_sql_injection_escape(self):
        sql = _template_powershell_after_logon({"user": "d'Angelo"})
        self.assertIn("lower('d''Angelo')", sql)


class ServiceOrTaskAfterHostLogonTests(unittest.TestCase):
    def test_raises_on_missing_computer(self):
        with self.assertRaises(ValueError):
            _template_service_or_task_after_host_logon({})

    def test_raises_on_empty_computer(self):
        with self.assertRaises(ValueError):
            _template_service_or_task_after_host_logon({"computer": ""})

    def test_contains_evtx_events(self):
        sql = _template_service_or_task_after_host_logon({"computer": "PC-01"})
        self.assertIn("FROM evtx_events", sql)
        self.assertIn("evtx_events", sql)

    def test_event_ids_known(self):
        sql = _template_service_or_task_after_host_logon({"computer": "PC-01"})
        self.assertIn("event_id IN (4697, 7045, 4698)", sql)

    def test_computer_lower_in_where(self):
        sql = _template_service_or_task_after_host_logon({"computer": "WORKSTATION"})
        self.assertIn("lower('WORKSTATION')", sql)

    def test_hours_default_24(self):
        sql = _template_service_or_task_after_host_logon({"computer": "PC-01"})
        self.assertIn("24 hours", sql)

    def test_custom_hours(self):
        sql = _template_service_or_task_after_host_logon(
            {"computer": "PC-01", "hours": 6}
        )
        self.assertIn("6 hours", sql)

    def test_columns_present(self):
        sql = _template_service_or_task_after_host_logon({"computer": "PC-01"})
        self.assertIn("timestamp", sql)
        self.assertIn("event_id", sql)
        self.assertIn("service_name", sql)
        self.assertIn("process_name", sql)
        self.assertIn("command_line", sql)
        self.assertIn("evidence_id", sql)

    def test_order_by_timestamp_desc(self):
        sql = _template_service_or_task_after_host_logon({"computer": "PC-01"})
        self.assertIn("ORDER BY timestamp DESC", sql)

    def test_sql_injection_escape(self):
        sql = _template_service_or_task_after_host_logon({"computer": "dev's"})
        self.assertIn("lower('dev''s')", sql)
