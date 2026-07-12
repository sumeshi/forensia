from __future__ import annotations

import unittest

from forensia.ai.prompts.sql_schema import (
    build_investigation_framework,
    load_app_catalog,
    load_fp_reduction_guidance,
    load_logon_type_schema,
)


class SqlSchemaYamlLoadingTests(unittest.TestCase):
    def setUp(self):
        load_logon_type_schema.cache_clear()
        load_app_catalog.cache_clear()
        load_fp_reduction_guidance.cache_clear()

    def test_load_logon_type_schema_returns_known_types(self):
        schema = load_logon_type_schema()
        self.assertIn("types", schema)
        types = schema["types"]
        for key in ("2", "3", "5", "10"):
            self.assertIn(key, types)
            self.assertIn("name", types[key])
            self.assertIn("description", types[key])
        self.assertEqual(types["2"]["name"], "Interactive")
        self.assertEqual(types["10"]["name"], "RemoteInteractive")

    def test_load_logon_type_schema_priority_events(self):
        schema = load_logon_type_schema()
        self.assertIn("priority_events", schema)
        self.assertGreaterEqual(len(schema["priority_events"]), 6)

    def test_load_app_catalog_returns_mappings_and_benign(self):
        cat = load_app_catalog()
        self.assertIn("mappings", cat)
        self.assertIn("benign_known", cat)
        self.assertIn("SCHTASKS.EXE", cat["mappings"])
        self.assertEqual(
            cat["mappings"]["SCHTASKS.EXE"]["category"], "persistence_tool"
        )

    def test_load_app_catalog_common_patterns(self):
        cat = load_app_catalog()
        self.assertIn("common_patterns", cat)
        self.assertIn("windows_update", cat["common_patterns"])
        self.assertIn("cloud_sync", cat["common_patterns"])

    def test_load_fp_reduction_guidance_returns_non_empty(self):
        guidance = load_fp_reduction_guidance()
        self.assertIsInstance(guidance, str)
        self.assertTrue(guidance.startswith("False-positive reduction"))
        self.assertIn("NORMAL", guidance)
        self.assertIn("risk amplifiers", guidance)
        self.assertIn("Lower confidence", guidance)

    def test_load_fp_reduction_guidance_contains_yaml_content(self):
        guidance = load_fp_reduction_guidance()
        self.assertIn("LogonType=3", guidance)
        self.assertIn("LogonType=5", guidance)
        self.assertIn("ADMIN$", guidance)

    def test_build_investigation_framework_returns_non_empty_string(self):
        framework = build_investigation_framework()
        self.assertIsInstance(framework, str)
        self.assertGreater(len(framework), 100)

    def test_build_investigation_framework_contains_key_sections(self):
        framework = build_investigation_framework()
        self.assertIn("Investigation framework", framework)
        self.assertIn("LogonType reference", framework)
        self.assertIn("Priority SQL guidance", framework)
        self.assertIn("Application categorization guidance", framework)
        self.assertIn("Available tables:", framework)
        self.assertIn("Only propose SELECT or WITH-prefixed read-only SQL", framework)

    def test_build_investigation_framework_contains_specific_tables(self):
        framework = build_investigation_framework()
        self.assertIn("evtx_events", framework)
        self.assertIn("mft_entries", framework)
        self.assertIn("prefetch_executions", framework)

    def test_build_investigation_framework_contains_logon_types(self):
        framework = build_investigation_framework()
        self.assertIn("Interactive", framework)
        self.assertIn("Network", framework)
        self.assertIn("RemoteInteractive", framework)
        self.assertIn("= Interactive", framework)
        self.assertIn("= RemoteInteractive", framework)

    def test_repeated_calls_return_consistent_results(self):
        schema_a = load_logon_type_schema()
        schema_b = load_logon_type_schema()
        self.assertIs(schema_a, schema_b)

        cat_a = load_app_catalog()
        cat_b = load_app_catalog()
        self.assertIs(cat_a, cat_b)

        fp_a = load_fp_reduction_guidance()
        fp_b = load_fp_reduction_guidance()
        self.assertIs(fp_a, fp_b)

        fw_a = build_investigation_framework()
        fw_b = build_investigation_framework()
        self.assertEqual(fw_a, fw_b)
