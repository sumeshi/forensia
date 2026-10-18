from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from forensia.knowledge.sigma.converter import compile_sigma_targets
from forensia.knowledge.sigma.validation import _sql_viability, validate_rule


class SigmaValidationBoundaryTests(unittest.TestCase):
    def _rule(self) -> dict:
        return {
            "title": "Validation boundary",
            "id": "66ee4c5f-81ae-43e5-9e19-9fc0e5a0e1cf",
            "logsource": {"product": "windows", "service": "security"},
            "detection": {"selection": {"EventID": 1102}, "condition": "selection"},
        }

    def _target(self, rawdata: dict):
        return next(
            target
            for target in compile_sigma_targets(rawdata)
            if target.status == "converted"
        )

    def test_every_generated_query_is_explained_and_executed_on_established_schema(
        self,
    ) -> None:
        rawdata = {
            **self._rule(),
            "detection": {"selection": {"EventID": 4624}, "condition": "selection"},
        }
        target = self._target(rawdata)
        result = _sql_viability(target.rule)
        self.assertEqual("passed", result["status"])
        self.assertEqual(
            "schema_only; shared semantic contract carries behavior checks",
            result["execution_scope"],
        )
        self.assertEqual(0, result["input_rows"])
        self.assertEqual(0, result["result_rows"])

    def test_fixtureless_rule_reports_absent_separately_from_sql_validation(
        self,
    ) -> None:
        rawdata = self._rule()
        target = self._target(rawdata)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "rule.yml"
            path.write_text("title: fixtureless\n", encoding="utf-8")
            result = validate_rule(
                root, path, rawdata, target.rule, binding=target.target_binding
            )

        self.assertEqual("passed", result["sql_validation"]["status"])
        self.assertEqual("absent", result["fixture"]["status"])
        self.assertEqual([], result["fixture"]["fixtures"])
        self.assertNotIn("status", result)

    def test_missing_declared_fixture_is_error_without_overwriting_sql_result(
        self,
    ) -> None:
        rawdata = {**self._rule(), "regression_tests_path": "regression/info.yml"}
        target = self._target(self._rule())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "rule.yml"
            path.write_text("title: fixtureful\n", encoding="utf-8")
            result = validate_rule(
                root, path, rawdata, target.rule, binding=target.target_binding
            )

        self.assertEqual("passed", result["sql_validation"]["status"])
        self.assertEqual("error", result["fixture"]["status"])
        self.assertEqual(
            "declared_fixture_missing_or_unsafe", result["fixture"]["reason_code"]
        )

    def test_fixture_count_and_evidence_refs_control_pass(self) -> None:
        rawdata = {**self._rule(), "regression_tests_path": "regression/info.yml"}
        event = {
            "@timestamp": "2026-01-01T00:00:00Z",
            "winlog": {
                "channel": "Security",
                "event_id": 1102,
                "record_id": 7,
                "computer_name": "validation-host",
                "provider": {"name": "Microsoft-Windows-Eventlog"},
                "event_data": {},
            },
        }

        def fake_ingest(case, evtx_path, source_sha, progress_callback=None):
            output = case.raw_dir / f"evtx-{source_sha}-records.jsonl"
            output.write_text(json.dumps(event) + "\n", encoding="utf-8")
            return output

        target = self._target(rawdata)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rule_path = root / "rules/windows/rule.yml"
            rule_path.parent.mkdir(parents=True)
            rule_path.write_text(yaml.safe_dump(rawdata), encoding="utf-8")
            (root / "regression").mkdir()
            fixture = root / "regression/events.evtx"
            fixture.write_bytes(b"parser output is mocked for this boundary test")
            info_path = root / "regression/info.yml"
            with patch(
                "forensia.knowledge.sigma.validation.ingest_evtx_file", fake_ingest
            ):
                results = {}
                for expected_count in (1, 0):
                    info_path.write_text(
                        yaml.safe_dump(
                            {
                                "rule_metadata": [{"id": rawdata["id"]}],
                                "regression_tests_info": [
                                    {
                                        "type": "evtx",
                                        "provider": "Microsoft-Windows-Eventlog",
                                        "match_count": expected_count,
                                        "path": "regression/events.evtx",
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                    results[expected_count] = validate_rule(
                        root,
                        rule_path,
                        rawdata,
                        target.rule,
                        binding=target.target_binding,
                    )

            passed = results[1]
            fixture_result = passed["fixture"]
            self.assertEqual("passed", fixture_result["status"], fixture_result)
            self.assertEqual(1, fixture_result["fixtures"][0]["expected_count"])
            self.assertEqual(1, fixture_result["fixtures"][0]["actual_count"])
            self.assertEqual(1, len(fixture_result["fixtures"][0]["evidence_refs"]))

            mismatch = results[0]["fixture"]
            self.assertEqual("mismatch", mismatch["status"])
            self.assertEqual(0, mismatch["fixtures"][0]["expected_count"])
            self.assertEqual(1, mismatch["fixtures"][0]["actual_count"])

    def test_channel_mismatch_is_not_applicable_not_conversion_failure(self) -> None:
        rawdata = {**self._rule(), "regression_tests_path": "regression/info.yml"}
        event = {
            "@timestamp": "2026-01-01T00:00:00Z",
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1102,
                "record_id": 7,
                "computer_name": "validation-host",
                "provider": {"name": "Microsoft-Windows-Eventlog"},
                "event_data": {},
            },
        }

        def fake_ingest(case, evtx_path, source_sha, progress_callback=None):
            output = case.raw_dir / f"evtx-{source_sha}-records.jsonl"
            output.write_text(json.dumps(event) + "\n", encoding="utf-8")
            return output

        target = self._target(rawdata)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rule_path = root / "rules/windows/rule.yml"
            rule_path.parent.mkdir(parents=True)
            rule_path.write_text(yaml.safe_dump(rawdata), encoding="utf-8")
            (root / "regression").mkdir()
            fixture = root / "regression/events.evtx"
            fixture.write_bytes(b"parser output is mocked for this boundary test")
            (root / "regression/info.yml").write_text(
                yaml.safe_dump(
                    {
                        "rule_metadata": [{"id": rawdata["id"]}],
                        "regression_tests_info": [
                            {
                                "type": "evtx",
                                "provider": "Microsoft-Windows-Eventlog",
                                "match_count": 0,
                                "path": "regression/events.evtx",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "forensia.knowledge.sigma.validation.ingest_evtx_file", fake_ingest
            ):
                result = validate_rule(
                    root,
                    rule_path,
                    rawdata,
                    target.rule,
                    binding=target.target_binding,
                )

            self.assertEqual("passed", result["sql_validation"]["status"])
            self.assertEqual("not_applicable", result["fixture"]["status"])
            self.assertEqual(
                "fixture_channel_mismatch",
                result["fixture"]["fixtures"][0]["reason_code"],
            )

    def test_missing_unrelated_provider_fixture_is_not_applicable(self) -> None:
        rawdata = {**self._rule(), "regression_tests_path": "regression/info.yml"}
        target = self._target(rawdata)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rule_path = root / "rules/windows/rule.yml"
            rule_path.parent.mkdir(parents=True)
            rule_path.write_text(yaml.safe_dump(rawdata), encoding="utf-8")
            info_path = root / "regression/info.yml"
            info_path.parent.mkdir(parents=True)
            info_path.write_text(
                yaml.safe_dump(
                    {
                        "rule_metadata": [{"id": rawdata["id"]}],
                        "regression_tests_info": [
                            {
                                "type": "evtx",
                                "provider": "Microsoft-Windows-Sysmon",
                                "match_count": 1,
                                "path": "regression/missing.evtx",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = validate_rule(
                root, rule_path, rawdata, target.rule, binding=target.target_binding
            )

        self.assertEqual("not_applicable", result["fixture"]["status"])
        self.assertEqual(
            "fixture_provider_mismatch", result["fixture"]["fixtures"][0]["reason_code"]
        )


if __name__ == "__main__":
    unittest.main()
