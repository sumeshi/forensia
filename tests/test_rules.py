from __future__ import annotations

import copy
import json
import math
import tempfile
import unittest
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.evtx import normalize_evtx
from forensia.knowledge.rules.engine import (
    generate_findings,
    iter_rule_row_batches,
    save_findings,
)
from forensia.knowledge.rules.loader import load_rules
from forensia.knowledge.rules.models import Finding, Rule

SHA = "a" * 64


class RuleDeclarationTests(unittest.TestCase):
    def test_analysis_revision_tracks_runtime_analysis_inputs(self) -> None:
        from unittest.mock import patch

        from forensia.pipeline import _analysis_revision

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            case = Case.init(root / "case")
            rules = root / "rules"
            rules.mkdir()
            schema = root / "schema"
            schema.mkdir(parents=True)
            package_root = root / "package"
            rules_code = package_root / "knowledge" / "rules"
            rules_code.mkdir(parents=True)
            catalog_code = package_root / "knowledge" / "catalog.py"
            sigma_contract = package_root / "knowledge" / "sigma_bundle.py"
            pipeline_code = package_root / "pipeline.py"
            catalog_code.parent.mkdir(parents=True, exist_ok=True)
            catalog_code.write_text("# catalog one\n", encoding="utf-8")
            sigma_contract.write_text("# sigma contract one\n", encoding="utf-8")
            pipeline_code.write_text("# pipeline one\n", encoding="utf-8")
            (rules_code / "engine.py").write_text("# engine one\n", encoding="utf-8")
            sql_rule = rules / "rule.yaml"
            sql_rule.write_text("id: rule-one\n", encoding="utf-8")
            false_positive = schema / "false_positive_rules.yaml"
            dfir_ioc = schema / "dfir_ioc_catalog.yaml"
            sigma_schema = schema / "sigma.yaml"
            bundle = root / "sigma_bundle.json"
            false_positive.write_text("version: one\n", encoding="utf-8")
            dfir_ioc.write_text("version: one\n", encoding="utf-8")
            sigma_schema.write_text("version: one\n", encoding="utf-8")
            bundle.write_text("{}\n", encoding="utf-8")

            with (
                patch("forensia.pipeline.rules_dir", return_value=rules),
                patch("forensia.pipeline.schema_dir", return_value=schema),
                patch("forensia.pipeline.sigma_bundle_path", return_value=bundle),
                patch("forensia.pipeline.__file__", str(pipeline_code)),
            ):
                original = _analysis_revision(case)
                false_positive.write_text("version: two\n", encoding="utf-8")
                self.assertNotEqual(original, _analysis_revision(case))

                false_positive.write_text("version: one\n", encoding="utf-8")
                dfir_ioc.write_text("version: two\n", encoding="utf-8")
                self.assertNotEqual(original, _analysis_revision(case))

                dfir_ioc.write_text("version: one\n", encoding="utf-8")
                bundle.write_text('{"version": 2}\n', encoding="utf-8")
                self.assertNotEqual(original, _analysis_revision(case))

                bundle.write_text("{}\n", encoding="utf-8")
                sql_rule.write_text("id: rule-two\n", encoding="utf-8")
                self.assertNotEqual(original, _analysis_revision(case))

                sql_rule.write_text("id: rule-one\n", encoding="utf-8")
                sigma_contract.write_text("# sigma contract two\n", encoding="utf-8")
                self.assertNotEqual(original, _analysis_revision(case))

                sigma_contract.write_text("# sigma contract one\n", encoding="utf-8")
                pipeline_code.write_text("# pipeline two\n", encoding="utf-8")
                self.assertNotEqual(original, _analysis_revision(case))

                pipeline_code.write_text("# pipeline one\n", encoding="utf-8")
                sigma_schema.write_text("version: two\n", encoding="utf-8")
                self.assertEqual(original, _analysis_revision(case))

    def test_catalog_and_sigma_rule_ids_are_unique(self) -> None:
        rules = load_rules()
        ids = {rule.id for rule in rules}
        self.assertEqual(len(rules), len(ids))
        self.assertTrue(
            {
                "prefetch-finding-antiforensic-tools",
                "prefetch-finding-data-staging",
                "filesystem-mft-cloud-sync-db-deleted",
                "registry-autorun-run-key-reference",
            }.issubset(ids)
        )

    def test_invalid_sigma_bundle_fails_before_case_creation(self) -> None:
        from unittest.mock import patch

        from forensia.pipeline import run_investigation

        with tempfile.TemporaryDirectory() as tmpdir:
            case_path = Path(tmpdir) / "case"
            broken_bundle = Path(tmpdir) / "sigma_bundle.json"
            broken_bundle.write_text("{}", encoding="utf-8")
            with patch(
                "forensia.knowledge.resources.sigma_bundle_path",
                return_value=broken_bundle,
            ):
                with self.assertRaisesRegex(ValueError, "schema"):
                    run_investigation(case_path)
            self.assertFalse(case_path.exists())

    def test_analysis_replaces_existing_rule_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO prefetch_executions (
                        evidence_id, source_file, executable_name, exec_count, last_exec_time
                    ) VALUES ('prefetch-cleaner-1', 'ERASER.EXE-12345678.pf',
                              'ERASER.EXE', 1, '2024-01-01 00:00:00')
                    """
                )
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence,
                        status, tags, evidence
                    ) VALUES (
                        'prefetch-finding-antiforensic-tools-0001',
                        'prefetch-finding-antiforensic-tools', 'old', '', 'high',
                        0.7, 'accepted', '[]', '[{"source_file":"old.pf"}]'
                    )
                    """
                )
                from forensia.pipeline import _run_analyze_stage

                _run_analyze_stage(
                    case, db, True, True, lambda *a, **kw: None, None, "test-run"
                )
                row = db.execute(
                    "SELECT evidence FROM findings WHERE finding_id = ?",
                    ("prefetch-finding-antiforensic-tools-0001",),
                ).fetchone()

        self.assertIsNotNone(row)
        self.assertIn("ERASER.EXE-12345678.pf", row[0])
        self.assertNotIn("old.pf", row[0])


class AllowlistTests(unittest.TestCase):
    def test_manual_allowlist_marks_matching_finding_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            case.allowlist_path.write_text(
                "rules:\n  - rule_id: test-rule\n    when:\n      target_user: [ANONYMOUS LOGON]\n",
                encoding="utf-8",
            )
            finding = Finding(
                finding_id="test-rule-0001",
                rule_id="test-rule",
                title="test",
                summary="test",
                severity="medium",
                confidence=0.5,
                evidence=[{"target_user": "ANONYMOUS LOGON"}],
            )
            with CaseDB(case) as db:
                save_findings(case, db, [finding])
                status = db.execute(
                    "SELECT status FROM findings WHERE finding_id = ?",
                    (finding.finding_id,),
                ).fetchone()[0]
        self.assertEqual("suppressed", status)


class SigmaRuleBoundaryTests(unittest.TestCase):
    def test_native_evtx_jsonl_runs_admitted_sigma_rules_with_source_evidence(
        self,
    ) -> None:
        events = [
            {
                "@timestamp": "2026-05-16T01:00:00Z",
                "winlog": {
                    "channel": "Security",
                    "event_id": 1102,
                    "record_id": 1,
                    "computer_name": "host1",
                },
            },
            {
                "@timestamp": "2026-05-16T01:01:00Z",
                "winlog": {
                    "channel": "Microsoft-Windows-Windows Defender/Operational",
                    "event_id": 5001,
                    "record_id": 2,
                    "computer_name": "host1",
                },
            },
            {
                "@timestamp": "2026-05-16T01:02:00Z",
                "winlog": {
                    "channel": "Security",
                    "event_id": 4688,
                    "record_id": 3,
                    "computer_name": "host1",
                    "event_data": {
                        "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "CommandLine": "powershell.exe -enc QUJD",
                    },
                },
            },
            {
                "@timestamp": "2026-05-16T01:03:00Z",
                "winlog": {
                    "channel": "Application",
                    "event_id": 1102,
                    "record_id": 4,
                    "computer_name": "host1",
                },
            },
            {
                "@timestamp": "2026-05-16T01:04:00Z",
                "winlog": {
                    "channel": "Security",
                    "event_id": 4688,
                    "record_id": 5,
                    "computer_name": "host1",
                    "event_data": {
                        "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "CommandLine": "powershell.exe Get-Process",
                    },
                },
            },
        ]
        providers = {
            "Security": "Microsoft-Windows-Security-Auditing",
            "Microsoft-Windows-Windows Defender/Operational": "Microsoft-Windows-Windows Defender",
            "Application": "Application",
            # A known channel/provider pair mismatch must not count as observed.
            "PowerShellCore/Operational": "Microsoft-Windows-PowerShell",
        }
        events.append(
            {
                "@timestamp": "2026-05-16T01:05:00Z",
                "winlog": {
                    "channel": "PowerShellCore/Operational",
                    "event_id": 4104,
                    "record_id": 6,
                    "computer_name": "host1",
                    "event_data": {"ScriptBlockText": "Get-Process"},
                },
            }
        )
        for event in events:
            event["winlog"]["provider"] = {
                "name": providers[event["winlog"]["channel"]]
            }
            if (
                event["winlog"]["channel"] == "Security"
                and event["winlog"]["event_id"] == 1102
            ):
                event["winlog"]["provider"]["name"] = "Microsoft-Windows-Eventlog"
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            raw = case.raw_dir / f"evtx-{SHA}-records.jsonl"
            raw.write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )
            with CaseDB(case) as db:
                self.assertEqual(len(events), normalize_evtx(case, db))
                rows = db.execute(
                    "SELECT raw_json FROM evtx_events ORDER BY record_id"
                ).fetchall()
                self.assertEqual(events, [json.loads(row[0]) for row in rows])
                self.assertTrue(
                    all("evidence_id" not in json.loads(row[0]) for row in rows)
                )
                from unittest.mock import patch

                from forensia.knowledge.rules.engine import (
                    feed_findings_to_timeline as actual_timeline_feed,
                )
                from forensia.knowledge.rules.engine import (
                    prepare_finding_run as actual_prepare_context,
                )
                from forensia.pipeline import _run_analyze_stage

                progress_messages: list[str] = []

                def progress(*args, **kwargs):
                    if args and isinstance(args[0], str):
                        progress_messages.append(args[0])

                revision_rules = Path(tmpdir) / "analysis-rules"
                revision_rules.mkdir()
                revision_schema = Path(tmpdir) / "analysis-schema"
                revision_schema.mkdir(parents=True)
                false_positive_rules = revision_schema / "false_positive_rules.yaml"
                (revision_schema / "dfir_ioc_catalog.yaml").write_text(
                    "# revision one\n", encoding="utf-8"
                )
                false_positive_rules.write_text("# revision one\n", encoding="utf-8")
                with (
                    patch(
                        "forensia.pipeline.prepare_finding_run",
                        wraps=actual_prepare_context,
                    ) as prepare_context,
                    patch(
                        "forensia.pipeline.feed_findings_to_timeline",
                        wraps=actual_timeline_feed,
                    ) as timeline_feed,
                    patch(
                        "forensia.pipeline.rules_dir",
                        return_value=revision_rules,
                    ),
                    patch(
                        "forensia.pipeline.schema_dir",
                        return_value=revision_schema,
                    ),
                ):
                    finding_count = _run_analyze_stage(
                        case, db, True, True, progress, None, "test-run"
                    )
                    progress_messages.clear()
                    self.assertEqual(
                        finding_count,
                        _run_analyze_stage(
                            case, db, False, False, progress, None, "test-run"
                        ),
                    )
                    false_positive_rules.write_text(
                        "# revision two\n", encoding="utf-8"
                    )
                    changed_declaration_count = _run_analyze_stage(
                        case, db, False, False, progress, None, "test-run"
                    )
                    self.assertEqual(finding_count, changed_declaration_count)
                self.assertEqual(2, prepare_context.call_count)
                self.assertEqual(2, timeline_feed.call_count)
                self.assertGreater(finding_count, 0)
                receipt = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'pipeline-analyze' "
                        "ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()[0]
                )
                sigma_rules = [
                    rule for rule in receipt["rules"] if rule["format"] == "sigma"
                ]
                rule_progress = [
                    message
                    for message in progress_messages
                    if message.startswith("[analyze] rule:")
                ]
                self.assertLess(len(rule_progress), len(receipt["rules"]))
                expected_upstream_rule = (
                    "sigma-b28e58e4-2a72-4fae-bdee-0fbe904db642-windefend"
                )
                self.assertIn(
                    expected_upstream_rule, {rule["id"] for rule in sigma_rules}
                )
                self.assertTrue(
                    all(len(rule["definition_sha256"]) == 64 for rule in sigma_rules)
                )
                sigma_receipt = receipt["sigma_bundle"]
                self.assertEqual(40, len(sigma_receipt["source"]["commit"]))
                self.assertTrue(sigma_receipt["build_id"])
                self.assertEqual(64, len(sigma_receipt["artifact_sha256"]))
                self.assertGreater(sigma_receipt["summary"]["admitted_rules"], 0)
                self.assertTrue(
                    any(
                        rule["execution"]["status"] == "not_observed"
                        and rule["execution"]["matches"] is None
                        for rule in sigma_rules
                    )
                )
                self.assertTrue(
                    all(
                        rule["execution"]["status"] == "not_observed"
                        for rule in sigma_rules
                        if rule["target"]["service"] == "powershell"
                    )
                )
                self.assertEqual(
                    4,
                    db.execute(
                        "SELECT COUNT(*) FROM trace.investigation_steps WHERE phase = 'pipeline-analyze'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    finding_count,
                    db.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                )
                upstream_findings = db.execute(
                    "SELECT evidence FROM findings WHERE rule_id = ?",
                    (expected_upstream_rule,),
                ).fetchall()
                self.assertEqual(1, len(upstream_findings))
                self.assertIn("evtx-" + SHA, upstream_findings[0][0])
                references = [
                    json.loads(row[0])[0]["evidence_id"]
                    for row in db.execute("SELECT evidence FROM findings").fetchall()
                ]
                self.assertEqual(finding_count, len(references))
                self.assertTrue(references)
                self.assertTrue(
                    all(ref.startswith("evtx-" + SHA) for ref in references)
                )

                from forensia.knowledge.resources import sigma_bundle_path
                from forensia.knowledge.sigma_bundle import (
                    bundle_build_id,
                    bundle_summary,
                    write_bundle_atomic,
                )

                changed_bundle = json.loads(
                    sigma_bundle_path().read_text(encoding="utf-8")
                )
                for binding in changed_bundle["bindings"]:
                    if (
                        binding["rule"]
                        and binding["rule"]["id"] == expected_upstream_rule
                    ):
                        binding["conversion"] = {
                            "status": "unsupported",
                            "reason_code": "runtime_revision_test",
                            "reason": "Removed from the test bundle",
                        }
                        binding["validation"] = {}
                        binding["rule"] = None
                        break
                else:
                    self.fail(
                        f"Missing expected admitted rule {expected_upstream_rule}"
                    )
                changed_bundle["summary"] = bundle_summary(changed_bundle["bindings"])
                changed_bundle["build_id"] = bundle_build_id(changed_bundle)
                test_bundle_path = Path(tmpdir) / "sigma_bundle.json"
                write_bundle_atomic(test_bundle_path, changed_bundle)
                with (
                    patch(
                        "forensia.knowledge.resources.sigma_bundle_path",
                        return_value=test_bundle_path,
                    ),
                    patch(
                        "forensia.pipeline.sigma_bundle_path",
                        return_value=test_bundle_path,
                    ),
                ):
                    updated_count = _run_analyze_stage(
                        case, db, False, False, progress, None, "test-run"
                    )
                self.assertLess(updated_count, finding_count)
                self.assertEqual(
                    0,
                    db.execute(
                        "SELECT COUNT(*) FROM findings WHERE rule_id = ?",
                        (expected_upstream_rule,),
                    ).fetchone()[0],
                )

                import duckdb

                from forensia.knowledge.rules.engine import (
                    iter_rule_row_batches as actual_iter_rule_row_batches,
                )
                from forensia.knowledge.rules.loader import load_rules

                with (
                    patch(
                        "forensia.knowledge.resources.sigma_bundle_path",
                        return_value=test_bundle_path,
                    ),
                    patch(
                        "forensia.pipeline.sigma_bundle_path",
                        return_value=test_bundle_path,
                    ),
                ):
                    valid_rules = load_rules()
                    failed_rules = copy.deepcopy(valid_rules)
                    failed_sigma_rule = next(
                        rule
                        for rule in failed_rules
                        if rule.id
                        in {
                            item["id"]
                            for item in sigma_rules
                            if item["execution"]["status"] == "completed"
                        }
                    )
                    failed_sigma_rule.query = (
                        "SELECT * FROM missing_sigma_runtime_test_table"
                    )
                    completed_before_failure = db.execute(
                        "SELECT COUNT(*) FROM trace.investigation_steps "
                        "WHERE phase = 'pipeline-analyze' "
                        "AND json_extract_string(output_json, '$.status') = 'completed'"
                    ).fetchone()[0]
                    with (
                        patch(
                            "forensia.pipeline.load_rules", return_value=failed_rules
                        ),
                        self.assertRaises(duckdb.CatalogException),
                    ):
                        _run_analyze_stage(
                            case, db, False, True, progress, None, "test-run"
                        )
                    failed_receipt = json.loads(
                        db.execute(
                            "SELECT output_json FROM trace.investigation_steps "
                            "WHERE phase = 'pipeline-analyze' "
                            "ORDER BY created_at DESC LIMIT 1"
                        ).fetchone()[0]
                    )
                    self.assertEqual("failed", failed_receipt["status"])
                    self.assertEqual(
                        failed_sigma_rule.id, failed_receipt["failed_rule_id"]
                    )
                    self.assertEqual(
                        completed_before_failure,
                        db.execute(
                            "SELECT COUNT(*) FROM trace.investigation_steps "
                            "WHERE phase = 'pipeline-analyze' "
                            "AND json_extract_string(output_json, '$.status') = 'completed'"
                        ).fetchone()[0],
                    )
                    with patch(
                        "forensia.pipeline.iter_rule_row_batches",
                        wraps=actual_iter_rule_row_batches,
                    ) as resumed_queries:
                        resumed_count = _run_analyze_stage(
                            case, db, False, False, progress, None, "test-run"
                        )
                    self.assertEqual(updated_count, resumed_count)
                    completed_rules = db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'pipeline-analyze' ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()[0]
                    self.assertEqual(
                        sum(
                            item["execution"]["status"] == "completed"
                            for item in json.loads(completed_rules)["rules"]
                        ),
                        resumed_queries.call_count,
                    )


class SigmaCompilerTests(unittest.TestCase):
    def _rule(self, detection: dict, *, logsource: dict | None = None) -> dict:
        return {
            "title": "shared Sigma boundary",
            "id": "6f0454e5-0918-4d03-ae3b-98c719b0f407",
            "logsource": logsource or {"product": "windows", "service": "security"},
            "detection": detection,
        }

    def _converted(self, data: dict, target_key: str = "security"):
        from scripts.sigma.converter import compile_sigma_targets

        outcomes = compile_sigma_targets(data)
        return next(
            result
            for result in outcomes
            if result.target_key == target_key and result.status == "converted"
        )

    def _insert(
        self,
        db: CaseDB,
        evidence_id: str,
        *,
        channel: str,
        provider: str,
        event_id: int,
        event_data: dict | None = None,
        logon_type: str | None = None,
        userdata: dict | None = None,
    ) -> None:
        event = {
            "winlog": {
                "channel": channel,
                "event_id": event_id,
                "provider": {"name": provider},
                "event_data": event_data or {},
            }
        }
        if userdata is not None:
            event["userdata"] = userdata
        db.execute(
            "INSERT INTO evtx_events "
            "(evidence_id, source_file, channel, event_id, logon_type, raw_json) "
            "VALUES (?, 'fixture', ?, ?, ?, ?)",
            (evidence_id, channel, event_id, logon_type, json.dumps(event)),
        )

    def test_category_targets_preserve_security_and_sysmon_meaning(self) -> None:
        from scripts.sigma.converter import compile_sigma_targets

        data = self._rule(
            {
                "selection": {
                    "OriginalFileName": "powershell.exe",
                    "Signed": "false",
                    "Hashes|contains": "SHA256=abc",
                },
                "condition": "selection",
            },
            logsource={"product": "windows", "category": "process_creation"},
        )
        results = {item.target_key: item for item in compile_sigma_targets(data)}
        self.assertEqual({"security", "sysmon"}, set(results))
        self.assertEqual("unsupported", results["security"].status)
        self.assertEqual("converted", results["sysmon"].status)
        sysmon = results["sysmon"]
        self.assertEqual(data["id"], sysmon.sigma_id)
        self.assertEqual(f"sigma-{data['id']}-sysmon", sysmon.rule.id)
        self.assertEqual(
            ["Microsoft-Windows-Sysmon/Operational"], sysmon.target_binding["channels"]
        )
        self.assertEqual(
            ["Microsoft-Windows-Sysmon"], sysmon.target_binding["providers"]
        )
        self.assertEqual([1], sysmon.target_binding["event_ids"])
        self.assertIn('$.winlog.event_data."Signed"', sysmon.rule.query)
        self.assertIn('$.winlog.event_data."Hashes"', sysmon.rule.query)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert(
                    db,
                    "sysmon-match",
                    channel="Microsoft-Windows-Sysmon/Operational",
                    provider="Microsoft-Windows-Sysmon",
                    event_id=1,
                    event_data={
                        "OriginalFileName": "powershell.exe",
                        "Signed": "false",
                        "Hashes": "SHA256=abc",
                    },
                )
                self._insert(
                    db,
                    "security-lookalike",
                    channel="Security",
                    provider="Microsoft-Windows-Security-Auditing",
                    event_id=4688,
                    event_data={
                        "OriginalFileName": "powershell.exe",
                        "Signed": "false",
                        "Hashes": "SHA256=abc",
                    },
                )
                self._insert(
                    db,
                    "wrong-provider",
                    channel="Microsoft-Windows-Sysmon/Operational",
                    provider="Other Provider",
                    event_id=1,
                    event_data={
                        "OriginalFileName": "powershell.exe",
                        "Signed": "false",
                        "Hashes": "SHA256=abc",
                    },
                )
                self.assertEqual(
                    ["sysmon-match"],
                    [row[0] for row in db.execute(sysmon.rule.query).fetchall()],
                )

    def test_fieldless_keyword_semantics_are_explicitly_unsupported(self) -> None:
        from scripts.sigma.converter import compile_sigma_targets

        results = compile_sigma_targets(
            self._rule(
                {"keywords": ["zerologon"], "condition": "keywords"},
                logsource={"product": "windows", "service": "system"},
            )
        )
        self.assertTrue(results)
        self.assertTrue(all(item.status == "unsupported" for item in results))
        self.assertTrue(all("fieldless" in item.reason.lower() for item in results))

    def test_security_provider_channel_and_typed_numeric_scope(self) -> None:
        data = self._rule(
            {
                "event": {"EventID": 4624},
                "selection": {"LogonType": 3},
                "condition": "event and selection",
            }
        )
        result = self._converted(data)
        self.assertIn("try_cast(logon_type AS BIGINT)", result.rule.query)
        self.assertIn("channel IN ('Security')", result.rule.query)
        self.assertIn("Microsoft-Windows-Security-Auditing", result.rule.query)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert(
                    db,
                    "match",
                    channel="Security",
                    provider="Microsoft-Windows-Security-Auditing",
                    event_id=4624,
                    event_data={"LogonType": "3"},
                    logon_type="3",
                )
                self._insert(
                    db,
                    "wrong-provider",
                    channel="Security",
                    provider="Other",
                    event_id=4624,
                    event_data={"LogonType": "3"},
                    logon_type="3",
                )
                self._insert(
                    db,
                    "wrong-channel",
                    channel="Application",
                    provider="Microsoft-Windows-Security-Auditing",
                    event_id=4624,
                    event_data={"LogonType": "3"},
                    logon_type="3",
                )
                self.assertEqual(
                    ["match"],
                    [row[0] for row in db.execute(result.rule.query).fetchall()],
                )

    def test_system_channel_keeps_multiple_providers_and_userdata_override(
        self,
    ) -> None:
        system = self._converted(
            self._rule(
                {"selection": {"EventID": [104, 7045]}, "condition": "selection"},
                logsource={"product": "windows", "service": "system"},
            ),
            target_key="system",
        )
        self.assertEqual(["System"], system.target_binding["channels"])
        self.assertEqual([], system.target_binding["providers"])
        self.assertEqual([104, 7045], system.target_binding["event_ids"])
        self.assertNotIn("winlog.provider.name", system.rule.query)

        terminal_services = self._converted(
            self._rule(
                {
                    "event": {"EventID": 21},
                    "selection": {"Address": "10.0.0.1"},
                    "condition": "event and selection",
                },
                logsource={
                    "product": "windows",
                    "service": "terminalservices-localsessionmanager",
                },
            ),
            target_key="terminalservices-localsessionmanager",
        )
        self.assertIn("$.userdata.EventXML.Address", terminal_services.rule.query)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert(
                    db,
                    "terminal-address",
                    channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                    provider="Microsoft-Windows-TerminalServices-LocalSessionManager",
                    event_id=21,
                    userdata={"EventXML": {"Address": "10.0.0.1"}},
                )
                self.assertEqual(
                    ["terminal-address"],
                    [
                        row[0]
                        for row in db.execute(terminal_services.rule.query).fetchall()
                    ],
                )

    def test_powershell_classic_data_text_array_mapping(self) -> None:
        logsource = {"product": "windows", "category": "ps_classic_script"}
        positive = self._converted(
            self._rule(
                {
                    "selection": {"Data|contains": "Bad*"},
                    "condition": "selection",
                },
                logsource=logsource,
            ),
            target_key="powershell-classic",
        )
        negative = self._converted(
            self._rule(
                {
                    "selection": {"Data|contains": "Bad*"},
                    "condition": "not selection",
                },
                logsource=logsource,
            ),
            target_key="powershell-classic",
        )
        self.assertEqual([800], positive.target_binding["event_ids"])
        self.assertIn('Data."#text"[*]', positive.rule.query)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for evidence_id, data in (
                    ("classic-match", {"#text": ["benign", "BadCommand"]}),
                    ("classic-other", {"#text": ["clean"]}),
                ):
                    self._insert(
                        db,
                        evidence_id,
                        channel="Windows PowerShell",
                        provider="PowerShell",
                        event_id=800,
                        event_data={"Data": data},
                    )
                self._insert(
                    db,
                    "classic-missing",
                    channel="Windows PowerShell",
                    provider="PowerShell",
                    event_id=800,
                )
                self.assertEqual(
                    ["classic-match"],
                    [row[0] for row in db.execute(positive.rule.query).fetchall()],
                )
                self.assertEqual(
                    ["classic-missing", "classic-other"],
                    [row[0] for row in db.execute(negative.rule.query).fetchall()],
                )

        powershell = self._converted(
            self._rule(
                {
                    "selection": {"ScriptBlockText|contains": "Invoke-WebRequest"},
                    "condition": "selection",
                },
                logsource={"product": "windows", "category": "ps_script"},
            ),
            target_key="powershell",
        )
        self.assertEqual(
            [
                "Microsoft-Windows-PowerShell/Operational",
                "PowerShellCore/Operational",
            ],
            powershell.target_binding["channels"],
        )
        self.assertEqual(
            [
                {
                    "channel": "Microsoft-Windows-PowerShell/Operational",
                    "provider": "Microsoft-Windows-PowerShell",
                },
                {"channel": "PowerShellCore/Operational", "provider": "PowerShellCore"},
            ],
            powershell.target_binding["provider_scopes"],
        )

    def test_newvalue_path_is_scoped_to_windefend(self) -> None:
        data = self._rule(
            {"selection": {"NewValue|contains": "Exclusion"}, "condition": "selection"},
            logsource={"product": "windows", "service": "windefend"},
        )
        defender = self._converted(data, target_key="windefend")
        self.assertIn('$.winlog.event_data."New Value"', defender.rule.query)

        security_data = self._rule(
            {"selection": {"NewValue|contains": "Exclusion"}, "condition": "selection"}
        )
        security = self._converted(security_data)
        self.assertIn('$.winlog.event_data."NewValue"', security.rule.query)
        self.assertNotIn('$.winlog.event_data."New Value"', security.rule.query)

    def test_wildcard_or_missing_not_and_numeric_event_comparison(self) -> None:
        wildcard = self._converted(
            self._rule(
                {
                    "event": {"EventID": 4624},
                    "ntlm": {"AuthenticationPackageName|contains": "NTLM*"},
                    "kerberos": {"AuthenticationPackageName|contains": "Kerberos?"},
                    "condition": "event and (ntlm or kerberos)",
                }
            )
        )
        negated = self._converted(
            self._rule(
                {
                    "event": {"EventID": 4624},
                    "selection": {"AuthenticationPackageName|contains": "NTLM*"},
                    "condition": "event and not selection",
                }
            )
        )
        numeric = self._converted(
            self._rule({"selection": {"EventID|gt": 1000}, "condition": "selection"})
        )
        windash = self._converted(
            self._rule(
                {
                    "selection": {"CommandLine|contains|windash": " -enc "},
                    "condition": "selection",
                },
                logsource={"product": "windows", "category": "process_creation"},
            ),
            target_key="sysmon",
        )
        self.assertIn("TRY_CAST(event_id AS BIGINT) > 1000", numeric.rule.query)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:

                def add(
                    evidence_id: str, event_id: int, package: str | list[str] | None
                ) -> None:
                    self._insert(
                        db,
                        evidence_id,
                        channel="Security",
                        provider=(
                            "Microsoft-Windows-Eventlog"
                            if event_id == 1102
                            else "Microsoft-Windows-Security-Auditing"
                        ),
                        event_id=event_id,
                        event_data={}
                        if package is None
                        else {"AuthenticationPackageName": package},
                    )

                add("ntlm", 4624, "NTLM V2")
                add("kerberos", 4624, "Kerberos5")
                add("array", 4624, ["Other", "NTLM V2"])
                add("missing", 4624, None)
                add("event-above", 1102, None)
                add("event-below", 999, None)
                self.assertEqual(
                    {"ntlm", "kerberos", "array"},
                    {row[0] for row in db.execute(wildcard.rule.query).fetchall()},
                )
                self.assertEqual(
                    {"kerberos", "missing"},
                    {row[0] for row in db.execute(negated.rule.query).fetchall()},
                )
                self.assertEqual(
                    ["array", "event-above", "kerberos", "missing", "ntlm"],
                    [row[0] for row in db.execute(numeric.rule.query).fetchall()],
                )
                for evidence_id, command_line in (
                    ("windash-minus", "powershell -enc payload"),
                    ("windash-slash", "powershell /enc payload"),
                    ("windash-en", "powershell –enc payload"),
                    ("windash-em", "powershell —enc payload"),
                    ("windash-horizontal", "powershell ―enc payload"),
                ):
                    self._insert(
                        db,
                        evidence_id,
                        channel="Microsoft-Windows-Sysmon/Operational",
                        provider="Microsoft-Windows-Sysmon",
                        event_id=1,
                        event_data={"CommandLine": command_line},
                    )
                self.assertEqual(
                    {
                        "windash-minus",
                        "windash-slash",
                        "windash-en",
                        "windash-em",
                        "windash-horizontal",
                    },
                    {row[0] for row in db.execute(windash.rule.query).fetchall()},
                )


class RuleAndFindingTests(unittest.TestCase):
    def test_prefetch_dll_reference_requires_one_matching_array_element(self) -> None:
        rule = next(
            rule for rule in load_rules() if rule.id == "prefetch-dll-path-reference"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for evidence_id, filenames in (
                    (
                        "split-match",
                        [
                            r"C:\Windows\System32\normal.dll",
                            r"C:\Users\Alice\AppData\Local\Temp\note.txt",
                        ],
                    ),
                    (
                        "same-element-match",
                        [r"C:\Users\Alice\AppData\Local\Temp\helper.dll"],
                    ),
                    (
                        "dll-directory-suffix",
                        [r"C:\Users\Alice\AppData\Local\Temp\helper.dllfolder"],
                    ),
                    (
                        "dll-backup-suffix",
                        [r"C:\Users\Alice\AppData\Local\Temp\helper.dll.bak"],
                    ),
                    ("empty-array", []),
                    ("missing-array", None),
                ):
                    db.execute(
                        "INSERT INTO prefetch_executions "
                        "(evidence_id, executable_name, exec_count, last_exec_time, filenames) "
                        "VALUES (?, 'APP.EXE', 1, '2026-01-01 00:00:00', ?)",
                        [
                            evidence_id,
                            json.dumps(filenames) if filenames is not None else None,
                        ],
                    )

                rows = [
                    row for batch in iter_rule_row_batches(db, rule) for row in batch
                ]
                findings = generate_findings(rule, rows)

        self.assertEqual(["same-element-match"], [row["evidence_id"] for row in rows])
        self.assertIn(
            r"C:\Users\Alice\AppData\Local\Temp\helper.dll", findings[0].summary
        )
        self.assertEqual("same-element-match", findings[0].evidence[0]["evidence_id"])
        self.assertEqual(
            r"C:\Users\Alice\AppData\Local\Temp\helper.dll",
            findings[0].evidence[0]["matched_filename"],
        )

    def test_bulk_finding_insert_preserves_json_text_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            finding = Finding(
                finding_id="quoted-finding",
                rule_id="quoted-rule",
                title='O\'Brien said "こんにちは"',
                summary="雪と café",
                severity="medium",
                confidence=0.75,
                evidence=[{"quote": 'it\'s "real"', "empty": None, "text": "雪"}],
                ai_summary=None,
                missing_checks=["確認しない"],
            )
            nonfinite = Finding(
                finding_id="nonfinite-finding",
                rule_id="quoted-rule",
                title="Non-finite confidence",
                summary="summary",
                severity="medium",
                confidence=float("nan"),
            )
            with CaseDB(case) as db:
                save_findings(case, db, [finding, nonfinite], feed_timeline=False)
                row = db.execute(
                    "SELECT title, summary, evidence, ai_summary, missing_checks "
                    "FROM findings WHERE finding_id = ?",
                    [finding.finding_id],
                ).fetchone()
                nonfinite_confidence = db.execute(
                    "SELECT confidence FROM findings WHERE finding_id = ?",
                    [nonfinite.finding_id],
                ).fetchone()[0]

        self.assertEqual(row[0], 'O\'Brien said "こんにちは"')
        self.assertEqual(row[1], "雪と café")
        self.assertEqual(json.loads(row[2]), finding.evidence)
        self.assertIsNone(row[3])
        self.assertEqual(json.loads(row[4]), ["確認しない"])
        self.assertTrue(math.isnan(nonfinite_confidence))

    def test_bulk_finding_insert_rolls_back_earlier_chunks_on_failure(self) -> None:
        from duckdb import ConstraintException

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, summary, "
                    "severity, confidence, status) "
                    "VALUES ('duplicate', 'rule', 'existing', '', 'medium', 0.5, 'new')"
                )
                findings = [
                    Finding(
                        finding_id=f"batch-{index}",
                        rule_id="batch",
                        title=f"Finding {index}",
                        summary="summary",
                        severity="medium",
                        confidence=0.5,
                    )
                    for index in range(500)
                ]
                findings.append(
                    Finding(
                        finding_id="duplicate",
                        rule_id="batch",
                        title="conflict",
                        summary="summary",
                        severity="medium",
                        confidence=0.5,
                    )
                )

                with self.assertRaises(ConstraintException):
                    save_findings(case, db, findings, feed_timeline=False)

                self.assertEqual(
                    0,
                    db.execute(
                        "SELECT COUNT(*) FROM findings WHERE rule_id = 'batch'"
                    ).fetchone()[0],
                )

    def test_bounded_rule_batches_survive_database_writes_and_keep_ordinals(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            rule = Rule.model_validate(
                {
                    "id": "batch-rule",
                    "title": "batch rule",
                    "query": "SELECT i AS value FROM range(1003) AS rows(i)",
                    "finding": {"title": "row {value}", "summary": "row {value}"},
                }
            )
            with CaseDB(case) as db:
                generated = 0
                for batch in iter_rule_row_batches(db, rule, batch_size=128):
                    findings = generate_findings(
                        rule, batch, first_ordinal=generated + 1
                    )
                    save_findings(case, db, findings, feed_timeline=False)
                    generated += len(findings)
                rows = db.execute(
                    "SELECT COUNT(*), MIN(finding_id), MAX(finding_id) FROM findings"
                ).fetchone()
                self.assertFalse((case.path / "findings").exists())

        self.assertEqual(1003, generated)
        self.assertEqual((1003, "batch-rule-0001", "batch-rule-1003"), tuple(rows))

    def test_correlation_finding_preserves_source_evidence_ids(self) -> None:
        rule = Rule.model_validate(
            {
                "id": "test-corr",
                "title": "logon then service",
                "severity": "high",
                "confidence": 0.7,
                "query": "SELECT 1",
                "finding": {"title": "t", "summary": "s"},
                "tags": ["test"],
                "attack": [],
            }
        )
        findings = generate_findings(
            rule,
            [
                {
                    "evidence_id": "evtx-a",
                    "evidence_ids": ["evtx-a", "evtx-b"],
                }
            ],
        )
        self.assertEqual(["evtx-a", "evtx-b"], findings[0].evidence[0]["evidence_ids"])

    def test_generate_findings_degrades_confidence_when_key_fields_are_missing(
        self,
    ) -> None:
        rule = Rule.model_validate(
            {
                "id": "test-rule",
                "title": "Test rule",
                "severity": "critical",
                "confidence": 0.9,
                "required_fields": ["target_user", "src_ip"],
                "query": "SELECT 1",
                "finding": {"title": "User {target_user}", "summary": "IP {src_ip}"},
                "tags": ["windows"],
                "attack": [],
            }
        )
        findings = generate_findings(rule, [{"target_user": None, "src_ip": "-"}])
        self.assertLess(findings[0].confidence, 0.9)
        self.assertTrue(findings[0].missing_checks)


if __name__ == "__main__":
    unittest.main()
