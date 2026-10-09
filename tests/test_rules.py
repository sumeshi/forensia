from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.evtx import normalize_evtx
from forensia.knowledge.rules.engine import generate_findings, save_findings
from forensia.knowledge.rules.loader import load_rules_from_dir
from forensia.knowledge.rules.models import Finding, Rule

RULES_DIR = Path("src/forensia/knowledge/rulepacks")
SHA = "a" * 64


class RuleDeclarationTests(unittest.TestCase):
    def test_catalog_and_sigma_rule_ids_are_unique(self) -> None:
        rules = load_rules_from_dir(RULES_DIR)
        ids = {rule.id for rule in rules}
        self.assertEqual(len(rules), len(ids))
        self.assertTrue(
            {
                "481d216e-1f57-4e2a-9ad0-927c51148819",
                "5e8c6210-2521-4e48-9f8c-9fc91d8c9353",
                "a91f778c-413b-4f21-a3fc-c775dac718b2",
                "prefetch-finding-antiforensic-tools",
                "prefetch-finding-data-staging",
                "filesystem-mft-cloud-sync-db-deleted",
                "registry-autorun-run-key-reference",
            }.issubset(ids)
        )

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

                _run_analyze_stage(case, db, True, True, lambda *a, **kw: None, None)
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
    def test_native_evtx_jsonl_normalizes_and_runs_three_sigma_detections(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            raw = case.raw_dir / f"evtx-{SHA}-records.jsonl"
            raw.write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )
            with CaseDB(case) as db:
                self.assertEqual(5, normalize_evtx(case, db))
                rows = db.execute(
                    "SELECT raw_json FROM evtx_events ORDER BY record_id"
                ).fetchall()
                self.assertEqual(events, [json.loads(row[0]) for row in rows])
                self.assertTrue(
                    all("evidence_id" not in json.loads(row[0]) for row in rows)
                )
                from forensia.pipeline import _run_analyze_stage

                def progress(*args, **kwargs):
                    pass

                self.assertEqual(
                    3,
                    _run_analyze_stage(case, db, True, True, progress, None),
                )
                receipt = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps WHERE phase = 'pipeline-analyze'"
                    ).fetchone()[0]
                )
                sigma_rules = [
                    rule for rule in receipt["rules"] if rule["format"] == "sigma"
                ]
                self.assertEqual(3, len(sigma_rules))
                self.assertEqual("2.0.0", receipt["pysigma_version"])
                self.assertTrue(
                    all(
                        len(rule["definition_sha256"]) == 64
                        and "evtx_events" in rule["query"]
                        for rule in sigma_rules
                    )
                )
                self.assertEqual(
                    3,
                    _run_analyze_stage(case, db, False, False, progress, None),
                )
                self.assertEqual(
                    1,
                    db.execute(
                        "SELECT COUNT(*) FROM trace.investigation_steps WHERE phase = 'pipeline-analyze'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    3, db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                )
                references = [
                    json.loads(row[0])[0]["evidence_id"]
                    for row in db.execute("SELECT evidence FROM findings").fetchall()
                ]
                self.assertEqual(3, len(set(references)))
                self.assertTrue(
                    all(ref.startswith("evtx-" + SHA) for ref in references)
                )


class SigmaCompilerTests(unittest.TestCase):
    def _rule(self, detection: dict, **overrides: object) -> dict:
        data: dict = {
            "title": "compiler test",
            "id": "6f0454e5-0918-4d03-ae3b-98c719b0f407",
            "logsource": {"product": "windows", "service": "security"},
            "detection": detection,
        }
        data.update(overrides)
        return data

    def test_rejects_unimplemented_sigma_shapes(self) -> None:
        from forensia.knowledge.rules.sigma import compile_sigma_rule

        invalid = [
            self._rule(
                {"selection": {"EventID": 1}, "condition": "selection"},
                logsource={"product": "linux", "service": "security"},
            ),
            self._rule(
                {"selection": {"EventID": 1}, "condition": "selection"},
                logsource={"product": "windows", "service": "sysmon"},
            ),
            self._rule(
                {"selection": {"EventID": 1}, "condition": "selection"},
                logsource={"product": "windows", "category": "process_creation"},
            ),
            self._rule({"selection": {"UnknownField": "x"}, "condition": "selection"}),
            self._rule(
                {"selection": {"CommandLine|regex": "x"}, "condition": "selection"}
            ),
            self._rule({"keywords": ["powershell"], "condition": "keywords"}),
            self._rule(
                {"selection": {"EventID": 1}, "condition": "selection"},
                correlation={"type": "temporal"},
            ),
            self._rule(
                {"selection": {"EventID": 1}, "condition": "selection"}, timeframe="5m"
            ),
            self._rule(
                {"selection": {"EventID": 1}, "condition": ["selection", "selection"]}
            ),
        ]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                compile_sigma_rule(data)

    def test_compiles_supported_modifiers_and_sql_literal_escaping(self) -> None:
        from forensia.knowledge.rules.sigma import compile_sigma_rule

        checks = [
            ("CommandLine", "O'Brien", "O'Brien"),
            ("CommandLine|contains", "literal%_part", "literal%_part"),
            ("CommandLine|contains", "powershell*", "powershellXYZ"),
            ("CommandLine|startswith", "start*", "startXYZ"),
            ("CommandLine|endswith", "*finish", "will-finish"),
            ("CommandLine|contains|all", ["alpha", "beta"], "alpha beta"),
            ("EventID", 1102, 1102),
            ("EventID", True, 1),
            ("CommandLine", None, None),
            ("CommandLine|exists", True, "present"),
            ("CommandLine|exists", False, None),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for field, value, matching in checks:
                    with self.subTest(field=field, value=value):
                        rule = compile_sigma_rule(
                            self._rule(
                                {"selection": {field: value}, "condition": "selection"}
                            )
                        )
                        db.execute("DELETE FROM evtx_events")
                        column = "event_id" if field == "EventID" else "command_line"
                        db.execute(
                            f"INSERT INTO evtx_events (evidence_id, source_file, channel, {column}) "
                            "VALUES ('match', 's', 'Security', ?)",
                            (matching,),
                        )
                        self.assertEqual(
                            ["match"],
                            [row[0] for row in db.execute(rule.query).fetchall()],
                        )

    def test_contains_escapes_sql_wildcards_and_negation_includes_null(self) -> None:
        from forensia.knowledge.rules.sigma import compile_sigma_rule

        contains = compile_sigma_rule(
            self._rule(
                {
                    "selection": {"CommandLine|contains": "100%_safe"},
                    "condition": "selection",
                }
            )
        )
        negated = compile_sigma_rule(
            self._rule(
                {
                    "selection": {"CommandLine|contains": "needle"},
                    "condition": "not selection",
                }
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, command_line) VALUES ('match', 's', 'Security', '100%_safe')"
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, command_line) VALUES ('wild', 's', 'Security', '100XXsafe')"
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, command_line) VALUES ('null', 's', 'Security', NULL)"
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, command_line) VALUES ('excluded', 's', 'Security', 'NEEDLE')"
                )
                actual = {row[0] for row in db.execute(contains.query).fetchall()}
                self.assertEqual({"match"}, actual)
                rejected = {row[0] for row in db.execute(negated.query).fetchall()}
                self.assertEqual({"match", "wild", "null"}, rejected)


class RuleAndFindingTests(unittest.TestCase):
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
