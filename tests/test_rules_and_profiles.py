from __future__ import annotations

import tempfile
import unittest
import warnings
from pathlib import Path

import pytest
import yaml

from forensia.ai.hypotheses.seeding import seed_findings
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.evtx import normalize_evtx
from forensia.knowledge.rules.engine import generate_findings, save_findings
from forensia.knowledge.rules.loader import load_rules_from_dir
from forensia.knowledge.rules.models import Finding, Rule


class RuleProfileTests(unittest.TestCase):
    def test_windows_rule_ids_are_unique_and_baseline_rules_have_no_attack_mapping(
        self,
    ) -> None:
        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)

        self.assertGreaterEqual(len(rules), 116)
        self.assertEqual(len(rules), len({rule.id for rule in rules}))
        by_id = {rule.id: rule for rule in rules}
        self.assertFalse(by_id["windows-security-1100-evtlog-shutdown"].attack)
        self.assertFalse(by_id["windows-system-6005-6006-eventlog-service"].attack)

    def test_tool_detection_rules_are_catalog_driven(self) -> None:
        """Detection scope must come from dfir_ioc_catalog.yaml, not the rule.

        Why: new anti-forensic or cloud-sync tools should become detectable by
        adding a catalog entry alone — no rule edit. If tool names were inlined
        in the rule SQL, the catalog would stop being the single source of
        truth for tool knowledge.
        """
        from forensia.knowledge.catalog import catalog_exe_globs

        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = {rule.id: rule for rule in load_rules_from_dir(rules_dir, profile_path)}

        for rule_id, section in (
            ("windows-finding-antiforensic-tools", "antiforensic_tools"),
            ("windows-finding-data-staging", "cloud_sync_artifacts"),
        ):
            rule = rules[rule_id]
            # Placeholders must be expanded at load time...
            self.assertNotIn("{{", rule.query, rule_id)
            # ...into predicates derived from the catalog section.
            globs = catalog_exe_globs(section)
            self.assertTrue(globs, f"catalog section {section} is empty")
            sample = globs[0].lower().replace("*", "%")
            self.assertIn(sample, rule.query.lower(), rule_id)

    def test_seed_findings_replaces_existing_rule_rows_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO prefetch_executions (
                        evidence_id, source_file, executable_name,
                        exec_count, last_exec_time
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "prefetch-cleaner-1",
                        "sample/case/Prefetch/ERASER.EXE-12345678.pf",
                        "ERASER.EXE",
                        1,
                        "2024-01-01 00:00:00",
                    ),
                )
                _insert_old_finding = """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity,
                        confidence, status, tags, evidence
                    )
                    VALUES (?, ?, ?, '', 'high', 0.7, 'accepted', '[]', ?)
                """
                db.execute(
                    _insert_old_finding,
                    (
                        "windows-finding-antiforensic-tools-0001",
                        "windows-finding-antiforensic-tools",
                        "Anti-forensic tool detected: ERASER.EXE",
                        '[{"source_file":"sample/old/Prefetch/ERASER.EXE-OLD.pf"}]',
                    ),
                )

                seed_findings(case, db, "windows-basic")
                row = db.execute(
                    """
                    SELECT evidence FROM findings
                    WHERE finding_id = 'windows-finding-antiforensic-tools-0001'
                    """
                ).fetchone()

        self.assertIsNotNone(row)
        self.assertIn("ERASER.EXE-12345678.pf", row[0])
        self.assertNotIn("sample/", row[0])

    def test_antiforensic_and_staging_rules_declare_seed_hypotheses(self) -> None:
        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = {rule.id: rule for rule in load_rules_from_dir(rules_dir, profile_path)}

        for rule_id in (
            "windows-finding-antiforensic-tools",
            "windows-finding-data-staging",
        ):
            rule = rules[rule_id]
            self.assertTrue(rule.hypotheses, rule_id)
            description = rule.hypotheses[0].description.lower()
            self.assertIn("{executable_name}", description)
            for specific_tool in ("eraser", "ccleaner", "google drive", "dropbox"):
                self.assertNotIn(specific_tool, description)
            self.assertTrue(rule.hypotheses[0].confirm_when)

    def test_ransomware_profile_filters_rule_ids(self) -> None:
        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/ransomware-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertEqual(14, len(rules))
        self.assertIn("windows-defender-5001-realtime-disabled", rule_ids)
        self.assertNotIn("windows-security-4624-rdp-logon", rule_ids)

    def test_data_leakage_profile_loads_leakage_rulepack(self) -> None:
        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/data-leakage.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertIn("leakage-mft-sensitive-filename", rule_ids)
        self.assertIn("leakage-mft-cloud-sync-artifact", rule_ids)
        self.assertIn("leakage-mft-archive-staging-file", rule_ids)
        self.assertGreater(len(rules), 62)

    def test_short_form_attack_emits_deprecation_warning(self) -> None:
        data = {
            "id": "test-rule",
            "title": "Test Rule",
            "query": "SELECT 1",
            "finding": {"title": "Test", "summary": "Test"},
            "attack": ["T1078"],
        }
        with pytest.warns(
            DeprecationWarning, match=r"rule test-rule: attack uses short-form"
        ):
            Rule.model_validate(data)

    def test_full_form_attack_no_warning(self) -> None:
        data = {
            "id": "test-rule",
            "title": "Test Rule",
            "query": "SELECT 1",
            "finding": {"title": "Test", "summary": "Test"},
            "attack": [
                {
                    "tactic": "initial-access",
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                }
            ],
        }
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Rule.model_validate(data)
            deprecation_warnings = [
                x for x in w if issubclass(x.category, DeprecationWarning)
            ]
            self.assertEqual(0, len(deprecation_warnings))

    def test_major_windows_rules_define_required_fields(self) -> None:
        expected = {
            "security_4624_network_logon.yaml": {
                "target_user",
                "computer",
                "src_ip",
                "logon_type",
            },
            "security_4624_rdp_logon.yaml": {
                "target_user",
                "computer",
                "src_ip",
                "logon_type",
            },
            "security_4624_interactive_logon.yaml": {
                "target_user",
                "computer",
                "logon_type",
            },
            "security_4625_failed_logon.yaml": {
                "src_ip",
                "computer",
                "target_user",
                "fail_count",
            },
            "security_4648_logon_explicit_creds.yaml": {
                "subject_user",
                "target_user",
                "computer",
                "process_name",
            },
            "security_4688_powershell.yaml": {
                "target_user",
                "computer",
                "process_name",
                "command_line",
            },
            "security_4688_suspicious_tools.yaml": {
                "target_user",
                "computer",
                "process_name",
                "command_line",
            },
            "security_4697_service_install.yaml": {
                "subject_user",
                "service_name",
                "computer",
            },
            "system_7045_service_installed.yaml": {
                "service_name",
                "computer",
                "subject_user",
            },
            "security_4720_account_lifecycle_consolidated.yaml": {
                "target_user",
                "computer",
                "subject_user",
            },
            "security_4728_group_change_consolidated.yaml": {
                "target_user",
                "computer",
                "subject_user",
                "message",
            },
        }
        rules_dir = Path("src/forensia/knowledge/rulepacks/windows")
        for filename, fields in expected.items():
            parsed = yaml.safe_load((rules_dir / filename).read_text(encoding="utf-8"))
            self.assertTrue(
                fields.issubset(set(parsed.get("required_fields") or [])), filename
            )

    def test_windows_allowlist_metadata_is_not_loaded_as_rule(self) -> None:
        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertGreaterEqual(len(rules), 116)
        self.assertNotIn("allowlist_services", rule_ids)

    def test_profile_with_nonexistent_rulepack_loads_zero_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profile.yaml"
            profile_path.write_text("rulepacks:\n  - nonexistent\n", encoding="utf-8")

            rules = load_rules_from_dir(
                "src/forensia/knowledge/rulepacks", profile_path
            )

        self.assertEqual(0, len(rules))


class AllowlistTests(unittest.TestCase):
    def test_allowlist_marks_matching_finding_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            case.allowlist_path.write_text(
                (
                    "rules:\n"
                    "  - rule_id: windows-security-4624-network-logon\n"
                    "    when:\n"
                    "      target_user: [ANONYMOUS LOGON]\n"
                    "      src_ip: [10.0.0.5]\n"
                ),
                encoding="utf-8",
            )
            finding = Finding(
                finding_id="windows-security-4624-network-logon-0001",
                rule_id="windows-security-4624-network-logon",
                title="test",
                summary="test",
                severity="medium",
                confidence=0.5,
                evidence=[{"target_user": "ANONYMOUS LOGON", "src_ip": "10.0.0.5"}],
            )

            with CaseDB(case) as db:
                save_findings(case, db, [finding])
                row = db.execute(
                    "SELECT status FROM findings WHERE finding_id = ?",
                    (finding.finding_id,),
                ).fetchone()

            self.assertIsNotNone(row)
            self.assertEqual("suppressed", row[0])

    def test_builtin_benign_allowlist_suppresses_known_service_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            finding = Finding(
                finding_id="windows-system-7045-service-installed-0001",
                rule_id="windows-system-7045-service-installed",
                title="Service installed: Google Update",
                summary="Known benign updater service installed",
                severity="high",
                confidence=0.9,
                evidence=[{"service_name": "gupdate"}],
            )

            with CaseDB(case) as db:
                save_findings(case, db, [finding])
                row = db.execute(
                    "SELECT status, severity, confidence, missing_checks FROM findings WHERE finding_id = ?",
                    (finding.finding_id,),
                ).fetchone()

            self.assertIsNotNone(row)
            self.assertEqual("suppressed", row[0])
            self.assertEqual("low", row[1])
            self.assertLessEqual(float(row[2]), 0.2)
            self.assertIn("built-in benign allowlist", row[3])

    def test_builtin_benign_allowlist_does_not_suppress_suspicious_process_rule(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            finding = Finding(
                finding_id="windows-security-4688-suspicious-tools-0001",
                rule_id="windows-security-4688-suspicious-tools",
                title="LOLBAS-style tool execution: msiexec.exe @ host1",
                summary="alice executed msiexec.exe with suspicious arguments",
                severity="medium",
                confidence=0.55,
                evidence=[{"process_name": "msiexec.exe"}],
            )

            with CaseDB(case) as db:
                save_findings(case, db, [finding])
                row = db.execute(
                    "SELECT status, severity, confidence FROM findings WHERE finding_id = ?",
                    (finding.finding_id,),
                ).fetchone()

            self.assertIsNotNone(row)
            self.assertEqual("new", row[0])
            self.assertEqual("medium", row[1])
            self.assertEqual(0.55, float(row[2]))


class NormalizeEvtxTests(unittest.TestCase):
    def test_normalize_evtx_maps_winlog_user_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.raw_dir / "evtx-abc123.jsonl").write_text(
                (
                    '{"evidence_id":"ev-1","source_file":"security.evtx","@timestamp":"2026-05-16T01:02:03Z",'
                    '"winlog":{"channel":"Security","event_id":"4624","record_id":"1","computer_name":"host1",'
                    '"user":{"name":"alice"},'
                    '"event_data":{"TargetUserName":"alice","SubjectUserName":"SYSTEM","IpAddress":"10.0.0.1","LogonType":"3"}}}\n'
                ),
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                inserted = normalize_evtx(case, db)
                user_names = db.execute(
                    "SELECT DISTINCT user_name FROM evtx_events WHERE user_name IS NOT NULL ORDER BY user_name"
                ).fetchall()

            self.assertEqual(1, inserted)
            self.assertEqual([("alice",)], user_names)


class RuleExecutionTests(unittest.TestCase):
    def _run_rule_query(self, db: CaseDB, filename: str) -> list[dict[str, object]]:
        rule_path = Path("src/forensia/knowledge/rulepacks/windows") / filename
        query = yaml.safe_load(rule_path.read_text(encoding="utf-8"))["query"]
        result = db.execute(query)
        columns = [item[0] for item in result.description]
        return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]

    def _insert_evtx_event(
        self,
        db: CaseDB,
        *,
        evidence_id: str,
        event_id: int,
        timestamp: str,
        computer: str,
        target_user: str | None = None,
        subject_user: str | None = None,
        src_ip: str | None = None,
        logon_type: str | None = None,
        message: str | None = None,
    ) -> None:
        db.execute(
            """
            INSERT INTO evtx_events (
                evidence_id, source_file, channel, event_id, record_id, timestamp,
                computer, target_user, subject_user, src_ip, logon_type, message
            ) VALUES (?, 'security.evtx', 'Security', ?, 1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                event_id,
                timestamp,
                computer,
                target_user,
                subject_user,
                src_ip,
                logon_type,
                message,
            ),
        )

    def test_4624_network_logon_filters_builtin_noise_accounts_and_loopback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-1",
                    event_id=4624,
                    timestamp="2026-05-16 01:00:00",
                    computer="host1",
                    target_user="alice",
                    subject_user="SYSTEM",
                    src_ip="10.0.0.5",
                    logon_type="3",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-2",
                    event_id=4624,
                    timestamp="2026-05-16 01:01:00",
                    computer="host1",
                    target_user="bob",
                    subject_user="SYSTEM",
                    src_ip="127.0.0.1",
                    logon_type="3",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-3",
                    event_id=4624,
                    timestamp="2026-05-16 01:02:00",
                    computer="host1",
                    target_user="ANONYMOUS LOGON",
                    subject_user="SYSTEM",
                    src_ip="10.0.0.6",
                    logon_type="3",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-4",
                    event_id=4624,
                    timestamp="2026-05-16 01:03:00",
                    computer="host1",
                    target_user="DESKTOP-01$",
                    subject_user="SYSTEM",
                    src_ip="10.0.0.7",
                    logon_type="3",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-5",
                    event_id=4624,
                    timestamp="2026-05-16 01:04:00",
                    computer="host1",
                    target_user="SYSTEM",
                    subject_user="SYSTEM",
                    src_ip="10.0.0.8",
                    logon_type="3",
                )

                rows = self._run_rule_query(db, "security_4624_network_logon.yaml")

            self.assertEqual(1, len(rows))
            self.assertEqual("alice", rows[0]["target_user"])
            self.assertEqual("10.0.0.5", rows[0]["src_ip"])

    def test_4625_failed_logon_uses_short_time_window_and_stricter_threshold(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index, minute in enumerate((0, 4, 8, 11, 14), start=1):
                    self._insert_evtx_event(
                        db,
                        evidence_id=f"burst-{index}",
                        event_id=4625,
                        timestamp=f"2026-05-16 00:{minute:02d}:00",
                        computer="host1",
                        target_user="alice",
                        src_ip="10.0.0.9",
                    )
                for index, minute in enumerate((0, 20, 40), start=1):
                    self._insert_evtx_event(
                        db,
                        evidence_id=f"spread-a-{index}",
                        event_id=4625,
                        timestamp=f"2026-05-16 01:{minute:02d}:00",
                        computer="host1",
                        target_user="bob",
                        src_ip="10.0.0.10",
                    )
                for index, minute in enumerate((0, 20), start=1):
                    self._insert_evtx_event(
                        db,
                        evidence_id=f"spread-b-{index}",
                        event_id=4625,
                        timestamp=f"2026-05-16 02:{minute:02d}:00",
                        computer="host1",
                        target_user="bob",
                        src_ip="10.0.0.10",
                    )

                rows = self._run_rule_query(db, "security_4625_failed_logon.yaml")

            self.assertEqual(1, len(rows))
            self.assertEqual("10.0.0.9", rows[0]["src_ip"])
            self.assertEqual("alice", rows[0]["target_user"])
            self.assertEqual(5, rows[0]["fail_count"])

    def test_4624_interactive_logon_keeps_user_logons_and_excludes_noise_accounts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-1",
                    event_id=4624,
                    timestamp="2026-05-16 04:00:00",
                    computer="host1",
                    target_user="informant",
                    subject_user="SYSTEM",
                    src_ip=None,
                    logon_type="2",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-2",
                    event_id=4624,
                    timestamp="2026-05-16 04:01:00",
                    computer="host1",
                    target_user="alice",
                    subject_user="SYSTEM",
                    src_ip="10.0.0.15",
                    logon_type="10",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-3",
                    event_id=4624,
                    timestamp="2026-05-16 04:02:00",
                    computer="host1",
                    target_user="SYSTEM",
                    subject_user="SYSTEM",
                    src_ip=None,
                    logon_type="2",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="ev-4",
                    event_id=4624,
                    timestamp="2026-05-16 04:03:00",
                    computer="host1",
                    target_user="DESKTOP-01$",
                    subject_user="SYSTEM",
                    src_ip=None,
                    logon_type="2",
                )

                rows = self._run_rule_query(db, "security_4624_interactive_logon.yaml")

            self.assertEqual(2, len(rows))
            self.assertEqual(
                {"informant", "alice"}, {row["target_user"] for row in rows}
            )

    def test_5140_admin_share_access_parses_share_name_and_excludes_ipc_noise(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert_evtx_event(
                    db,
                    evidence_id="share-1",
                    event_id=5140,
                    timestamp="2026-05-16 03:00:00",
                    computer="host1",
                    subject_user="alice",
                    src_ip="10.0.0.11",
                    message="Share Name:\t\\\\*\\ADMIN$\r\nRelative Target Name:\ttemp",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="share-2",
                    event_id=5140,
                    timestamp="2026-05-16 03:01:00",
                    computer="host1",
                    subject_user="bob",
                    src_ip="10.0.0.12",
                    message="ShareName=\\\\fileserver\\C$ AccessMask=0x1",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="share-3",
                    event_id=5140,
                    timestamp="2026-05-16 03:02:00",
                    computer="host1",
                    subject_user="carol",
                    src_ip="10.0.0.13",
                    message="Share Name:\t\\\\*\\IPC$\r\nRelative Target Name:\t",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="share-4",
                    event_id=5140,
                    timestamp="2026-05-16 03:03:00",
                    computer="host1",
                    subject_user="dave",
                    src_ip="10.0.0.14",
                    message="User opened admin console without a share path",
                )

                rows = self._run_rule_query(db, "security_5140_admin_share_access.yaml")

            self.assertEqual(2, len(rows))
            self.assertEqual({"ADMIN$", "C$"}, {row["share_name"] for row in rows})
            self.assertEqual(
                {"share-1", "share-2"}, {row["evidence_id"] for row in rows}
            )

    def test_system_104_log_cleared_requires_eventlog_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp,
                        computer, raw_json
                    ) VALUES (?, 'diagnosis.evtx', ?, 104, 1, ?, ?, ?)
                    """,
                    (
                        "diagnosis-104",
                        "Microsoft-Windows-Diagnosis-Scripted/Operational",
                        "2026-05-16 01:00:00",
                        "host1",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Diagnosis-Scripted"}}}',
                    ),
                )
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp,
                        computer, raw_json
                    ) VALUES (?, 'system.evtx', ?, 104, 2, ?, ?, ?)
                    """,
                    (
                        "eventlog-104",
                        "System",
                        "2026-05-16 01:05:00",
                        "host1",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Eventlog"}}}',
                    ),
                )

                rows = self._run_rule_query(db, "system_104_log_cleared.yaml")

            self.assertEqual(1, len(rows))
            self.assertEqual("eventlog-104", rows[0]["evidence_id"])

    def test_correlation_finding_carries_source_evidence_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert_evtx_event(
                    db,
                    evidence_id="evtx-security-000000000001",
                    event_id=4624,
                    timestamp="2026-05-16 01:00:00",
                    computer="host1",
                    target_user="alice",
                    subject_user="SYSTEM",
                    src_ip="10.0.0.5",
                    logon_type="3",
                )
                self._insert_evtx_event(
                    db,
                    evidence_id="evtx-security-000000000002",
                    event_id=4697,
                    timestamp="2026-05-16 01:05:00",
                    computer="host1",
                    target_user="alice",
                    subject_user="alice",
                )

                rule = Rule.model_validate(
                    {
                        "id": "test-corr",
                        "title": "Network logon then service install",
                        "severity": "critical",
                        "confidence": 0.65,
                        "query": (
                            "WITH net_logons AS (\n"
                            "    SELECT evidence_id, timestamp AS logon_time, computer,\n"
                            "           src_ip, target_user\n"
                            "    FROM evtx_events\n"
                            "    WHERE event_id = 4624 AND logon_type = '3'\n"
                            "      AND target_user NOT LIKE '%$'\n"
                            "),\n"
                            "svc_installs AS (\n"
                            "    SELECT evidence_id, timestamp AS svc_time, computer,\n"
                            "           service_name, subject_user\n"
                            "    FROM evtx_events\n"
                            "    WHERE event_id IN (4697, 7045)\n"
                            ")\n"
                            "SELECT l.evidence_id,\n"
                            "       LIST_VALUE(l.evidence_id, s.evidence_id) AS evidence_ids,\n"
                            "       l.src_ip, l.computer, l.target_user,\n"
                            "       l.logon_time, s.svc_time, s.service_name\n"
                            "FROM net_logons l\n"
                            "JOIN svc_installs s\n"
                            "  ON l.computer = s.computer\n"
                            " AND s.svc_time BETWEEN l.logon_time AND l.logon_time + INTERVAL 15 MINUTE"
                        ),
                        "finding": {
                            "title": "test {src_ip}",
                            "summary": "test {service_name}",
                        },
                        "tags": ["test"],
                        "attack": [],
                    }
                )
                result = db.execute(rule.query)
                columns = [item[0] for item in result.description]
                rows = [
                    dict(zip(columns, row, strict=False)) for row in result.fetchall()
                ]
                findings = generate_findings(rule, rows)

            self.assertEqual(1, len(findings))
            ev = findings[0].evidence[0]
            self.assertIn(
                "evidence_id", ev, "correlation finding must carry source evidence_id"
            )
            self.assertIn(
                "evidence_ids", ev, "correlation finding must carry evidence_ids list"
            )
            self.assertIn("evtx-security-000000000001", str(ev.get("evidence_ids")))
            self.assertIn("evtx-security-000000000002", str(ev.get("evidence_ids")))

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
                "finding": {
                    "title": "Network logon: {target_user}",
                    "summary": "Source IP: {src_ip}",
                },
                "tags": ["windows"],
                "attack": [
                    {
                        "tactic": "initial-access",
                        "technique_id": "T1078",
                        "technique_name": "Valid Accounts",
                    }
                ],
            }
        )

        findings = generate_findings(rule, [{"target_user": None, "src_ip": "-"}])

        self.assertEqual(1, len(findings))
        self.assertEqual("Network logon: ", findings[0].title)
        self.assertEqual("Source IP: ", findings[0].summary)
        self.assertLess(findings[0].confidence, 0.9)
        self.assertTrue(findings[0].missing_checks)


if __name__ == "__main__":
    unittest.main()


class FindingEvidencePathSanitizationTests(unittest.TestCase):
    """Finding evidence must never record the analyst's local ingest tree.

    Why: databases ingested before the source_file basename fix carry raw
    local paths (e.g. sample/<case>/Prefetch/FOO.pf). Rules that SELECT
    source_file would otherwise copy those paths into finding evidence and
    the rendered summary, from where they leak into report_brief.json and
    the client-facing report.
    """

    def test_generate_findings_sanitizes_ingest_paths_in_evidence(self) -> None:
        rule = Rule.model_validate(
            {
                "id": "test-path-sanitize",
                "title": "t",
                "severity": "high",
                "confidence": 0.7,
                "query": "SELECT 1",
                "finding": {
                    "title": "tool {executable_name}",
                    "summary": "seen in {source_file}",
                },
                "tags": ["test"],
                "attack": [],
            }
        )
        rows = [
            {
                "evidence_id": "pf-001",
                "executable_name": "ERASER.EXE",
                "source_file": "sample/case1/Prefetch/ERASER.EXE-BE552234.pf",
            },
            {
                "evidence_id": "ev-002",
                "executable_name": "REAL.EXE",
                # Real Windows path from the image — must stay untouched.
                "source_file": "C:\\Windows\\Prefetch\\REAL.EXE-11111111.pf",
            },
        ]
        findings = generate_findings(rule, rows)

        self.assertEqual(2, len(findings))
        ingest_ev = findings[0].evidence[0]
        self.assertEqual(
            "ERASER.EXE-BE552234.pf",
            ingest_ev["source_file"],
            "local ingest path must be reduced to basename",
        )
        self.assertNotIn("sample/", findings[0].summary)
        windows_ev = findings[1].evidence[0]
        self.assertEqual(
            "C:\\Windows\\Prefetch\\REAL.EXE-11111111.pf",
            windows_ev["source_file"],
            "real Windows evidence paths must not be shortened",
        )
