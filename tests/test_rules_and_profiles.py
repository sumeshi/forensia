from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize.evtx import normalize_evtx
from forensia.rules.engine import save_findings
from forensia.rules.engine import generate_findings
from forensia.rules.loader import load_rules_from_dir
from forensia.rules.models import Finding, Rule


JP_CHAR_PATTERN = r"[ぁ-んァ-ン一-龥]"


class RuleProfileTests(unittest.TestCase):
    def test_windows_rules_have_attack_mapping(self) -> None:
        rules_dir = Path("src/forensia/rulepacks")
        profile_path = Path("src/forensia/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)

        self.assertEqual(125, len(rules))
        self.assertTrue(all(rule.attack for rule in rules))

    def test_ransomware_profile_filters_rule_ids(self) -> None:
        rules_dir = Path("src/forensia/rulepacks")
        profile_path = Path("src/forensia/profiles/ransomware-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertEqual(14, len(rules))
        self.assertIn("windows-defender-5001-realtime-disabled", rule_ids)
        self.assertNotIn("windows-security-4624-rdp-logon", rule_ids)

    def test_data_leakage_profile_loads_leakage_rulepack(self) -> None:
        rules_dir = Path("src/forensia/rulepacks")
        profile_path = Path("src/forensia/profiles/data-leakage.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertIn("leakage-mft-sensitive-filename", rule_ids)
        self.assertIn("leakage-mft-cloud-sync-artifact", rule_ids)
        self.assertIn("leakage-mft-archive-staging-file", rule_ids)
        self.assertGreater(len(rules), 62)

    def test_major_windows_rules_define_required_fields(self) -> None:
        expected = {
            "security_4624_network_logon.yaml": {"target_user", "computer", "src_ip", "logon_type"},
            "security_4624_rdp_logon.yaml": {"target_user", "computer", "src_ip", "logon_type"},
            "security_4624_interactive_logon.yaml": {"target_user", "computer", "logon_type"},
            "security_4625_failed_logon.yaml": {"src_ip", "computer", "target_user", "fail_count"},
            "security_4648_logon_explicit_creds.yaml": {"subject_user", "target_user", "computer", "process_name"},
            "security_4688_powershell.yaml": {"target_user", "computer", "process_name", "command_line"},
            "security_4688_suspicious_tools.yaml": {"target_user", "computer", "process_name", "command_line"},
            "security_4697_service_install.yaml": {"subject_user", "service_name", "computer"},
            "system_7045_service_installed.yaml": {"service_name", "computer", "subject_user"},
            "security_4720_account_created.yaml": {"subject_user", "target_user", "computer"},
            "security_4728_domain_admin_added.yaml": {"subject_user", "target_user", "computer", "message"},
            "security_4732_local_admin_added.yaml": {"subject_user", "target_user", "computer", "message"},
        }
        rules_dir = Path("src/forensia/rulepacks/windows")
        for filename, fields in expected.items():
            parsed = yaml.safe_load((rules_dir / filename).read_text(encoding="utf-8"))
            self.assertTrue(fields.issubset(set(parsed.get("required_fields") or [])), filename)

    def test_windows_allowlist_metadata_is_not_loaded_as_rule(self) -> None:
        rules_dir = Path("src/forensia/rulepacks")
        profile_path = Path("src/forensia/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertEqual(125, len(rules))
        self.assertNotIn("allowlist_services", rule_ids)

    def test_profile_with_nonexistent_rulepack_loads_zero_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profile.yaml"
            profile_path.write_text("rulepacks:\n  - nonexistent\n", encoding="utf-8")

            rules = load_rules_from_dir("src/forensia/rulepacks", profile_path)

        self.assertEqual(0, len(rules))

    def test_windows_rule_findings_are_english_for_translated_batch(self) -> None:
        target_files = [
            "corr_account_created_then_admin_added.yaml",
            "corr_bruteforce_then_success.yaml",
            "corr_defender_disabled_then_exec.yaml",
            "corr_logon_then_logclear.yaml",
            "corr_logon_then_service.yaml",
            "corr_logon_then_task.yaml",
            "corr_rdp_then_powershell.yaml",
            "defender_1116_malware_detected.yaml",
            "defender_1117_action_taken.yaml",
            "defender_5001_realtime_disabled.yaml",
            "powershell_400_engine_start.yaml",
            "powershell_4103_module_logging.yaml",
            "powershell_4104_encoded.yaml",
            "powershell_4105_script_started.yaml",
            "rdp_lsm_21_logon.yaml",
            "rdp_lsm_24_disconnect.yaml",
            "rdp_lsm_25_reconnect.yaml",
            "rdp_rcm_1149_user_auth_success.yaml",
            "security_1100_evtlog_shutdown.yaml",
            "security_1102_log_cleared.yaml",
            "security_1104_security_log_full.yaml",
            "security_4616_time_changed.yaml",
            "security_4624_explicit_creds.yaml",
            "security_4624_interactive_logon.yaml",
            "security_4624_network_logon.yaml",
            "security_4624_rdp_logon.yaml",
            "security_4625_failed_logon.yaml",
            "security_4648_logon_explicit_creds.yaml",
            "security_4672_special_privileges.yaml",
            "security_4688_powershell.yaml",
            "security_4688_suspicious_tools.yaml",
            "security_4697_service_install.yaml",
            "security_4698_task_created.yaml",
            "security_4699_task_deleted.yaml",
            "security_4719_audit_policy_changed.yaml",
            "security_4720_account_created.yaml",
            "security_4722_account_enabled.yaml",
            "security_4723_password_change.yaml",
            "security_4724_password_reset.yaml",
            "security_4726_account_deleted.yaml",
            "security_4728_domain_admin_added.yaml",
            "security_4729_global_group_removed.yaml",
            "security_4732_local_admin_added.yaml",
            "security_4738_account_changed.yaml",
            "security_4740_account_lockout.yaml",
            "security_4756_universal_group_added.yaml",
            "security_4768_tgt_request.yaml",
            "security_4769_st_request.yaml",
            "security_4771_pre_auth_failed.yaml",
            "security_4776_ntlm_auth.yaml",
            "security_4778_rdp_reconnect.yaml",
            "security_4779_rdp_disconnect.yaml",
            "security_5140_admin_share_access.yaml",
            "system_104_log_cleared.yaml",
            "system_1074_initiated_shutdown.yaml",
            "system_41_unexpected_reboot.yaml",
            "system_6008_unexpected_shutdown.yaml",
            "system_7036_service_state.yaml",
            "system_7040_service_starttype_change.yaml",
            "system_7045_service_installed.yaml",
            "tasksched_106_task_registered.yaml",
            "tasksched_141_task_deleted.yaml",
        ]
        rules_dir = Path("src/forensia/rulepacks/windows")
        for filename in target_files:
            parsed = yaml.safe_load((rules_dir / filename).read_text(encoding="utf-8"))
            finding = parsed["finding"]
            self.assertNotRegex(finding["title"], JP_CHAR_PATTERN, filename)
            self.assertNotRegex(finding["summary"], JP_CHAR_PATTERN, filename)


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
        rule_path = Path("src/forensia/rulepacks/windows") / filename
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
            (evidence_id, event_id, timestamp, computer, target_user, subject_user, src_ip, logon_type, message),
        )

    def test_4624_network_logon_filters_builtin_noise_accounts_and_loopback(self) -> None:
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

    def test_4625_failed_logon_uses_short_time_window_and_stricter_threshold(self) -> None:
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

    def test_4624_interactive_logon_keeps_user_logons_and_excludes_noise_accounts(self) -> None:
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
            self.assertEqual({"informant", "alice"}, {row["target_user"] for row in rows})

    def test_5140_admin_share_access_parses_share_name_and_excludes_ipc_noise(self) -> None:
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
            self.assertEqual({"share-1", "share-2"}, {row["evidence_id"] for row in rows})

    def test_generate_findings_degrades_confidence_when_key_fields_are_missing(self) -> None:
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
                "attack": ["T1078"],
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
