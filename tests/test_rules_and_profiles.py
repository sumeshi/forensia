from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize.evtx import normalize_evtx
from forensia.rules.engine import save_findings
from forensia.rules.loader import load_rules_from_dir
from forensia.rules.models import Finding


JP_CHAR_PATTERN = r"[ぁ-んァ-ン一-龥]"


class RuleProfileTests(unittest.TestCase):
    def test_windows_rules_have_attack_mapping(self) -> None:
        rules_dir = Path("src/forensia/rulepacks")
        profile_path = Path("src/forensia/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)

        self.assertEqual(61, len(rules))
        self.assertTrue(all(rule.attack for rule in rules))

    def test_ransomware_profile_filters_rule_ids(self) -> None:
        rules_dir = Path("src/forensia/rulepacks")
        profile_path = Path("src/forensia/profiles/ransomware-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_ids = {rule.id for rule in rules}

        self.assertEqual(14, len(rules))
        self.assertIn("windows-defender-5001-realtime-disabled", rule_ids)
        self.assertNotIn("windows-security-4624-rdp-logon", rule_ids)

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


class NormalizeEvtxTests(unittest.TestCase):
    def test_normalize_evtx_maps_winlog_user_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.raw_dir / "security.jsonl").write_text(
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


if __name__ == "__main__":
    unittest.main()
