from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.rules.engine import save_findings
from forensia.rules.loader import load_rules_from_dir
from forensia.rules.models import Finding


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


if __name__ == "__main__":
    unittest.main()
