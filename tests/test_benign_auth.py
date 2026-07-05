from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.benign_auth import (
    _normalise_ip,
    finding_is_auth_scoped,
    is_benign_local_auth,
    tag_benign_local_auth_findings,
)

# ====================================================================
# _normalise_ip
# ====================================================================


class TestNormaliseIp:
    @staticmethod
    def test_none_returns_empty() -> None:
        assert _normalise_ip(None) == ""

    @staticmethod
    def test_empty_string() -> None:
        assert _normalise_ip("") == ""

    @staticmethod
    def test_ipv4_loopback() -> None:
        assert _normalise_ip("127.0.0.1") == "127.0.0.1"

    @staticmethod
    def test_ipv6_loopback() -> None:
        assert _normalise_ip("::1") == "::1"

    @staticmethod
    def test_localhost() -> None:
        assert _normalise_ip("localhost") == "localhost"

    @staticmethod
    def test_dash() -> None:
        assert _normalise_ip("-") == "-"

    @staticmethod
    def test_whitespace_stripped_and_lowered() -> None:
        assert _normalise_ip("  LOCALHOST  ") == "localhost"


# ====================================================================
# is_benign_local_auth
# ====================================================================


class TestIsBenignLocalAuth:
    """Tests for is_benign_local_auth()."""

    @staticmethod
    def test_loopback_4648_true() -> None:
        """src_ip=127.0.0.1, event_id=4648 → benign."""
        row: dict[str, Any] = {"src_ip": "127.0.0.1", "event_id": "4648"}
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_loopback_4624_true() -> None:
        """src_ip=::1, event_id=4624 → benign."""
        row: dict[str, Any] = {"src_ip": "::1", "event_id": "4624"}
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_non_loopback_4648_false() -> None:
        """src_ip=10.0.0.5, event_id=4648 → NOT benign."""
        row: dict[str, Any] = {"src_ip": "10.0.0.5", "event_id": "4648"}
        assert is_benign_local_auth(row) is False

    @staticmethod
    def test_subject_machine_account_on_loopback_true() -> None:
        """subject=WIN-D9RGPJQ68G8$, src_ip=127.0.0.1 → benign."""
        row: dict[str, Any] = {
            "src_ip": "127.0.0.1",
            "subject_user": "WIN-D9RGPJQ68G8$",
            "event_id": "4648",
        }
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_lsass_on_loopback_true() -> None:
        """process=lsass.exe, src_ip=127.0.0.1 → benign."""
        row: dict[str, Any] = {
            "src_ip": "127.0.0.1",
            "process_name": "lsass.exe",
            "event_id": "4624",
        }
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_winlogon_on_loopback_true() -> None:
        """process=winlogon.exe, src_ip=localhost → benign."""
        row: dict[str, Any] = {
            "src_ip": "localhost",
            "process_name": "winlogon.exe",
            "event_id": "4624",
        }
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_loopback_src_ip_none_true() -> None:
        """src_ip=None, event_id=4648 → benign."""
        row: dict[str, Any] = {"src_ip": None, "event_id": "4648"}
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_dash_src_ip_4648_true() -> None:
        """src_ip=-, event_id=4648 → benign."""
        row: dict[str, Any] = {"src_ip": "-", "event_id": "4648"}
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_non_loopback_non_logon_false() -> None:
        """src_ip=192.168.1.1, event_id=4625 → NOT benign (logon failure,
        not loopback)."""
        row: dict[str, Any] = {"src_ip": "192.168.1.1", "event_id": "4625"}
        assert is_benign_local_auth(row) is False

    @staticmethod
    def test_loopback_wrong_event_id_false() -> None:
        """src_ip=127.0.0.1, event_id=4625 → NOT benign (failure logon,
        not 4624/4648)."""
        row: dict[str, Any] = {"src_ip": "127.0.0.1", "event_id": "4625"}
        assert is_benign_local_auth(row) is False

    @staticmethod
    def test_non_loopback_machine_account_false() -> None:
        """subject=PC$, src_ip=10.0.0.5 → NOT benign (non-loopback)."""
        row: dict[str, Any] = {
            "src_ip": "10.0.0.5",
            "subject_user": "PC$", "event_id": "4648",
        }
        assert is_benign_local_auth(row) is False

    @staticmethod
    def test_lsass_non_loopback_false() -> None:
        """process=lsass.exe, src_ip=10.0.0.5 → NOT benign."""
        row: dict[str, Any] = {
            "src_ip": "10.0.0.5",
            "process_name": "lsass.exe",
        }
        assert is_benign_local_auth(row) is False

    @staticmethod
    def test_empty_row_false() -> None:
        """Empty row → NOT benign."""
        assert is_benign_local_auth({}) is False

    @staticmethod
    def test_loopback_value_none_true() -> None:
        """src_ip='None' (string), event_id=4648 → benign."""
        row: dict[str, Any] = {"src_ip": "None", "event_id": "4648"}
        assert is_benign_local_auth(row) is True

    @staticmethod
    def test_empty_src_ip_4648_true() -> None:
        """src_ip='', event_id=4648 → benign."""
        row: dict[str, Any] = {"src_ip": "", "event_id": "4648"}
        assert is_benign_local_auth(row) is True


# ====================================================================
# tag_benign_local_auth_findings (integration with real CaseDB)
# ====================================================================


class TestTagBenignLocalAuthFindings:
    """Integration tests for tag_benign_local_auth_findings()."""

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _insert_finding(
        db: CaseDB,
        finding_id: str,
        evidence_rows: list[dict[str, Any]],
        existing_tags: list[str] | None = None,
    ) -> None:
        db.execute(
            """
            INSERT INTO findings (finding_id, rule_id, title, severity, confidence,
                                  status, tags, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, now())
            """,
            (
                finding_id,
                "rule-test",
                "test finding",
                "high",
                0.9,
                "accepted",
                json.dumps(existing_tags or []),
                json.dumps(evidence_rows),
            ),
        )

    # ------------------------------------------------------------------
    # tests
    # ------------------------------------------------------------------

    def test_all_benign_rows_tagged(self) -> None:
        """Finding where ALL evidence rows are benign → tag appended."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._insert_finding(
                    db,
                    "f-001",
                    evidence_rows=[
                        {"src_ip": "127.0.0.1", "event_id": "4648"},
                        {"src_ip": "127.0.0.1", "subject_user": "PC$", "event_id": "4648"},
                    ],
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 1

                rows = db.execute(
                    "SELECT tags FROM findings WHERE finding_id = ?",
                    ("f-001",),
                ).fetchall()
                tags = json.loads(rows[0][0])
                assert "benign-context:loopback-local-auth" in tags

    def test_not_tagged_when_mixed(self) -> None:
        """Finding with a non-benign evidence row → NOT tagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._insert_finding(
                    db,
                    "f-002",
                    evidence_rows=[
                        {"src_ip": "127.0.0.1", "event_id": "4648"},
                        {"src_ip": "10.0.0.5", "event_id": "4648"},
                    ],
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 0

                rows = db.execute(
                    "SELECT tags FROM findings WHERE finding_id = ?",
                    ("f-002",),
                ).fetchall()
                tags = json.loads(rows[0][0])
                assert "benign-context:loopback-local-auth" not in tags

    def test_preserves_existing_tags(self) -> None:
        """Existing tags are preserved; new tag is appended."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._insert_finding(
                    db,
                    "f-003",
                    evidence_rows=[
                        {"src_ip": "127.0.0.1", "event_id": "4648"},
                    ],
                    existing_tags=["existing-tag"],
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 1

                rows = db.execute(
                    "SELECT tags FROM findings WHERE finding_id = ?",
                    ("f-003",),
                ).fetchall()
                tags = json.loads(rows[0][0])
                assert "existing-tag" in tags
                assert "benign-context:loopback-local-auth" in tags

    def test_skips_when_already_tagged(self) -> None:
        """Finding already having benign-context:loopback-local-auth → skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._insert_finding(
                    db,
                    "f-004",
                    evidence_rows=[
                        {"src_ip": "127.0.0.1", "event_id": "4648"},
                    ],
                    existing_tags=["benign-context:loopback-local-auth"],
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 0  # already tagged

    def test_no_evidence_finding_skipped(self) -> None:
        """Finding with NULL evidence → skipped (count unchanged)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (finding_id, rule_id, title, severity,
                                          confidence, status, tags, evidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, now())
                    """,
                    (
                        "f-005",
                        "rule-test",
                        "no evidence",
                        "high",
                        0.9,
                        "accepted",
                        "[]",
                        None,
                    ),
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 0

    @staticmethod
    def test_only_one_finding_tagged_when_one_matches() -> None:
        """Only findings with all-benign evidence are tagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                # benign
                TestTagBenignLocalAuthFindings._insert_finding(
                    db,
                    "f-006",
                    evidence_rows=[
                        {"src_ip": "127.0.0.1", "event_id": "4648"},
                    ],
                )
                # non-benign
                TestTagBenignLocalAuthFindings._insert_finding(
                    db,
                    "f-007",
                    evidence_rows=[
                        {"src_ip": "10.0.0.5", "event_id": "4648"},
                    ],
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 1

                rows = db.execute(
                    "SELECT finding_id FROM findings WHERE tags LIKE '%benign-context:loopback-local-auth%'",
                ).fetchall()
                tagged_ids = {r[0] for r in rows}
                assert tagged_ids == {"f-006"}

# ====================================================================
# Real-data shape: evidence rows without event_id (auth rules that
# filter on event_id but do not SELECT it). Mirrors the 2026-07-05
# dist/cfreds run where benign 4648 findings led top_findings because
# their evidence rows carried no event_id column. (H-1)
# ====================================================================


class TestFindingIsAuthScoped:
    def test_rule_id_naming_auth_event(self) -> None:
        assert finding_is_auth_scoped(
            "windows-security-4648-logon-explicit-creds", ""
        )

    def test_title_naming_auth_event(self) -> None:
        assert finding_is_auth_scoped(
            "some-rule", "Logon attempt with explicit credentials (4648): PC$ -> user"
        )

    def test_non_auth_finding_not_scoped(self) -> None:
        assert not finding_is_auth_scoped(
            "windows-finding-antiforensic-tools", "Anti-forensic tool: CCLEANER.EXE"
        )

    def test_substring_digits_do_not_false_match(self) -> None:
        # 14648 / 46480 must not match the 4648 auth id.
        assert not finding_is_auth_scoped("id-14648-x", "count 46480 things")


class TestBenignDetectionWithoutEventIdColumn:
    """The real-data failure: evidence rows lack event_id."""

    _EVIDENCE_NO_EID = {
        "computer": "informant-PC",
        "target_user": "informant",
        "subject_user": "INFORMANT-PC$",
        "src_ip": "127.0.0.1",
        "process_name": "C:\\Windows\\System32\\winlogon.exe",
    }

    def test_not_benign_without_assume(self) -> None:
        assert not is_benign_local_auth(self._EVIDENCE_NO_EID)

    def test_benign_with_assume_auth_event(self) -> None:
        assert is_benign_local_auth(
            self._EVIDENCE_NO_EID, assume_auth_event=True
        )

    def test_present_non_auth_event_id_still_rejected(self) -> None:
        row = {**self._EVIDENCE_NO_EID, "event_id": "4688"}
        assert not is_benign_local_auth(row, assume_auth_event=True)

    def test_loopback_machine_account_benign_even_if_name_differs(self) -> None:
        """A renamed host / base-image machine account authenticating to
        itself over loopback is benign — lateral movement cannot present as a
        127.0.0.1 source (mirrors dist/cfreds WIN-D9RGPJQ68G8$ -> informant)."""
        row = {**self._EVIDENCE_NO_EID, "subject_user": "WIN-D9RGPJQ68G8$"}
        assert is_benign_local_auth(row, assume_auth_event=True)

    def test_non_loopback_cross_host_machine_account_not_benign(self) -> None:
        """A different host's machine account over a real IP is a
        lateral-movement signal, not benign."""
        row = {
            **self._EVIDENCE_NO_EID,
            "subject_user": "OTHER-PC$",
            "src_ip": "10.0.0.5",
        }
        assert not is_benign_local_auth(row, assume_auth_event=True)

    def test_tag_pass_uses_finding_scope(self) -> None:
        """The tagging pass must tag a 4648 finding whose evidence has no
        event_id, using the finding's auth-scoped rule_id/title."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (finding_id, rule_id, title, severity,
                        confidence, status, tags, evidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, now())
                    """,
                    (
                        "windows-security-4648-logon-explicit-creds-0015",
                        "windows-security-4648-logon-explicit-creds",
                        "Logon attempt with explicit credentials (4648): "
                        "INFORMANT-PC$ -> informant",
                        "high",
                        0.75,
                        "accepted",
                        json.dumps([]),
                        json.dumps([self._EVIDENCE_NO_EID]),
                    ),
                )
                count = tag_benign_local_auth_findings(db)
                assert count == 1
                tags = json.loads(
                    db.execute(
                        "SELECT tags FROM findings WHERE finding_id = ?",
                        ("windows-security-4648-logon-explicit-creds-0015",),
                    ).fetchall()[0][0]
                )
                assert "benign-context:loopback-local-auth" in tags
