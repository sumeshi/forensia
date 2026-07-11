"""Behavioral tests for local-auth classification and finding tagging."""

from __future__ import annotations

import json
import tempfile
import unittest
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

BENIGN_TAG = "benign-context:loopback-local-auth"


def _insert_finding(
    db: CaseDB,
    finding_id: str,
    evidence: list[dict[str, Any]] | None,
    *,
    tags: list[str] | None = None,
    rule_id: str = "rule-test",
    title: str = "test finding",
) -> None:
    db.execute(
        """
        INSERT INTO findings (
            finding_id, rule_id, title, severity, confidence, status, tags,
            evidence, created_at
        ) VALUES (?, ?, ?, 'high', 0.9, 'accepted', ?, ?, now())
        """,
        (
            finding_id,
            rule_id,
            title,
            json.dumps(tags or []),
            json.dumps(evidence) if evidence is not None else None,
        ),
    )


class LocalAuthClassificationTests(unittest.TestCase):
    def test_ip_normalization_matrix(self) -> None:
        for value, expected in (
            (None, ""),
            ("", ""),
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "::1"),
            ("  LOCALHOST  ", "localhost"),
            ("-", "-"),
        ):
            with self.subTest(value=value):
                self.assertEqual(expected, _normalise_ip(value))

    def test_local_auth_decision_matrix(self) -> None:
        cases = (
            ({"src_ip": "127.0.0.1", "event_id": "4648"}, True),
            ({"src_ip": "::1", "event_id": "4624"}, True),
            (
                {
                    "src_ip": "localhost",
                    "process_name": "winlogon.exe",
                    "event_id": "4624",
                },
                True,
            ),
            ({"src_ip": None, "event_id": "4648"}, True),
            ({"src_ip": "None", "event_id": "4648"}, True),
            ({"src_ip": "-", "event_id": "4648"}, True),
            ({"src_ip": "", "event_id": "4648"}, True),
            ({"src_ip": "10.0.0.5", "event_id": "4648"}, False),
            ({"src_ip": "127.0.0.1", "event_id": "4625"}, False),
            ({"src_ip": "10.0.0.5", "subject_user": "PC$", "event_id": "4648"}, False),
            ({"src_ip": "10.0.0.5", "process_name": "lsass.exe"}, False),
            ({}, False),
        )
        for row, expected in cases:
            with self.subTest(row=row):
                self.assertIs(expected, is_benign_local_auth(row))

    def test_missing_event_id_requires_auth_scope_assumption(self) -> None:
        base = {
            "computer": "informant-PC",
            "target_user": "informant",
            "subject_user": "INFORMANT-PC$",
            "src_ip": "127.0.0.1",
            "process_name": r"C:\Windows\System32\winlogon.exe",
        }
        self.assertFalse(is_benign_local_auth(base))
        self.assertTrue(is_benign_local_auth(base, assume_auth_event=True))
        self.assertFalse(
            is_benign_local_auth({**base, "event_id": "4688"}, assume_auth_event=True)
        )
        self.assertFalse(
            is_benign_local_auth(
                {**base, "subject_user": "OTHER-PC$", "src_ip": "10.0.0.5"},
                assume_auth_event=True,
            )
        )


class FindingScopeTests(unittest.TestCase):
    def test_auth_scope_matrix(self) -> None:
        cases = (
            ("windows-security-4648-logon-explicit-creds", "", True),
            ("some-rule", "Logon with explicit credentials (4648)", True),
            ("windows-finding-antiforensic-tools", "CCLEANER.EXE", False),
            ("id-14648-x", "count 46480 things", False),
        )
        for rule_id, title, expected in cases:
            with self.subTest(rule_id=rule_id):
                self.assertIs(expected, finding_is_auth_scoped(rule_id, title))


class FindingTaggingTests(unittest.TestCase):
    def test_tags_only_untagged_findings_with_all_benign_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(Path(tmpdir) / "case")) as db:
                _insert_finding(
                    db,
                    "benign",
                    [{"src_ip": "127.0.0.1", "event_id": "4648"}],
                    tags=["existing"],
                )
                _insert_finding(
                    db,
                    "mixed",
                    [
                        {"src_ip": "127.0.0.1", "event_id": "4648"},
                        {"src_ip": "10.0.0.5", "event_id": "4648"},
                    ],
                )
                _insert_finding(
                    db,
                    "already-tagged",
                    [{"src_ip": "127.0.0.1", "event_id": "4648"}],
                    tags=[BENIGN_TAG],
                )
                _insert_finding(db, "no-evidence", None)

                self.assertEqual(1, tag_benign_local_auth_findings(db))
                rows = dict(
                    db.execute("SELECT finding_id, tags FROM findings").fetchall()
                )

        self.assertEqual({"existing", BENIGN_TAG}, set(json.loads(rows["benign"])))
        self.assertNotIn(BENIGN_TAG, json.loads(rows["mixed"]))
        self.assertEqual([BENIGN_TAG], json.loads(rows["already-tagged"]))

    def test_tagging_uses_finding_scope_when_evidence_omits_event_id(self) -> None:
        evidence = {
            "computer": "informant-PC",
            "target_user": "informant",
            "subject_user": "INFORMANT-PC$",
            "src_ip": "127.0.0.1",
            "process_name": r"C:\Windows\System32\winlogon.exe",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(Path(tmpdir) / "case")) as db:
                _insert_finding(
                    db,
                    "auth-without-event-id",
                    [evidence],
                    rule_id="windows-security-4648-logon-explicit-creds",
                    title="Logon attempt with explicit credentials (4648)",
                )
                self.assertEqual(1, tag_benign_local_auth_findings(db))
                tags = json.loads(
                    db.execute(
                        "SELECT tags FROM findings WHERE finding_id = 'auth-without-event-id'"
                    ).fetchone()[0]
                )
        self.assertIn(BENIGN_TAG, tags)
