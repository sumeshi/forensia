"""Behavioral tests for local-auth classification."""

from __future__ import annotations

import json
import unittest

from forensia.report.benign_auth import (
    finding_is_auth_scoped,
    is_benign_local_auth,
    normalise_ip,
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
                self.assertEqual(expected, normalise_ip(value))

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
                event_id = row.get("event_id")
                contextual = {
                    **row,
                    "channel": "Security",
                    "raw_json": json.dumps(
                        {
                            "winlog": {
                                "provider": {
                                    "name": "Microsoft-Windows-Security-Auditing"
                                }
                            }
                        }
                    ),
                }
                self.assertIs(
                    expected,
                    is_benign_local_auth(contextual if event_id else row),
                )

    def test_missing_or_mismatched_context_cannot_be_assumed_from_finding(self) -> None:
        base = {
            "computer": "informant-PC",
            "target_user": "informant",
            "subject_user": "INFORMANT-PC$",
            "src_ip": "127.0.0.1",
            "process_name": r"C:\Windows\System32\winlogon.exe",
        }
        self.assertFalse(is_benign_local_auth(base))
        self.assertTrue(finding_is_auth_scoped("windows-security-4648-logon", ""))
        self.assertFalse(
            is_benign_local_auth(
                {
                    **base,
                    "event_id": "4648",
                    "channel": "Application",
                    "raw_json": '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                }
            )
        )
        self.assertFalse(
            is_benign_local_auth(
                {
                    **base,
                    "event_id": "4648",
                    "channel": "Security",
                }
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
