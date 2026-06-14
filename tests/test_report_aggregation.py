"""Tests for report aggregation consistency (RPT-03, RPT-04).

Why this matters: the report's Key Findings table (Overview) and Action Plan
table (Recommendations) must report the same `(N件)` count for a given finding
theme. Before this fix they came from two independently-filtered queries and
could disagree (e.g. "明示的資格情報利用の観測 (3件)" vs "(15件)" for the same
case). These tests pin a single-source theme count and a top-findings ranking
that demotes routine local machine-account 4648 events and removes exact
duplicate finding titles.
"""

from __future__ import annotations

import json
import tempfile
import unittest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.probes import (
    _build_recommendations_table,
    _finding_theme_counts,
    _query_top_findings,
    _signal_finding_rows,
)


def _insert_finding(
    db: CaseDB,
    *,
    finding_id: str,
    rule_id: str,
    title: str,
    severity: str = "high",
    confidence: float = 0.75,
    tags: list[str] | None = None,
    evidence: list[dict] | None = None,
) -> None:
    db.execute(
        """
        INSERT INTO findings (finding_id, rule_id, title, summary, severity, confidence, status, tags, evidence)
        VALUES (?, ?, ?, '', ?, ?, 'accepted', ?, ?)
        """,
        (
            finding_id,
            rule_id,
            title,
            severity,
            confidence,
            json.dumps(tags or []),
            json.dumps(evidence or []),
        ),
    )


class TestFindingThemeCountsConsistency(unittest.TestCase):
    """RPT-03: Key Findings and Action Plan must read the same theme counts."""

    def test_theme_counts_match_across_key_findings_and_action_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # 5 explicit-credential (4648) findings, all eligible.
                for i in range(5):
                    _insert_finding(
                        db,
                        finding_id=f"windows-security-4648-logon-explicit-creds-{i:04d}",
                        rule_id="windows-security-4648-logon-explicit-creds",
                        title=f"Logon attempt with explicit credentials (4648): user{i} -> target{i}",
                        evidence=[
                            {
                                "evidence_id": f"evtx-{i}",
                                "computer": "HOST-A",
                                "subject_user": f"user{i}",
                                "target_user": f"target{i}",
                            }
                        ],
                    )
                # 1 benign-context-tagged 4648 finding should not be counted.
                _insert_finding(
                    db,
                    finding_id="windows-security-4648-logon-explicit-creds-0099",
                    rule_id="windows-security-4648-logon-explicit-creds",
                    title="Logon attempt with explicit credentials (4648): svc -> svc",
                    tags=["benign-context:service-account"],
                    evidence=[{"evidence_id": "evtx-99", "computer": "HOST-A"}],
                )

                theme_counts = _finding_theme_counts(db)
                self.assertEqual(theme_counts.get("explicit_credentials"), 5)

                key_findings = _signal_finding_rows(db, 8)
                action_plan = _build_recommendations_table(db)

        key_findings_row = next(
            r for r in key_findings if "明示的資格情報利用の観測" in r["finding"]
        )
        action_plan_row = next(
            r for r in action_plan if "明示的資格情報利用の観測" in r["action"]
        )
        self.assertIn("(5件)", key_findings_row["finding"])
        self.assertIn("(5件)", action_plan_row["action"])


class TestLocalMachineAccount4648Demotion(unittest.TestCase):
    """RPT-04: self-host machine-account 4648 should not top the rankings,
    and exact duplicate finding titles must be collapsed."""

    def test_local_machine_account_4648_is_not_top_ranked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Routine local credential prompt: HOST-A$ authenticating on HOST-A.
                for i in range(5):
                    _insert_finding(
                        db,
                        finding_id=f"windows-security-4648-logon-explicit-creds-{i:04d}",
                        rule_id="windows-security-4648-logon-explicit-creds",
                        title="Logon attempt with explicit credentials (4648): HOST-A$ -> informant",
                        evidence=[
                            {
                                "evidence_id": f"evtx-local-{i}",
                                "computer": "HOST-A",
                                "subject_user": "HOST-A$",
                                "target_user": "informant",
                            }
                        ],
                    )
                # Genuine cross-host machine account: a different host's
                # machine account authenticating on HOST-A.
                _insert_finding(
                    db,
                    finding_id="windows-security-4648-logon-explicit-creds-0100",
                    rule_id="windows-security-4648-logon-explicit-creds",
                    title="Logon attempt with explicit credentials (4648): WIN-OTHERHOST$ -> informant",
                    evidence=[
                        {
                            "evidence_id": "evtx-remote-1",
                            "computer": "HOST-A",
                            "subject_user": "WIN-OTHERHOST$",
                            "target_user": "informant",
                        }
                    ],
                )

                top_findings = _query_top_findings(db, 8)

        titles = [item["title"] for item in top_findings]
        # The cross-host machine-account finding ranks above the self-host one.
        cross_host_index = titles.index(
            "Logon attempt with explicit credentials (4648): WIN-OTHERHOST$ -> informant"
        )
        local_indices = [
            i
            for i, t in enumerate(titles)
            if t == "Logon attempt with explicit credentials (4648): HOST-A$ -> informant"
        ]
        self.assertTrue(local_indices, "local machine-account finding should still appear")
        self.assertLess(cross_host_index, min(local_indices))

        # Exact duplicate titles are collapsed to a single row.
        self.assertEqual(
            titles.count(
                "Logon attempt with explicit credentials (4648): HOST-A$ -> informant"
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
