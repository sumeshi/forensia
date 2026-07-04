"""Tests for report aggregation consistency (RPT-03, RPT-04).

Why this matters: the report's Key Findings table (Overview) and Action Plan
table (Recommendations) must report the same `(N)` count for a given finding
theme. Before this fix they came from two independently-filtered queries and
could disagree (e.g. "Explicit credential usage observed (3)" vs "(15)" for
the same case). These tests pin a single-source theme count and a
top-findings ranking that demotes routine local machine-account 4648 events
and removes exact duplicate finding titles.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.probes import (
    _antiforensic_rows,
    _build_recommendations_table,
    _finding_theme_counts,
    _query_top_findings,
    _signal_finding_rows,
)
from forensia.report.ranking import (
    audit_packaged_report_templates,
    load_top_findings_priority_keywords,
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
            r
            for r in key_findings
            if "Explicit credential usage observed" in r["finding"]
        )
        action_plan_row = next(
            r
            for r in action_plan
            if "Explicit credential usage observed" in r["action"]
        )
        self.assertIn("(5)", key_findings_row["finding"])
        self.assertIn("(5)", action_plan_row["action"])


class TestActionPlanIsClientFacing(unittest.TestCase):
    """P-7: the Action Plan carries forensic recommendations only.

    Tool-side investigation bookkeeping (triaging open hypotheses, reviewing
    automatic benign downgrades) is not client-facing advice. It must stay out
    of the Action Plan even when the case has open hypotheses and
    benign-tagged findings — open hypotheses already surface in the Gap
    Assessment tables.
    """

    def test_no_investigation_ops_rows_in_action_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (hypothesis_id, description, status)
                    VALUES ('H-001', 'unfinished lateral movement hypothesis', 'active')
                    """
                )
                _insert_finding(
                    db,
                    finding_id="windows-security-4648-logon-explicit-creds-0001",
                    rule_id="windows-security-4648-logon-explicit-creds",
                    title="Logon attempt with explicit credentials (4648): HOST-A$ -> HOST-A$",
                    tags=["benign-context:loopback-local-auth"],
                    evidence=[{"evidence_id": "evtx-1", "computer": "HOST-A"}],
                )
                rows = _build_recommendations_table(db)

        for row in rows:
            text = " ".join(
                str(row.get(key) or "") for key in ("action", "rationale")
            ).lower()
            self.assertNotIn("hypothes", text)
            self.assertNotIn("auto-downgraded", text)


class TestAntiforensicTableDeduplication(unittest.TestCase):
    """P-8: one on-disk artifact must appear as one antiforensic table row.

    The MFT commonly stores several records for the same file (8.3 short
    names, duplicate attribute records). Without deduplication these inflate
    the apparent count of anti-forensic artifacts.
    """

    def test_duplicate_mft_records_collapse_to_one_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for i in (234, 235):
                    db.execute(
                        """
                        INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            f"mft-{i}",
                            "C:\\Users\\informant\\Desktop\\ERASER.EXE",
                            "ERASER.EXE",
                            "2015-03-22 14:38:16",
                        ),
                    )
                rows = _antiforensic_rows(db)

        artifact_rows = [r for r in rows if r.get("type") == "tool artifact"]
        self.assertEqual(1, len(artifact_rows))
        self.assertEqual("ERASER.EXE", artifact_rows[0].get("artifact"))


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
                                "src_ip": "127.0.0.1",
                                "event_id": "4648",
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
                            "src_ip": "10.0.0.5",
                            "event_id": "4648",
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
            if t
            == "Logon attempt with explicit credentials (4648): HOST-A$ -> informant"
        ]
        self.assertTrue(
            local_indices, "local machine-account finding should still appear"
        )
        self.assertLess(cross_host_index, min(local_indices))

        # Exact duplicate titles are collapsed to a single row.
        self.assertEqual(
            titles.count(
                "Logon attempt with explicit credentials (4648): HOST-A$ -> informant"
            ),
            1,
        )


class TestTopFindingsRankingIsCaseAgnostic(unittest.TestCase):
    """The report's leading thesis must not be biased toward the benchmark case.

    Why this matters: `top_findings` drives `report_brief.json`, which seeds the
    report's leading thesis (CLAUDE.md Rule 17). Ranking must therefore depend on
    case-agnostic finding attributes (severity, ATT&CK mapping, confidence), not
    on keywords specific to one case (e.g. "4648", "outlook", "ccleaner"). This
    test uses a ransomware-flavoured case with zero CFReDS vocabulary and asserts
    the most severe finding leads — and that a low-severity 4648 finding, which
    the old keyword ranking would have floated to the top, does not lead.
    """

    def _insert(self, db, *, finding_id, title, severity, confidence, attack):
        db.execute(
            """
            INSERT INTO findings
              (finding_id, rule_id, title, summary, severity, confidence, status, tags, evidence, attack)
            VALUES (?, ?, ?, '', ?, ?, 'accepted', '[]', '[]', ?)
            """,
            (finding_id, finding_id, title, severity, confidence, attack),
        )

    def test_most_severe_attack_mapped_finding_leads_without_keyword_bias(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Critical, ATT&CK-mapped, no CFReDS keywords -> must lead.
                self._insert(
                    db,
                    finding_id="ransomware-mass-encryption-0001",
                    title="Mass file encryption consistent with ransomware",
                    severity="critical",
                    confidence=0.85,
                    attack=json.dumps([{"tactic": "impact", "technique": "T1486"}]),
                )
                # High severity persistence, also no CFReDS keywords.
                self._insert(
                    db,
                    finding_id="persistence-scheduled-task-0001",
                    title="Suspicious scheduled task created for persistence",
                    severity="high",
                    confidence=0.8,
                    attack=json.dumps(
                        [{"tactic": "persistence", "technique": "T1053"}]
                    ),
                )
                # A 4648 finding the OLD ranking hard-coded to rank 0 (top). It is
                # only medium severity here, so a case-agnostic ranking must keep
                # it below the critical/high findings above.
                self._insert(
                    db,
                    finding_id="windows-security-4648-logon-explicit-creds-0001",
                    title="Logon attempt with explicit credentials (4648)",
                    severity="medium",
                    confidence=0.7,
                    attack="[]",
                )

                top = _query_top_findings(db, 8)

        titles = [item["title"] for item in top]
        self.assertEqual(titles[0], "Mass file encryption consistent with ransomware")
        four648_index = titles.index("Logon attempt with explicit credentials (4648)")
        # The low-severity 4648 finding must rank below both higher-severity ones,
        # proving the leading thesis is no longer keyword-biased toward CFReDS.
        self.assertEqual(four648_index, len(titles) - 1)


class TestTopFindingsRankingPolicyFromTemplate(unittest.TestCase):
    """The leading-thesis ordering policy must come from the Markdown templates.

    Why this matters: different cases want different leading orders (a data-
    exfiltration narrative vs a plain severity order). That policy must be
    swappable by swapping templates, not hard-coded in core. A reader of the
    overview template's frontmatter should be able to see and change how that
    section orders its findings, and the case-specific vocabulary must live in the
    template, never in core or the packaged generic templates.
    """

    _OVERVIEW_WITH_POLICY = (
        "---\n"
        "behaviors:\n"
        "  - canonical_evidence_scope\n"
        "brief:\n"
        "  top_findings:\n"
        "    ranking:\n"
        "      policy: priority_keywords\n"
        "      priority_keywords:\n"
        '        - ["4648", "explicit credential"]\n'
        "---\n"
        "# Investigation Overview\n"
    )

    def _insert(self, db, *, finding_id, title, severity):
        db.execute(
            """
            INSERT INTO findings
              (finding_id, rule_id, title, summary, severity, confidence, status, tags, evidence, attack)
            VALUES (?, ?, ?, '', ?, 0.7, 'accepted', '[]', '[]', '[]')
            """,
            (finding_id, finding_id, title, severity),
        )

    def _write_template(self, tmpdir: str, name: str, text: str) -> Path:
        tdir = Path(tmpdir) / "templates"
        tdir.mkdir(exist_ok=True)
        (tdir / name).write_text(text, encoding="utf-8")
        return tdir

    def test_overview_frontmatter_drives_ranking_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # A high-severity finding the generic default ranks first.
                self._insert(
                    db,
                    finding_id="ransomware-mass-encryption-0001",
                    title="Mass file encryption consistent with ransomware",
                    severity="critical",
                )
                # A lower-severity finding a narrative policy wants to lead with.
                self._insert(
                    db,
                    finding_id="windows-security-4648-logon-explicit-creds-0001",
                    title="Logon attempt with explicit credentials (4648)",
                    severity="medium",
                )

                # Core default (no policy): severity wins.
                default_titles = [r["title"] for r in _query_top_findings(db)]

                # Policy declared in the overview template's frontmatter: the 4648
                # narrative tier leads despite being lower severity.
                tdir = self._write_template(
                    tmpdir, "1_overview.md", self._OVERVIEW_WITH_POLICY
                )
                keywords = load_top_findings_priority_keywords(tdir)
                policy_titles = [
                    r["title"]
                    for r in _query_top_findings(db, priority_keywords=keywords)
                ]

        self.assertEqual(
            default_titles[0], "Mass file encryption consistent with ransomware"
        )
        self.assertEqual(
            policy_titles[0], "Logon attempt with explicit credentials (4648)"
        )

    def test_template_without_policy_yields_no_keywords(self):
        # A template set that declares no ranking (only behaviors) must NOT pull
        # in any benchmark ranking — core stays on its severity default.
        with tempfile.TemporaryDirectory() as tmpdir:
            tdir = self._write_template(
                tmpdir,
                "1_overview.md",
                "---\nbehaviors:\n  - canonical_evidence_scope\n---\n# Overview\n",
            )
            self.assertIsNone(load_top_findings_priority_keywords(tdir))
            # Explicit severity policy is also a no-op (use default).
            self._write_template(
                tmpdir,
                "1_overview.md",
                "---\nbrief:\n  top_findings:\n    ranking:\n      policy: severity\n---\n# Overview\n",
            )
            self.assertIsNone(load_top_findings_priority_keywords(tdir))

    def test_malformed_policy_warns_and_falls_back(self):
        # A declared-but-malformed policy must not silently degrade: it warns and
        # falls back to the default (the doctor gate is the hard check).
        with tempfile.TemporaryDirectory() as tmpdir:
            tdir = self._write_template(
                tmpdir,
                "1_overview.md",
                "---\nbrief:\n  top_findings:\n    ranking:\n      policy: priority_keywords\n---\n# Overview\n",
            )
            with self.assertWarns(UserWarning):
                self.assertIsNone(load_top_findings_priority_keywords(tdir))

    def test_packaged_templates_carry_no_case_specific_policy(self):
        # The doctor gate: bundled generic templates must parse and must not
        # smuggle in a case-specific priority_keywords policy.
        self.assertEqual(audit_packaged_report_templates(), [])


if __name__ == "__main__":
    unittest.main()
