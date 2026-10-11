from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from hashlib import sha1
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.rules.engine import execute_event_keyword_fallback_search
from forensia.report.answers.keypoint_catalog import (
    default_keypoints_for_section,
    resolve_evidence_results,
)
from forensia.report.answers.table_registry import collect_flat_evidence_rows
from forensia.report.render.markdown import sort_markdown_table_by_first_column
from forensia.report.render.writer import build_report_markdown_from_db
from forensia.report.sections.quality_gates import quality_gate_section
from forensia.report.sections.report_input import (
    ReportSpecError,
    resolve_report_sources,
    section_source_from_path,
    sections_from_report_spec,
)
from forensia.report.sections.section_assembly import prepare_section_request
from forensia.report.sections.section_finalize import finalize_section
from forensia.report.sections.section_run_store import replace_section_evidence
from forensia.report.template_export import export_packaged_report_templates


class SectionFinalizeTests(unittest.TestCase):
    """Section request assembly, quality gates, finalize_section, report markdown build."""

    def test_prepare_section_request_infers_section_evidence_without_template_keypoints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "1_overview.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                "# Overview\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "ev-1",
                        "a.evtx",
                        "Security",
                        4624,
                        1,
                        "host1",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "{}",
                        "[]",
                        "info",
                    ),
                )
                request = prepare_section_request(
                    case,
                    db,
                    section_source_from_path(template_path),
                    {},
                    report_brief={},
                )
                # Verify default keypoint selection and resolver directly.
                default_keypoints = default_keypoints_for_section("1_overview")
                resolved = resolve_evidence_results(db, keypoints=default_keypoints)

            self.assertEqual("1_overview", request["section_key"])
            result_names = {item["keypoint"] for item in resolved}
            self.assertIn("overview_top_findings", result_names)

    def test_prepare_section_request_infers_ioc_keypoints_from_section_name(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "3_technical.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                "# Technical\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        target_user, process_name, command_line, src_ip, severity
                    ) VALUES
                        ('ev-1', 'a.evtx', 'Security', 4688, 1, now(), 'host1', 'user1', 'powershell.exe', '-enc AQBkAC...', NULL, 'high'),
                        ('ev-2', 'a.evtx', 'Security', 4624, 2, now(), 'host1', 'user1', NULL, NULL, '10.0.0.1', 'info'),
                        ('ev-3', 'a.evtx', 'Security', 4624, 3, now(), 'host1', 'user2', NULL, NULL, '10.0.0.2', 'info')
                    """
                )
                prepare_section_request(
                    case,
                    db,
                    section_source_from_path(template_path),
                    {},
                    report_brief={},
                )
                default_keypoints = default_keypoints_for_section("3_technical")
                resolved = resolve_evidence_results(db, keypoints=default_keypoints)

            results = {item["keypoint"]: item for item in resolved}
            self.assertIn("host_execution_activity", results)
            self.assertIn("account_logon_patterns", results)
            self.assertIn("ioc_source_ips", results)
            self.assertEqual(
                "powershell.exe",
                results["host_execution_activity"]["sample_rows"][0]["process_name"],
            )
            self.assertGreater(results["ioc_source_ips"]["row_count"], 0)

    def test_prepare_section_request_extracts_block_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "6_appendix.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                (
                    "# Appendix\n\n"
                    "## 8. E-mail data files\n"
                    "<!-- question: Where is the e-mail file located? -->\n"
                    "<!-- mode: structured -->\n"
                    "<!-- answer_id: Q20 -->\n"
                    "<!-- answer_spec: email_data_files -->\n"
                    "<!-- evidence_keypoints: ioc_email_ost_files, timeline_prefetch_history -->\n"
                    "<!-- fill -->\n"
                ),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                request = prepare_section_request(
                    case,
                    db,
                    section_source_from_path(template_path),
                    {},
                    report_brief={},
                )

            block = request["block_requests"][0]
            self.assertEqual("structured", block["mode"])
            self.assertEqual("Q20", block["answer_id"])
            self.assertEqual("email_data_files", block["answer_spec"])
            self.assertEqual("Where is the e-mail file located?", block["question"])
            self.assertEqual(
                ["ioc_email_ost_files", "timeline_prefetch_history"],
                block["evidence_keypoints"],
            )

    def test_report_md_normalizes_onto_the_template_section_contract(self) -> None:
        """V2-06: a case REPORT.md is the report input entry; ``#`` headings become
        sections (stable ``NN_<slug>`` keys from heading text + document order),
        ``##`` blocks keep the existing hint contract, and file frontmatter
        instructions apply to every section derived from the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            report_spec = case.path / "REPORT.md"
            report_spec.write_text(
                "---\ninstructions: |\n  Write for incident responders.\n---\n"
                "# Investigation Overview\n\n"
                "## Executive Summary\n<!-- mode: narrative; summarize the case -->\n"
                "# Timeline\n\n"
                "## Chronology\n<!-- question: When did lateral movement happen? -->\n"
                "<!-- mode: structured -->\n",
                encoding="utf-8",
            )
            # Default entry resolution (no explicit path): the case REPORT.md
            # beats the seeded template directory.
            sources = resolve_report_sources(case, None)
            self.assertEqual(
                ["01_investigation_overview", "02_timeline"],
                [source.section_key for source in sources],
            )
            # Section keys are stable across re-runs of the same input.
            self.assertEqual(
                [source.section_key for source in sources],
                [
                    source.section_key
                    for source in sections_from_report_spec(report_spec)
                ],
            )
            self.assertEqual(
                "Write for incident responders.", sources[1].meta.instructions
            )
            with CaseDB(case) as db:
                requests = [
                    prepare_section_request(case, db, source, {}, report_brief={})
                    for source in sources
                ]
            self.assertEqual("Investigation Overview", requests[0]["title"])
            first_block = requests[0]["block_requests"][0]
            self.assertEqual("Executive Summary", first_block["heading"])
            self.assertEqual("narrative", first_block["mode"])
            timeline_block = requests[1]["block_requests"][0]
            self.assertEqual("structured", timeline_block["mode"])
            self.assertEqual(
                "When did lateral movement happen?", timeline_block["question"]
            )

    def test_report_md_rejects_duplicate_section_headings_explicitly(self) -> None:
        """V2-06: duplicate headings never merge ambiguously into one section key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            report_spec = case.path / "REPORT.md"
            report_spec.write_text(
                "# Raw Evidence\n\n## Disk A\n\n# Raw Evidence\n\n## Disk B\n",
                encoding="utf-8",
            )
            with self.assertRaises(ReportSpecError) as caught:
                sections_from_report_spec(report_spec)
            message = str(caught.exception)
            self.assertIn("duplicate section headings", message)
            self.assertIn("'raw_evidence'", message)
            self.assertIn("#1 and #2", message)
            # The explicit flag beats the duplicate default without side effects.
            explicit = Path(tmpdir) / "spec.md"
            explicit.write_text("# Overview\n\n## Summary\n", encoding="utf-8")
            sources = resolve_report_sources(
                case, case.report_template_dir, report_spec=explicit
            )
            self.assertEqual(["01_overview"], [s.section_key for s in sources])

    def test_question_marker_enables_structured_mode_without_explicit_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "6_appendix.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                ("# Appendix\n\n## Last shutdown\n<!-- question -->\n<!-- fill -->\n"),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                request = prepare_section_request(
                    case,
                    db,
                    section_source_from_path(template_path),
                    {},
                    report_brief={},
                )

            block = request["block_requests"][0]
            self.assertEqual("structured", block["mode"])
            self.assertEqual("", block["answer_spec"])

    def test_quality_gate_flags_placeholder_entities_and_non_chronological_timeline(
        self,
    ) -> None:
        body = (
            "| Timestamp | Host | Stage | Event | evidence_id |\n"
            "|---|---|---|---|---|\n"
            "| 2026-05-16 10:00:00 | host1 | Login | user=None | ev-2 |\n"
            "| 2026-05-16 09:00:00 | host1 | Execution | process | ev-1 |\n"
        )

        gaps, confidence = quality_gate_section(
            "2_timeline",
            "Attack Timeline",
            body,
            [],
            1.0,
        )

        self.assertTrue(any("Placeholder entity values detected" in g for g in gaps))
        self.assertTrue(any("events are not strictly chronological" in g for g in gaps))
        self.assertLess(confidence, 1.0)

    def testcollect_flat_evidence_rows_filters_sparse_rows(self) -> None:
        rows = [
            {
                "kind": "rows",
                "sample_rows": [
                    {
                        "timestamp": "2026-05-28 10:00:00",
                        "event_id": 4624,
                        "process_name": "powershell.exe",
                        "message": "NULL",
                    },
                    {
                        "timestamp": None,
                        "event_id": None,
                        "process_name": None,
                        "message": None,
                    },
                ],
            }
        ]

        flat = collect_flat_evidence_rows(rows, min_filled_cols=0.5)
        self.assertEqual(1, len(flat))
        self.assertEqual("powershell.exe", flat[0]["process_name"])

    def test_finalize_section_flags_overstated_claims_for_non_confirmed_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "ev-1",
                        "a.evtx",
                        "Security",
                        4720,
                        1,
                        "host1",
                        "",
                        "alice",
                        "alice",
                        "admin",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "{}",
                        "[]",
                        "info",
                    ),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Technical",
                    body="## Account Creation\n\nThe attack was confirmed and compromised the host.",
                    evidence_results=[
                        {
                            "kind": "rows",
                            "source_verdict": "newlead",
                            "sample_rows": [{"event_id": 4720, "evidence_id": "ev-1"}],
                            "evidence_ids": ["ev-1"],
                            "finding_ids": [],
                            "hypothesis_ids": [],
                        }
                    ],
                )

                self.assertTrue(
                    any("cautious wording" in str(gap) for gap in result["gaps"]),
                    msg=f"Expected strength gap in {result['gaps']}",
                )

    def test_claims_use_current_adjudicated_evidence_roles(self) -> None:
        from forensia.core.verification import VerificationSpec
        from forensia.db.evidence_lookup import lookup_evidence_record
        from forensia.evidence.content_identity import fingerprint_from_record
        from forensia.evidence.links import verification_spec_fingerprint

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                evidence_rows = (
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        4624,
                    ),
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-000000000002",
                        7045,
                    ),
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-000000000003",
                        7036,
                    ),
                )
                for evidence_id, event_id in evidence_rows:
                    db.execute(
                        """
                        INSERT INTO evtx_events (
                            evidence_id, source_file, channel, event_id, record_id,
                            timestamp, computer, raw_json, tags, severity
                        ) VALUES (?, 'source.evtx', 'Security', ?, 1, now(),
                                  'host1', '{}', '[]', 'info')
                        """,
                        (evidence_id, event_id),
                    )

                spec = VerificationSpec()
                spec_json = json.dumps(spec.model_dump(mode="json"))
                spec_fingerprint = verification_spec_fingerprint(spec)
                for hypothesis_id, description, status in (
                    ("H-confirmed", "credential access", "confirmed"),
                    ("H-refuted", "lateral movement", "refuted"),
                ):
                    db.execute(
                        """INSERT INTO hypotheses (
                            hypothesis_id, description, status, verdict,
                            sufficiency_status, human_review_required,
                            verification_spec, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'sufficient', false, ?, now(), now())""",
                        [hypothesis_id, description, status, status, spec_json],
                    )
                link_roles = (
                    (
                        "L-support-current",
                        "H-confirmed",
                        evidence_rows[0][0],
                        "supporting",
                        "cf-current",
                    ),
                    (
                        "L-context-only",
                        "H-confirmed",
                        evidence_rows[1][0],
                        "contradictory",
                        "cf-context",
                    ),
                    (
                        "L-support-stale",
                        "H-confirmed",
                        evidence_rows[2][0],
                        "supporting",
                        "cf-stale",
                    ),
                    (
                        "L-refute-current",
                        "H-refuted",
                        evidence_rows[1][0],
                        "contradictory",
                        "cf-current",
                    ),
                    (
                        "L-refute-context",
                        "H-refuted",
                        evidence_rows[0][0],
                        "supporting",
                        "cf-context",
                    ),
                )
                for (
                    link_id,
                    hypothesis_id,
                    evidence_id,
                    role,
                    fingerprint,
                ) in link_roles:
                    live = lookup_evidence_record(db, evidence_id)
                    actual_fingerprint = fingerprint_from_record(live)
                    if fingerprint == "cf-current":
                        fingerprint = actual_fingerprint
                    elif fingerprint == "cf-stale":
                        fingerprint = "cf-stale-content"
                    db.execute(
                        """INSERT INTO hypothesis_evidence (
                            link_id, hypothesis_id, evidence_id, finding_id, assessment_id,
                            role, source_family, source_file, derivation_group,
                            content_fingerprint, verification_spec_fingerprint,
                            assessment_reason, matched_conditions, strength, created_at
                        ) VALUES (?, ?, ?, '', 'assessment-1', ?, 'evtx', 'source.evtx', ?, ?, ?,
                                  'matched declared condition', '[\"event_id\"]', 'strong', now())""",
                        [
                            link_id,
                            hypothesis_id,
                            evidence_id,
                            role,
                            evidence_id,
                            fingerprint,
                            spec_fingerprint,
                        ],
                    )

                # Prior projection values do not survive recomputation.
                for hypothesis_id in ("H-confirmed", "H-refuted"):
                    claim_id = sha1(
                        f"3_technical\0{hypothesis_id}".encode()
                    ).hexdigest()[:16]
                    db.execute(
                        """INSERT INTO claims (
                            claim_id, section_key, claim_text, support_status,
                            created_at, updated_at
                        ) VALUES (?, '3_technical', 'prior claim', 'needs_review', now(), now())""",
                        [claim_id],
                    )
                replace_section_evidence(
                    db,
                    "3_technical",
                    [
                        {
                            "kind": "rows",
                            "block_heading": "Account activity",
                            "source_ref": "table:technical_accounts",
                            "evidence_ids": [item[0] for item in evidence_rows],
                        }
                    ],
                )
                finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Technical",
                    body="## Account activity\n\nRelevant evidence was observed.",
                )
                claims = db.execute(
                    "SELECT hypothesis_ids, evidence_ids, support_status, claim_text FROM claims "
                    "WHERE section_key = '3_technical'"
                ).fetchall()

        projected = {
            json.loads(hypothesis_ids)[0]: (
                set(json.loads(evidence_ids)),
                support,
                claim_text,
            )
            for hypothesis_ids, evidence_ids, support, claim_text in claims
        }
        self.assertEqual({"H-confirmed", "H-refuted"}, set(projected))
        self.assertEqual({evidence_rows[0][0]}, projected["H-confirmed"][0])
        self.assertEqual("supported", projected["H-confirmed"][1])
        self.assertEqual({evidence_rows[1][0]}, projected["H-refuted"][0])
        self.assertEqual("supported", projected["H-refuted"][1])
        self.assertEqual(
            "Confirmed hypothesis: credential access", projected["H-confirmed"][2]
        )
        self.assertEqual(
            "Refuted hypothesis: lateral movement", projected["H-refuted"][2]
        )

    def test_execute_event_keyword_fallback_search_uses_event_id_keywords(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "ev-4720",
                        "a.evtx",
                        "Security",
                        4720,
                        1,
                        "host1",
                        "",
                        "alice",
                        "alice",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "account created for alice",
                        '{"message":"account created for alice"}',
                        "[]",
                        "info",
                    ),
                )
                rows, fallback_info = execute_event_keyword_fallback_search(
                    db,
                    "SELECT * FROM evtx_events WHERE event_id = 4720 AND computer = 'missing'",
                )

            self.assertEqual(1, len(rows))
            self.assertEqual("keyword_in_raw_json", fallback_info["phase"])
            self.assertIn(4720, fallback_info["event_ids"])
            self.assertTrue(
                any(
                    "account created" in keyword
                    for keyword in fallback_info["keywords"]
                )
            )

    def test_build_report_markdown_keeps_coverage_out_of_final_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at, stale
                    ) VALUES
                        ('1_overview', 'Overview', '# Investigation Overview\n\n## Evidence Scope\n\nOriginal scope text.\n', 0.9, 'ai_exhausted', 1, '[]', 's-1', now(), FALSE),
                        ('2_timeline', 'Timeline', '# Timeline\n\n**Status:** partial\n\nBody text with evidence_query reference.\n', 0.9, 'ai_exhausted', 1, '[]', 's-1', now(), FALSE)
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_runs (run_id, section_key, block_heading, iteration, phase, payload, verdict, created_at)
                    VALUES
                        ('run-1', '1_overview', 'Evidence Scope', 1, 'query', '{"source_kind":"keypoint","source_ref":"benchmark_ost_file","result":{"keypoint":"benchmark_ost_file","source_ref":"benchmark_ost_file","source_kind":"keypoint","kind":"rows","row_count":2}}', NULL, now()),
                        ('run-2', '2_timeline', 'Timeline', 1, 'query', '{"source_kind":"keypoint","source_ref":"benchmark_timeline_events","result":{"keypoint":"benchmark_timeline_events","source_ref":"benchmark_timeline_events","source_kind":"keypoint","kind":"rows","row_count":5}}', NULL, now()),
                        ('run-3', '2_timeline', 'Timeline', 1, 'query', '{"source_kind":"keypoint","source_ref":"empty_timeline_events","result":{"keypoint":"empty_timeline_events","source_ref":"empty_timeline_events","source_kind":"keypoint","kind":"rows","row_count":0}}', NULL, now())
                    """
                )
                coverage_rows = db.execute(
                    """
                    SELECT section_key, source_query, evidence_table, row_count, used_in_answer, queried
                    FROM section_run_coverage
                    ORDER BY section_key, source_query
                    """
                ).fetchall()
                markdown = build_report_markdown_from_db(db)

            self.assertEqual(3, len(coverage_rows))
            self.assertEqual("benchmark_ost_file", coverage_rows[0][1])
            self.assertEqual("Yes", coverage_rows[0][4])
            zero_row = next(
                row for row in coverage_rows if row[1] == "empty_timeline_events"
            )
            self.assertEqual("No", zero_row[4])
            self.assertNotIn("#### Coverage Summary", markdown)
            self.assertNotIn("benchmark_ost_file", markdown)
            self.assertNotIn("#### Evidence Coverage", markdown)
            self.assertNotIn("benchmark_timeline_events", markdown)
            self.assertNotIn("**Status:** partial", markdown)
            self.assertNotIn("raw_sql", markdown)

    def test_build_report_markdown_rebuilds_non_question_sections_with_tables(
        self,
    ) -> None:
        """Without deterministic override, report_markdown renders from DB bodies directly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count,
                        gaps, last_filled_session, last_filled_at, stale
                    ) VALUES
                        ('1_overview', 'Investigation Overview', '# Investigation Overview\n\n## Executive Summary\n\nLLM written overview content.\n\n## Key Findings\n\nDetailed findings.', 0.8, 'draft', 1, '[]', 'S-1', now(), FALSE),
                        ('2_timeline', 'Activity Timeline', '# Activity Timeline\n\n## Phase Summary\n\nTimeline narrative.', 0.7, 'draft', 1, '[]', 'S-1', now(), FALSE),
                        ('3_technical', 'Technical Analysis', '# Technical Analysis\n\n## Systems and Accounts\n\nAccount analysis text.', 0.7, 'draft', 1, '[]', 'S-1', now(), FALSE),
                        ('4_gaps', 'Investigation Gaps', '# Investigation Gaps\n\n## Evidence Gaps\n\nGap analysis.', 0.7, 'draft', 1, '[]', 'S-1', now(), FALSE)
                    """
                )

                markdown = build_report_markdown_from_db(db)

            self.assertIn("# Investigation Overview", markdown)
            self.assertIn("LLM written overview content", markdown)
            self.assertIn("# Activity Timeline", markdown)
            self.assertIn("Timeline narrative.", markdown)
            self.assertIn("# Technical Analysis", markdown)
            self.assertIn("Account analysis text.", markdown)
            self.assertIn("# Investigation Gaps", markdown)
            self.assertIn("Gap analysis.", markdown)
            self.assertNotIn("**Status:**", markdown)

    def test_finalize_section_upserts_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                result = finalize_section(
                    db=db,
                    section_key="1_overview",
                    title="Overview",
                    body="## Overview\n\nOverview content here.",
                    evidence_results=[],
                )
                row = db.execute(
                    """
                    SELECT section_key, title, body, status
                    FROM report_sections
                    WHERE section_key = ?
                    """,
                    ("1_overview",),
                ).fetchone()

            self.assertEqual("1_overview", str(row[0]))
            self.assertEqual("Overview", str(row[1]))
            self.assertIn("Overview content here", str(row[2]))
            self.assertIsInstance(result, dict)
            self.assertIn("gaps", result)
            self.assertIn("confidence", result)

    def test_quality_gate_flags_heading_title_mismatch(self) -> None:
        gaps, confidence = quality_gate_section(
            "3_technical",
            "Compromised Accounts and Authentication",
            "# Indicators of Compromise\n\nBody text",
            [],
            1.0,
        )

        self.assertTrue(any("heading does not match" in gap.lower() for gap in gaps))
        self.assertLessEqual(confidence, 0.65)

    def test_quality_gate_forces_low_confidence_when_fill_placeholder_remains(
        self,
    ) -> None:
        gaps, confidence = quality_gate_section(
            "1_overview",
            "Investigation Overview",
            "# Investigation Overview\n\n<!-- fill -->",
            [],
            1.0,
        )

        self.assertTrue(any("placeholder" in gap.lower() for gap in gaps))
        self.assertLessEqual(confidence, 0.3)

    def test_quality_gate_flags_recommendations_without_evidence_strength(self) -> None:
        body = (
            "## Immediate Response\n\n"
            "| Priority | Action | Justification |\n"
            "|---|---|---|\n"
            "| High | Isolate host1 now | suspicious activity observed |\n"
        )

        gaps, confidence = quality_gate_section(
            "5_recommendations",
            "Recommended Actions",
            body,
            [],
            1.0,
        )

        self.assertTrue(
            any("Recommendations should state evidence strength" in g for g in gaps)
        )
        self.assertLess(confidence, 1.0)

    def testsort_markdown_table_by_first_column_orders_timeline_rows(self) -> None:
        body = (
            "| Timestamp | Host |\n"
            "|---|---|\n"
            "| 2026-05-16 10:00:00 | host1 |\n"
            "| 2026-05-16 09:00:00 | host1 |\n"
        )
        sorted_body = sort_markdown_table_by_first_column(body)
        self.assertLess(sorted_body.find("09:00:00"), sorted_body.find("10:00:00"))

    def test_export_packaged_templates_excludes_benchmark_appendix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir, overwrite=True)

            self.assertFalse(any(path.name == "6_appendix.md" for path in written))
            self.assertFalse((Path(tmpdir) / "6_appendix.md").exists())

    def test_finalize_section_flags_duplicate_finding_mentions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence, status,
                        tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "F-1",
                        "rule",
                        "Suspicious Service",
                        "Summary",
                        "high",
                        0.9,
                        "accepted",
                        "[]",
                        "[]",
                        "[]",
                        "",
                        "[]",
                        now,
                    ),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Persistence and Execution",
                    body="# Persistence and Execution\n\nSuspicious Service\n\nSuspicious Service\n\nSuspicious Service",
                    evidence_results=[],
                    session_id="S-1",
                )

            self.assertTrue(any("repeated too often" in gap for gap in result["gaps"]))
            self.assertLessEqual(result["confidence"], 0.6)


if __name__ == "__main__":
    unittest.main()
