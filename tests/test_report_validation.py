"""Unit tests for report_validation checks.

All tests use synthetic briefs — no dist/cfreds data required.
"""

from __future__ import annotations

import hashlib
import json
import tempfile

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN
from forensia.report.report_validation import (
    check_claim_traceability,
    check_local_path_leak,
    check_thesis_alignment,
    validate_report,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _brief(
    *,
    executive_summary: str = "",
    confirmed_hypotheses: list[dict] | None = None,
    refuted_hypotheses: list[dict] | None = None,
    evidence_gaps: list[dict] | None = None,
) -> dict:
    return {
        "executive_summary": executive_summary,
        "confirmed_hypotheses": confirmed_hypotheses or [],
        "refuted_hypotheses": refuted_hypotheses or [],
        "evidence_gaps": evidence_gaps or [],
    }


# ---------------------------------------------------------------------------
# Thesis alignment
# ---------------------------------------------------------------------------


class TestThesisAlignment:
    def test_pass_when_intrusion_keywords_with_strong_confirmed(self) -> None:
        """Summary with intrusion keywords AND strong confirmed hypothesis → no finding."""
        brief = _brief(
            executive_summary="Evidence suggests an intrusion via lateral movement",
            confirmed_hypotheses=[
                {
                    "description": "confirmed intrusion",
                    "source_rule_ids": ["RULE-001"],
                    "tags": ["lateral-movement"],
                }
            ],
        )
        findings = check_thesis_alignment(brief)
        assert findings == []


# ---------------------------------------------------------------------------
# Verdict contradiction
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Local path leak
# ---------------------------------------------------------------------------


class TestLocalPathLeak:
    def test_error_when_mnt_path_in_body(self) -> None:
        """Body containing '/mnt/c/' → finding."""
        findings = check_local_path_leak("Evidence from /mnt/c/Users/test/evidence/")
        assert len(findings) == 1
        assert findings[0].check_name == "local_path_leak"

    def test_windows_prefetch_artifact_path_is_not_local_host_leak(self) -> None:
        findings = check_local_path_leak(
            "Artifact: Windows/Prefetch/CCLEANER64.EXE-779BD542.pf"
        )
        assert findings == []


class TestFallbackStub:
    """H-2: narrator-fallback stubs must never ship as report prose."""

    def test_validate_report_includes_fallback_check(self) -> None:
        body = "For X, the collected evidence returned 3 related rows."
        findings = validate_report({}, report_body=body)
        assert any(f.check_name == "fallback_stub" for f in findings)


class TestLanguageConsistency:
    def test_validate_report_can_include_language_check(self) -> None:
        body = "## Summary\n\nこの本文は設定言語と一致しません。"
        findings = validate_report({}, report_body=body, expected_language="en")
        assert any(f.check_name == "language_consistency" for f in findings)


# ---------------------------------------------------------------------------
# validate_report orchestrator
# ---------------------------------------------------------------------------


class TestValidateReport:
    def test_no_issues_on_clean_brief(self) -> None:
        """Clean brief with proper confirmed hypothesis → empty list."""
        brief = _brief(
            executive_summary="No intrusion indicators found",
            confirmed_hypotheses=[
                {
                    "description": "normal user activity",
                    "source_rule_ids": ["RULE-001"],
                    "tags": [],
                }
            ],
        )
        findings = validate_report(brief, report_body="Clean evidence summary.")
        assert findings == []

    def test_multiple_issues_when_all_problems_present(self) -> None:
        """Brief with all problems → multiple findings."""
        overlap_desc = "Unauthorized access was confirmed"
        brief = _brief(
            executive_summary="Intrusion via lateral movement was detected",
            confirmed_hypotheses=[{"description": overlap_desc}],
            refuted_hypotheses=[
                {"description": overlap_desc},
                {"description": "bad.exe was executed"},
            ],
            evidence_gaps=[{"item": "Locate bad.exe in prefetch"}],
        )

        findings = validate_report(
            brief, report_body="See sample/evidence/bad.exe for analysis."
        )
        check_names = {f.check_name for f in findings}
        # thesis_alignment: intrusion keywords + no strong confirmed
        # verdict_contradiction: same description in both
        # refuted_leakage: bad.exe token in gaps
        # local_path_leak: sample/ in body
        assert "thesis_alignment" in check_names
        assert "verdict_contradiction" in check_names
        assert "refuted_leakage" in check_names
        assert "local_path_leak" in check_names
        assert len(findings) >= 4


class TestEvidenceIdPattern:
    def test_matches_current_evidence_id_formats(self) -> None:
        assert EVIDENCE_ID_PATTERN.search(
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
            "security-000000000120"
        )
        assert EVIDENCE_ID_PATTERN.search(
            "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
            "000000072008-00"
        )
        assert EVIDENCE_ID_PATTERN.search(
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
            "calc.exe-deadbeef"
        )
        assert EVIDENCE_ID_PATTERN.search("registry-" + "a" * 64)

    def test_rejects_old_evidence_id_formats(self) -> None:
        assert EVIDENCE_ID_PATTERN.search("ev-0001") is None
        assert EVIDENCE_ID_PATTERN.search("KP-0001") is None
        assert EVIDENCE_ID_PATTERN.search("evtx-security-000000000120") is None
        assert EVIDENCE_ID_PATTERN.search("mft-000000072008-00") is None

    def test_matches_canonical_ids_next_to_japanese_text(self) -> None:
        from forensia.core.evidence import make_prefetch_evidence_id

        prefetch = "prefetch-" + "a" * 64 + "-calc-exe-deadbeef"
        mft = "mft-" + "b" * 64 + "-72008-00"
        evtx_a = "evtx-" + "c" * 64 + "-security-000000000001"
        evtx_b = "evtx-" + "d" * 64 + "-system-000000000002"
        text = f"{prefetch}）と{mft}など{evtx_a}および{evtx_b}。"

        assert EVIDENCE_ID_PATTERN.findall(text) == [prefetch, mft, evtx_a, evtx_b]
        localized = make_prefetch_evidence_id("a" * 64, "調査.exe", "deadbeef")
        assert EVIDENCE_ID_PATTERN.findall(
            f"{localized}など{evtx_a}および{evtx_b}"
        ) == [localized, evtx_a, evtx_b]
        assert EVIDENCE_ID_PATTERN.findall(f"unknown-{evtx_a}z") == []


class TestDeterministicTableTraceability:
    def test_table_claim_requires_current_source_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                from forensia.report.answers.table_registry import (
                    TABLE_BLOCKS,
                    render_table_block,
                    source_receipt_metadata,
                )
                from forensia.report.sections.section_refresher import (
                    _case_evidence_signature,
                    _projection_receipts,
                )

                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, parser_name, parser_version, row_count) "
                    "VALUES ('source-registry-1', 'registry', 'complete', 'registry-parser', '1', 1)"
                )
                builder = "overview_evidence_scope"
                spec = TABLE_BLOCKS[builder]
                rows = spec.builder(db)
                source_metadata = source_receipt_metadata(db, spec)
                block = render_table_block(db, builder, rows=rows)
                block += (
                    f"\n\nSource query: {builder} — {spec.query_description}; "
                    f"tables: {', '.join(spec.source_tables)}; "
                    f"source families: {', '.join(spec.source_families)}; "
                    "source receipts: 0"
                )
                block = f"## Evidence Coverage\n\n{block}"
                body = f"# Summary and Scope\n\n{block}"
                result = {
                    "source_ref": f"table:{builder}",
                    "query_ref": builder,
                    "source_kind": "deterministic_table",
                    "block_heading": "Evidence Coverage",
                    "row_count": len(rows),
                    "evidence_ids": [],
                    "source_state_signature": _case_evidence_signature(db),
                    "table_rows_sha256": hashlib.sha256(
                        json.dumps(
                            rows,
                            ensure_ascii=False,
                            sort_keys=True,
                            default=str,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                    "block_body_sha256": hashlib.sha256(
                        block.encode("utf-8")
                    ).hexdigest(),
                    **source_metadata,
                    "case_refs": [],
                }
                unreceipted = check_claim_traceability(body, db)
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, stale) "
                    "VALUES ('01_summary', 'Summary and Scope', ?, FALSE)",
                    [body],
                )
                db.execute(
                    """
                    INSERT INTO section_runs (
                        run_id, section_key, block_heading, iteration, phase, payload, created_at
                    ) VALUES ('projection', '01_summary', '', 1, 'projection', ?, now())
                    """,
                    [json.dumps({"query_receipts": _projection_receipts([result])})],
                )
                db.execute(
                    """
                    INSERT INTO section_runs (
                        run_id, section_key, block_heading, iteration, phase, payload, created_at
                    ) VALUES (
                        'query', '01_summary', 'Evidence Coverage', 1, 'query',
                        ?,
                        now()
                    )
                    """,
                    [
                        json.dumps(
                            {
                                "source_kind": "deterministic_table",
                                "query_ref": builder,
                                **result,
                            }
                        )
                    ],
                )
                stale_recipe = {**result, "source_families": ["stale-family"]}
                db.execute(
                    "UPDATE section_runs SET payload = ? WHERE run_id = 'query'",
                    [
                        json.dumps(
                            {"source_kind": "deterministic_table", **stale_recipe}
                        )
                    ],
                )
                db.execute(
                    "UPDATE section_runs SET payload = ? WHERE run_id = 'projection'",
                    [
                        json.dumps(
                            {"query_receipts": _projection_receipts([stale_recipe])}
                        )
                    ],
                )
                stale_recipe_result = check_claim_traceability(body, db)
                db.execute(
                    "UPDATE section_runs SET payload = ? WHERE run_id = 'query'",
                    [json.dumps({"source_kind": "deterministic_table", **result})],
                )
                db.execute(
                    "UPDATE section_runs SET payload = ? WHERE run_id = 'projection'",
                    [json.dumps({"query_receipts": _projection_receipts([result])})],
                )
                receipted = check_claim_traceability(body, db)
                db.execute(
                    "UPDATE investigation_state SET objective = 'finalized' "
                    "WHERE state_id = 'case'"
                )
                terminal_state_only = check_claim_traceability(body, db)
                changed = body.replace("Registry", "Altered Registry")
                changed_material = check_claim_traceability(changed, db)
                db.execute(
                    "UPDATE evidence_sources SET parser_version = '2' "
                    "WHERE source_id = 'source-registry-1'"
                )
                stale_material = check_claim_traceability(body, db)

            assert any("Evidence claim lacks" in item.message for item in unreceipted)
            assert any(
                "Evidence claim lacks" in item.message for item in stale_recipe_result
            )
            assert receipted == []
            assert terminal_state_only == []
            assert any(
                "Evidence claim lacks" in item.message for item in changed_material
            )
            assert any(
                "Evidence claim lacks" in item.message for item in stale_material
            )


class TestKeypointTraceability:
    def test_channel_coverage_resolver_hash_is_stable_for_tied_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index, channel in enumerate(("Zulu", "Echo", "Bravo", "Alpha")):
                    db.execute(
                        """
                        INSERT INTO evtx_events (
                            evidence_id, event_id, timestamp, computer, channel, raw_json
                        ) VALUES (?, 4624, '2026-10-12 10:00:00', 'HOST-1', ?, '{}')
                        """,
                        [f"evtx-{index:064x}-security-000000000001", channel],
                    )

            from forensia.report.sections.section_exec import _execute_keypoint
            from forensia.report.sections.section_refresher import _canonical_hash

            snapshots = []
            orders = []
            for _ in range(5):
                with CaseDB(case, read_only=True) as db:
                    _, result = _execute_keypoint(case, db, "gaps_channel_coverage")
                snapshots.append(_canonical_hash(result))
                orders.append([row["channel"] for row in result["sample_rows"]])

        assert len(set(snapshots)) == 1
        assert orders == [["Alpha", "Bravo", "Echo", "Zulu"]] * 5

    def test_keypoint_receipt_replays_and_rejects_changed_or_tampered_projection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                from forensia.report.sections.section_exec import _execute_keypoint
                from forensia.report.sections.section_refresher import (
                    _canonical_hash,
                    _case_evidence_signature,
                    _projection_receipts,
                    _result_table,
                )

                evidence_id = "evtx-" + "a" * 64 + "-security-000000000120"
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, event_id, timestamp, computer, target_user,
                        logon_type, channel, raw_json
                    ) VALUES (
                        ?, 4624, '2026-10-12 10:00:00', 'HOST-1', 'alice', '3',
                        'Security',
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}'
                    )
                    """,
                    [evidence_id],
                )
                _source_ref, result = _execute_keypoint(
                    case, db, "account_all_logon_summary"
                )
                assert result["row_count"] == 1
                assert result["evidence_ids"] == [evidence_id]
                result["source_ref"] = "account_all_logon_summary"
                result["block_heading"] = "Observed accounts"
                result["case_refs"] = []
                result["source_state_signature"] = _case_evidence_signature(db)
                result["keypoint_result_sha256"] = _canonical_hash(result)
                _coverage_ref, coverage = _execute_keypoint(
                    case, db, "gaps_event_coverage"
                )
                assert coverage["row_count"] > 0
                assert coverage["evidence_ids"] == []
                coverage["source_ref"] = "gaps_event_coverage"
                coverage["block_heading"] = "Observed accounts"
                coverage["case_refs"] = []
                coverage["source_state_signature"] = _case_evidence_signature(db)
                coverage["keypoint_result_sha256"] = _canonical_hash(coverage)
                block = (
                    f"## Observed accounts\n\n**Logon summary**\n\n"
                    f"**{result['description']}**\n\n{_result_table(result)}\n\n"
                    f"**{coverage['description']}**\n\n{_result_table(coverage)}"
                )
                result["block_body_sha256"] = hashlib.sha256(
                    block.encode("utf-8")
                ).hexdigest()
                coverage["block_body_sha256"] = result["block_body_sha256"]
                body = f"# Account Summary\n\n{block}"
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, stale) "
                    "VALUES ('accounts', 'Account Summary', ?, FALSE)",
                    [body],
                )
                db.execute(
                    """
                    INSERT INTO section_runs
                        (run_id, section_key, block_heading, iteration, phase, payload, created_at)
                    VALUES ('projection', 'accounts', '', 1, 'projection', ?, now())
                    """,
                    [
                        json.dumps(
                            {"query_receipts": _projection_receipts([result, coverage])}
                        )
                    ],
                )

                def query_receipt(keypoint_result: dict) -> dict:
                    return {
                        "source_kind": "keypoint",
                        "source_ref": keypoint_result["source_ref"],
                        "query_ref": keypoint_result["source_ref"],
                        "block_heading": "Observed accounts",
                        "source_state_signature": keypoint_result[
                            "source_state_signature"
                        ],
                        "keypoint_result_sha256": keypoint_result[
                            "keypoint_result_sha256"
                        ],
                        "block_body_sha256": keypoint_result["block_body_sha256"],
                        "case_refs": keypoint_result["case_refs"],
                        "result": {
                            "row_count": keypoint_result["row_count"],
                            "evidence_ids": keypoint_result["evidence_ids"],
                            "evidence_count": len(keypoint_result["evidence_ids"]),
                        },
                    }

                account_receipt = query_receipt(result)
                coverage_receipt = query_receipt(coverage)
                db.execute(
                    """
                    INSERT INTO section_runs
                        (run_id, section_key, block_heading, iteration, phase, payload, created_at)
                    VALUES ('query', 'accounts', 'Observed accounts', 1, 'query', ?, now())
                    """,
                    [json.dumps(account_receipt)],
                )
                db.execute(
                    """
                    INSERT INTO section_runs
                        (run_id, section_key, block_heading, iteration, phase, payload, created_at)
                    VALUES ('query-coverage', 'accounts', 'Observed accounts', 1, 'query', ?, now())
                    """,
                    [json.dumps(coverage_receipt)],
                )
                from forensia.report.report_validation import _trusted_table_blocks

                assert _trusted_table_blocks(db, body) == {
                    ("Account Summary", "Observed accounts")
                }
                assert check_claim_traceability(body, db) == []

                altered_coverage_receipt = {
                    **coverage_receipt,
                    "case_refs": ["H-FAKE"],
                }
                db.execute(
                    "UPDATE section_runs SET payload = ? WHERE run_id = 'query-coverage'",
                    [json.dumps(altered_coverage_receipt)],
                )
                assert _trusted_table_blocks(db, body) == set()
                findings = check_claim_traceability(body, db)
                assert any("Evidence claim lacks" in item.message for item in findings)
                db.execute(
                    "UPDATE section_runs SET payload = ? WHERE run_id = 'query-coverage'",
                    [json.dumps(coverage_receipt)],
                )

                changed = body.replace(evidence_id, "unreferenced")
                assert _trusted_table_blocks(db, changed) == set()
                findings = check_claim_traceability(changed, db)
                assert any("Evidence claim lacks" in item.message for item in findings)

                db.execute(
                    "UPDATE evtx_events SET target_user = 'bob' WHERE evidence_id = ?",
                    [evidence_id],
                )
                assert _trusted_table_blocks(db, body) == set()
                findings = check_claim_traceability(body, db)
                assert any("Evidence claim lacks" in item.message for item in findings)

    def test_generic_hypothesis_word_is_not_an_identifier(self) -> None:
        body = (
            "# Review\n\n"
            "The hypothesis remains unresolved and requires additional evidence."
        )
        assert check_claim_traceability(body) == []
