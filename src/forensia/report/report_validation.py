"""Post-generation report validation checks.

Each check is a pure function that inspects a generated report (its brief,
body, or JSON) and returns a list of ``ValidationFinding`` objects.

Checks are deterministic — no LLM calls. They are wired into ``python -m forensia.cli.doctor``
to catch regressions after generation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from functools import lru_cache
from typing import Any

import yaml

from forensia.evidence.timestamp_policy import (
    configured_timestamp_policy,
    timestamp_year_range_sql,
)
from forensia.knowledge.resources import schema_dir
from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN
from forensia.report.sections.quality_gates import (
    _detect_body_language,
    failure_markers,
)
from forensia.report.sections.section_store import fetch_report_sections

_SCHEMA_DIR = schema_dir()
_VOCAB_PATH = _SCHEMA_DIR / "report_validation_vocab.yaml"


# ---------------------------------------------------------------------------
# Vocabulary loader (YAML-backed, same pattern as knowledge.py)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_vocab() -> dict[str, Any]:
    """Load detection vocabulary from report_validation_vocab.yaml."""
    if not _VOCAB_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(_VOCAB_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_intrusion_keywords() -> tuple[str, ...]:
    """Return intrusion keywords from YAML vocabulary."""
    vocab = _load_vocab()
    raw = vocab.get("intrusion_keywords") or []
    return tuple(str(k).lower() for k in raw) if isinstance(raw, list) else ()


def _get_path_leak_patterns() -> tuple[re.Pattern, ...]:
    """Return path-leak regex patterns from YAML vocabulary."""
    vocab = _load_vocab()
    raw = vocab.get("path_leak_patterns") or []
    if not isinstance(raw, list):
        return ()
    return tuple(re.compile(p, re.IGNORECASE) for p in raw if isinstance(p, str))


def _get_fallback_stub_phrases() -> tuple[str, ...]:
    """Return narrative-fallback stub phrases from YAML vocabulary."""
    vocab = _load_vocab()
    raw = vocab.get("fallback_stub_phrases") or []
    return tuple(str(p).lower() for p in raw) if isinstance(raw, list) else ()


class ValidationFinding:
    """A single validation issue found in the report output."""

    def __init__(
        self,
        check_name: str,
        severity: str,
        message: str,
        details: str | None = None,
    ) -> None:
        self.check_name = check_name
        self.severity = severity  # "error" or "warning"
        self.message = message
        self.details = details

    def __repr__(self) -> str:
        return f"[{self.severity.upper()}] {self.check_name}: {self.message}"

    def as_dict(self) -> dict[str, str | None]:
        return {
            "check_name": self.check_name,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
        }


def derive_publication_state(db: Any) -> dict[str, Any]:
    """Derive report readiness, investigation status, and evidence confidence.

    Publication readiness is determined by current output for the adopted
    report sections and resolvable evidence links. Investigation status and
    confidence describe separate durable case facts and do not gate a report.
    """
    state: dict[str, Any] = {
        "publication_status": "needs_review",
        "report_complete": False,
        "confirmed_hypothesis_count": None,
        "confirmed_without_evidence_count": 0,
        "hypothesis_execution_step_count": 0,
        "plan_step_count": 0,
        "draft_sections": [],
        "section_statuses": {},
        "missing_section_keys": [],
        "stale_section_keys": [],
        "invalid_reference_sections": [],
        "investigation_status": "unknown",
        "stop_reason_code": "",
        "stop_reason": "",
        "evidence_confidence": "not_established",
        "claim_scope": "deterministic_signals_only",
        "reasons": [],
        "investigation_reasons": [],
    }
    if db is None:
        state["reasons"].append("database_unavailable")
        state["investigation_reasons"].append("database_unavailable")
        return state

    try:
        from forensia.report.sections.status import build_report_status

        report = build_report_status(db)
        state["report_complete"] = bool(report.get("complete"))
        state["missing_section_keys"] = list(report.get("missing_section_keys") or [])
        state["stale_section_keys"] = list(report.get("stale_section_keys") or [])
        state["invalid_reference_sections"] = list(
            report.get("invalid_reference_sections") or []
        )
        statuses = {
            str(item.get("section_key") or ""): str(item.get("status") or "draft")
            for item in report.get("items", [])
            if item.get("section_key")
        }
        state["section_statuses"] = statuses
        state["draft_sections"] = sorted(
            key for key, status in statuses.items() if status == "draft"
        )
        if not report.get("required_section_keys"):
            state["reasons"].append("no_adopted_report_sections")
        if state["missing_section_keys"]:
            state["reasons"].append("report_sections_missing_current_output")
        if state["stale_section_keys"]:
            state["reasons"].append("report_sections_stale")
        if state["invalid_reference_sections"]:
            state["reasons"].append("report_sections_have_unresolved_evidence")
    except Exception:
        state["reasons"].append("report_status_unavailable")

    try:
        row = db.execute(
            "SELECT status, stop_reason_code, stop_reason "
            "FROM investigation_state WHERE state_id = 'case'"
        ).fetchone()
        if row:
            state["investigation_status"] = str(row[0] or "active")
            state["stop_reason_code"] = str(row[1] or "")
            state["stop_reason"] = str(row[2] or "")
        else:
            state["investigation_reasons"].append("investigation_state_unavailable")
    except Exception:
        state["investigation_reasons"].append("investigation_state_unavailable")

    confidence_reasons = state["investigation_reasons"]
    try:
        state["confirmed_hypothesis_count"] = int(
            db.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status = 'confirmed'"
            ).fetchone()[0]
        )
    except Exception:
        confidence_reasons.append("confirmed_hypotheses_unavailable")

    try:
        from forensia.evidence.links import load_evidence_links

        confirmed_ids = [
            str(row[0])
            for row in db.execute(
                "SELECT hypothesis_id FROM hypotheses WHERE status = 'confirmed'"
            ).fetchall()
        ]
        for hypothesis_id in confirmed_ids:
            has_current_support = any(
                link.assessment_id and link.role in {"supporting", "corroborating"}
                for link in load_evidence_links(db, hypothesis_id, current_only=True)
            )
            if not has_current_support:
                state["confirmed_without_evidence_count"] += 1
    except Exception:
        confidence_reasons.append("hypothesis_evidence_unavailable")

    # Hypothesis ``do`` and ``check`` are the durable receipts that prove the
    # planner actually investigated a hypothesis. Section query runs are not a
    # substitute for this loop.
    try:
        state["hypothesis_execution_step_count"] = int(
            db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps "
                "WHERE phase IN ('do', 'check')"
            ).fetchone()[0]
        )
        state["plan_step_count"] = int(
            db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps "
                "WHERE phase IN ('plan-hypothesis', 'hypothesis-plan')"
            ).fetchone()[0]
        )
    except Exception:
        confidence_reasons.append("hypothesis_execution_receipts_unavailable")

    if state["confirmed_hypothesis_count"] == 0:
        confidence_reasons.append("no_confirmed_hypotheses")
    if state["confirmed_without_evidence_count"]:
        confidence_reasons.append("confirmed_hypotheses_without_evidence")
    if (
        not any(
            reason in confidence_reasons
            for reason in (
                "confirmed_hypotheses_unavailable",
                "hypothesis_evidence_unavailable",
            )
        )
        and state["confirmed_hypothesis_count"] is not None
        and state["confirmed_hypothesis_count"] > 0
        and not state["confirmed_without_evidence_count"]
    ):
        state["evidence_confidence"] = "established"
        state["claim_scope"] = "confirmed_conclusions"

    if state["report_complete"]:
        state["publication_status"] = "complete"
    return state


def check_publication_readiness(db: Any) -> list[ValidationFinding]:
    """Require current output and resolvable evidence for adopted sections."""
    from forensia.report.sections.status import build_report_status

    state = build_report_status(db)
    findings: list[ValidationFinding] = []
    if state["missing_section_keys"]:
        findings.append(
            ValidationFinding(
                "publication_readiness",
                "error",
                "Adopted report sections are missing current output",
                f"sections={state['missing_section_keys']}",
            )
        )
    if state["stale_section_keys"]:
        findings.append(
            ValidationFinding(
                "publication_readiness",
                "error",
                "Adopted report sections have stale output",
                f"sections={state['stale_section_keys']}",
            )
        )
    if state["invalid_reference_sections"]:
        findings.append(
            ValidationFinding(
                "publication_readiness",
                "error",
                "Adopted report sections contain unresolved evidence references",
                f"sections={state['invalid_reference_sections']}",
            )
        )
    if not state["required_section_keys"]:
        findings.append(
            ValidationFinding(
                "publication_readiness",
                "error",
                "No adopted report sections are available",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_thesis_alignment(report_brief: dict[str, Any]) -> list[ValidationFinding]:
    """Verify Executive Summary thesis is backed by strong confirmed hypotheses.

    If the summary uses intrusion language but no rule-seeded, non-benign
    confirmed hypothesis exists, flag a misalignment.
    """
    findings: list[ValidationFinding] = []
    summary = str(report_brief.get("executive_summary") or "")
    if not summary:
        return findings

    _intrusion_kw = _get_intrusion_keywords()
    has_intrusion_language = any(kw in summary.lower() for kw in _intrusion_kw)
    if not has_intrusion_language:
        return findings

    # Check for strong confirmed hypotheses
    confirmed = report_brief.get("confirmed_hypotheses") or []
    strong_count = 0
    for hyp in confirmed:
        source_rules = hyp.get("source_rule_ids") or []
        tags = hyp.get("tags") or []
        is_benign = any("benign" in str(t) for t in tags)
        if source_rules and not is_benign:
            strong_count += 1

    if strong_count == 0:
        findings.append(
            ValidationFinding(
                "thesis_alignment",
                "error",
                "Executive Summary uses intrusion language but no strong "
                "confirmed hypotheses exist to support it",
                f"keywords matched: {[kw for kw in _intrusion_kw if kw in summary.lower()]}",
            )
        )
    return findings


def check_refuted_leakage(report_brief: dict[str, Any]) -> list[ValidationFinding]:
    """Detect refuted-hypothesis claims leaking into gap sections."""
    findings: list[ValidationFinding] = []
    refuted = report_brief.get("refuted_hypotheses") or []
    gaps_text = json.dumps(report_brief.get("evidence_gaps", []))

    for hyp in refuted:
        desc = str(hyp.get("description") or "")
        if not desc:
            continue
        # Extract key tokens from refuted description
        tokens = re.findall(r"[A-Za-z0-9_\-\.]+\.(?:exe|dll|sys|bat|ps1)", desc)
        for token in tokens:
            if token.lower() in gaps_text.lower():
                findings.append(
                    ValidationFinding(
                        "refuted_leakage",
                        "warning",
                        f"Refuted hypothesis token '{token}' found in gaps section",
                        f"Hypothesis: {desc[:120]}",
                    )
                )
    return findings


def check_local_path_leak(content: str) -> list[ValidationFinding]:
    """Detect local ingest paths in report content."""
    findings: list[ValidationFinding] = []
    for pattern in _get_path_leak_patterns():
        matches = pattern.findall(content)
        if matches:
            findings.append(
                ValidationFinding(
                    "local_path_leak",
                    "error",
                    f"Local ingest path pattern '{pattern.pattern}' found "
                    f"in report content ({len(matches)} matches)",
                    f"Samples: {matches[:3]}",
                )
            )
    return findings


def check_fallback_stub(content: str) -> list[ValidationFinding]:
    """Detect deterministic narrative-fallback stubs shipped as report prose.

    When the LLM narrator fails twice, a deterministic fallback paragraph is
    produced. If its fixed phrasing reaches the rendered report, a narrator
    failure was shipped verbatim (e.g. as an Executive Summary) instead of a
    real summary — a Fail-loud violation the pipeline must surface.
    """
    findings: list[ValidationFinding] = []
    lowered = content.lower()
    for phrase in _get_fallback_stub_phrases():
        if phrase and phrase in lowered:
            findings.append(
                ValidationFinding(
                    "fallback_stub",
                    "error",
                    "Narrative fallback stub phrase found in report body "
                    f"('{phrase}'); a narrator failure was shipped as prose",
                    None,
                )
            )
    return findings


def check_failure_markers(content: str) -> list[ValidationFinding]:
    """Detect section block failure markers shipped in the final report body.

    Markers are the shared vocabulary from
    ``data/schema/report_validation_vocab.yaml`` (see quality_gates.failure_markers);
    they indicate that a block error was rendered as report prose instead of
    being handled gracefully.
    """
    findings: list[ValidationFinding] = []
    lowered = content.lower()
    for marker in failure_markers():
        if marker.lower() in lowered:
            findings.append(
                ValidationFinding(
                    "failure_marker",
                    "error",
                    f"Failure marker '{marker}' found in report body; "
                    "a block error was shipped as report prose",
                    None,
                )
            )
    return findings


def has_failure_marker(content: str) -> bool:
    """Return whether persisted prose contains a generation-failure marker."""
    return bool(check_failure_markers(content))


# Machine-detectable reference patterns for report traceability.
_FINDING_ID_PATTERN = re.compile(
    r"\b[A-Za-z0-9_./-]*?(?:finding|find-|ext-)[A-Za-z0-9_./-]*\b", re.IGNORECASE
)
_HYPOTHESIS_ID_PATTERN = re.compile(
    r"\b(?:H-[A-Za-z0-9][A-Za-z0-9_-]*|hyp(?:othesis)?[_-][A-Za-z0-9][A-Za-z0-9_-]*|gap-[0-9a-f]{10})\b",
    re.IGNORECASE,
)
_CREDENTIAL_SPECULATION_TERMS = (
    "credential compromise",
    "credentials were compromised",
    "credentials compromised",
    "compromised credential",
    "compromised credentials",
    "account compromise",
    "account was compromised",
    "credential theft",
    "credentials were stolen",
    "credentials stolen",
)


def _table_block_hashes(content: str) -> dict[tuple[str, str], str]:
    blocks: dict[tuple[str, str], str] = {}
    section = ""
    heading = ""
    lines: list[str] = []

    def save() -> None:
        if section and heading and lines:
            body = "\n".join(lines).strip()
            blocks[(section, heading)] = hashlib.sha256(
                body.encode("utf-8")
            ).hexdigest()

    for line in str(content or "").splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match:
            save()
            level, title = len(match.group(1)), match.group(2).strip()
            if level == 1:
                section, heading, lines = title, "", []
            elif level == 2:
                heading, lines = title, [line]
            else:
                lines.append(line)
            continue
        if heading:
            lines.append(line)
    save()
    return blocks


def _trusted_table_blocks(db: Any | None, content: str) -> set[tuple[str, str]]:
    if db is None:
        return set()
    present_hashes = _table_block_hashes(content)
    projections = db.execute(
        """
        SELECT section_key, payload FROM section_runs
        WHERE phase = 'projection'
        ORDER BY created_at DESC, run_id DESC
        """
    ).fetchall()
    latest_projection: dict[str, dict[str, Any]] = {}
    for section_key, serialized in projections:
        key = str(section_key or "")
        if key in latest_projection:
            continue
        try:
            payload = json.loads(str(serialized))
        except TypeError, ValueError:
            continue
        if isinstance(payload, dict):
            latest_projection[key] = payload

    try:
        from forensia.report.answers.table_registry import (
            TABLE_BLOCKS,
            source_receipt_metadata,
        )
    except Exception:
        return set()

    trusted: set[tuple[str, str]] = set()
    rows = db.execute(
        """
        SELECT section.section_key, section.title, section.stale,
               receipt.block_heading, receipt.payload
        FROM section_runs AS receipt
        JOIN report_sections AS section USING (section_key)
        WHERE receipt.phase = 'query'
          AND json_extract_string(receipt.payload, '$.source_kind') = 'deterministic_table'
        """
    ).fetchall()
    for section_key, title, stale, block_heading, serialized in rows:
        key = (str(title or "").strip(), str(block_heading or "").strip())
        if not key[0] or not key[1] or bool(stale):
            continue
        payload = latest_projection.get(str(section_key or ""), {})
        try:
            receipt = json.loads(str(serialized))
        except TypeError, ValueError:
            continue
        block_hash = str(receipt.get("block_body_sha256") or "")
        if not block_hash or present_hashes.get(key) != block_hash:
            continue
        source_signature = str(receipt.get("source_state_signature") or "")
        if not source_signature:
            continue
        builder = str(receipt.get("query_ref") or "")
        table_spec = TABLE_BLOCKS.get(builder)
        if table_spec is None:
            continue
        try:
            table_rows = table_spec.builder(db)
            source_metadata = source_receipt_metadata(db, table_spec)
        except Exception:
            continue
        if any(
            receipt.get(key) != value
            for key, value in source_metadata.items()
            if key
            in {
                "source_tables",
                "source_families",
                "query_description",
            }
        ):
            continue
        rows_hash = hashlib.sha256(
            json.dumps(
                table_rows,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if rows_hash != str(receipt.get("table_rows_sha256") or ""):
            continue
        if source_metadata["source_ids"] != receipt.get("source_ids"):
            continue
        if source_metadata["source_receipt_sha256"] != receipt.get(
            "source_receipt_sha256"
        ):
            continue
        projection_receipts = payload.get("query_receipts") or []
        if not any(
            item.get("source_kind") == "deterministic_table"
            and item.get("block_heading") == key[1]
            and item.get("query_ref") == builder
            and item.get("block_body_sha256") == block_hash
            and item.get("table_rows_sha256") == rows_hash
            and item.get("source_receipt_sha256")
            == source_metadata["source_receipt_sha256"]
            and item.get("source_state_signature") == source_signature
            and all(
                item.get(field) == source_metadata[field]
                for field in (
                    "source_tables",
                    "source_families",
                    "query_description",
                    "source_ids",
                )
            )
            for item in projection_receipts
            if isinstance(item, dict)
        ):
            continue
        trusted.add(key)
    # Keypoint blocks require current resolver replay and an exact body receipt.
    try:
        from forensia.report.answers.keypoint_catalog import (
            REPORT_KEYPOINT_ALIASES,
            REPORT_KEYPOINT_METADATA,
        )
        from forensia.report.sections.section_exec import _execute_keypoint
        from forensia.report.sections.section_refresher import (
            _canonical_hash,
            _case_evidence_signature,
            _evidence_ids,
        )

        current_signature = _case_evidence_signature(db)
        section_rows = db.execute(
            "SELECT section_key, title, stale FROM report_sections"
        ).fetchall()
        section_info = {
            str(section_key): (str(title or "").strip(), bool(stale))
            for section_key, title, stale in section_rows
        }
        query_rows = db.execute(
            """
            SELECT section_key, block_heading, payload
            FROM section_runs
            WHERE phase = 'query'
              AND json_extract_string(payload, '$.source_kind') = 'keypoint'
            ORDER BY created_at DESC, run_id DESC
            """
        ).fetchall()
        latest: dict[tuple[str, str, str], dict[str, Any]] = {}
        for section_key, block_heading, serialized in query_rows:
            try:
                receipt = json.loads(str(serialized))
            except TypeError, ValueError:
                continue
            if not isinstance(receipt, dict):
                continue
            identity = (
                str(section_key or ""),
                str(block_heading or ""),
                str(receipt.get("query_ref") or ""),
            )
            latest.setdefault(identity, receipt)

        projection_receipts: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for section_key, payload in latest_projection.items():
            for receipt in payload.get("query_receipts") or []:
                if (
                    isinstance(receipt, dict)
                    and receipt.get("source_kind") == "keypoint"
                ):
                    key = (section_key, str(receipt.get("block_heading") or ""))
                    projection_receipts.setdefault(key, []).append(receipt)

        expected: dict[tuple[str, str], set[str]] = {}
        valid: dict[tuple[str, str], set[str]] = {}
        for (section_key, block_heading, query_ref), receipt in latest.items():
            title, stale = section_info.get(section_key, ("", True))
            key = (title, block_heading)
            expected.setdefault(key, set()).add(query_ref)
            block_hash = str(receipt.get("block_body_sha256") or "")
            result_hash = str(receipt.get("keypoint_result_sha256") or "")
            if (
                not title
                or not block_heading
                or stale
                or not block_hash
                or present_hashes.get(key) != block_hash
                or not result_hash
                or receipt.get("source_state_signature") != current_signature
            ):
                continue
            try:
                _source_ref, result = _execute_keypoint(
                    getattr(db, "case", None), db, query_ref
                )
                result["source_ref"] = query_ref
                result["block_heading"] = block_heading
                result["case_refs"] = sorted(
                    {
                        str(value)
                        for value in result.get("hypothesis_ids") or []
                        if str(value).strip()
                    }
                )
                result["source_state_signature"] = current_signature
                if _canonical_hash(result) != result_hash:
                    continue
            except Exception:
                continue
            evidence_count = int(
                (receipt.get("result") or {}).get("evidence_count") or 0
            )
            evidence_ids = _evidence_ids([result])
            case_refs = receipt.get("case_refs") or []
            metadata_name = REPORT_KEYPOINT_ALIASES.get(query_ref, query_ref)
            is_coverage = (
                REPORT_KEYPOINT_METADATA.get(metadata_name) is not None
                and REPORT_KEYPOINT_METADATA[metadata_name].purpose == "coverage"
            )
            if (
                evidence_count != len(evidence_ids)
                or (receipt.get("result") or {}).get("evidence_ids") != evidence_ids
                or case_refs != result.get("case_refs", [])
                or (not evidence_ids and not case_refs and not is_coverage)
            ):
                continue
            matched = any(
                item.get("query_ref") == query_ref
                and item.get("keypoint_result_sha256") == result_hash
                and item.get("block_body_sha256") == block_hash
                and item.get("source_state_signature") == current_signature
                and item.get("case_refs") == case_refs
                and item.get("evidence_count") == len(evidence_ids)
                for item in projection_receipts.get((section_key, block_heading), [])
            )
            if matched:
                valid.setdefault(key, set()).add(query_ref)

        for key, query_refs in expected.items():
            if query_refs and valid.get(key) == query_refs:
                trusted.add(key)
    except Exception:
        pass
    return trusted


def _extract_claim_paragraphs(
    content: str, *, trusted_table_blocks: set[tuple[str, str]] | None = None
) -> list[str]:
    """Split prose and blocks without a matching deterministic receipt."""
    paragraphs: list[str] = []
    section_title = ""
    block_heading = ""
    for paragraph in re.split(r"\n\s*\n", str(content or "")):
        text = paragraph.strip()
        if not text:
            continue
        heading = re.match(r"^#{1,6}\s+(.+)$", text)
        if heading:
            level = len(text) - len(text.lstrip("#"))
            if level == 1:
                section_title = heading.group(1).strip()
                block_heading = ""
            elif level == 2:
                block_heading = heading.group(1).strip()
            continue
        if (
            trusted_table_blocks
            and (section_title, block_heading) in trusted_table_blocks
        ):
            continue
        if text.startswith(("**Status:**", "**ID:**")):
            continue
        paragraphs.append(text)
    return paragraphs


def _has_machine_ref(text: str) -> bool:
    return bool(EVIDENCE_ID_PATTERN.search(text) or _FINDING_ID_PATTERN.search(text))


# Tokens that indicate a paragraph is making a forensic/evidence claim (rather
# than generic or narrative prose). The zero-reference traceability gate only
# applies to such paragraphs, so trivial summaries are not penalised.
_EVIDENCE_ADJACENT_PATTERN = re.compile(
    r"\b(evtx|mft|prefetch|registry|ost|pst|edb|eml|mbox|logon|logoff|shutdown|"
    r"startup|event_id|4624|4625|4634|4647|4672|6005|6006|6008|1074|1102|104|"
    r"outlook|onedrive|google\s?drive|icloud|dropbox|recycle)\b",
    re.IGNORECASE,
)


def _is_evidence_claim(text: str) -> bool:
    return bool(_EVIDENCE_ADJACENT_PATTERN.search(text))


def check_claim_traceability(
    content: str, db: Any | None = None
) -> list[ValidationFinding]:
    """Reject claims that cannot be traced to machine-detectable evidence/finding refs.

    A report must not publish bare hypothesis IDs or unsupported credential
    compromise speculation. Every factual claim paragraph should expose at least
    one machine-detectable evidence/finding reference; a report body that
    contains claim prose but zero references fails traceability outright.
    """
    findings: list[ValidationFinding] = []
    paragraphs = _extract_claim_paragraphs(
        content, trusted_table_blocks=_trusted_table_blocks(db, content)
    )
    if not paragraphs:
        return findings

    for paragraph in paragraphs:
        is_evidence_claim = _is_evidence_claim(paragraph)
        # Bare hypothesis reference without a machine-detectable ref.
        if _HYPOTHESIS_ID_PATTERN.search(paragraph) and not _has_machine_ref(paragraph):
            findings.append(
                ValidationFinding(
                    "claim_traceability",
                    "error",
                    "Claim references a hypothesis without a machine-detectable "
                    "evidence/finding reference",
                    paragraph[:160],
                )
            )
        lowered = paragraph.lower()
        if any(term in lowered for term in _CREDENTIAL_SPECULATION_TERMS):
            if not _has_machine_ref(paragraph):
                findings.append(
                    ValidationFinding(
                        "claim_traceability",
                        "error",
                        "Unsupported credential-compromise speculation without "
                        "machine-detectable evidence/finding reference",
                        paragraph[:160],
                    )
                )
        if is_evidence_claim and not _has_machine_ref(paragraph):
            findings.append(
                ValidationFinding(
                    "claim_traceability",
                    "error",
                    "Evidence claim lacks a machine-detectable evidence/finding reference",
                    paragraph[:160],
                )
            )
    return findings


def check_persisted_section_failures(db: Any) -> list[ValidationFinding]:
    """Report invalid persisted sections even when writer omits their prose."""
    findings: list[ValidationFinding] = []
    try:
        for row in fetch_report_sections(db):
            section_key, body = row["section_key"], row["body"]
            if has_failure_marker(str(body or "")):
                findings.append(
                    ValidationFinding(
                        "section_generation_failure",
                        "error",
                        f"Report section {section_key} contains a generation failure and was omitted",
                        f"section_key={section_key}",
                    )
                )
    except Exception as exc:
        findings.append(
            ValidationFinding(
                "section_generation_failure",
                "error",
                "Could not inspect persisted report sections",
                f"{type(exc).__name__}: {exc}",
            )
        )
    return findings


def _normalize_expected_language(expected_lang: str) -> str:
    value = str(expected_lang or "").strip().lower()
    if value in {"ja", "jp", "japanese"}:
        return "ja"
    if value in {"en", "english"}:
        return "en"
    return value


def check_language_consistency(
    content: str, expected_lang: str
) -> list[ValidationFinding]:
    """Detect report-body language that conflicts with the configured output language."""
    expected = _normalize_expected_language(expected_lang)
    if expected not in {"en", "ja"}:
        return []
    detected = _detect_body_language(content)
    if detected in {"unknown", expected}:
        return []
    return [
        ValidationFinding(
            "language_consistency",
            "error",
            f"Report body language mismatch: expected={expected}, detected={detected}",
            None,
        )
    ]


def check_verdict_contradiction(
    report_brief: dict[str, Any],
) -> list[ValidationFinding]:
    """Detect identical claims in both confirmed and refuted hypotheses."""
    findings: list[ValidationFinding] = []
    confirmed = report_brief.get("confirmed_hypotheses") or []
    refuted = report_brief.get("refuted_hypotheses") or []

    confirmed_descs = {
        _normalize_for_compare(h.get("description", "")) for h in confirmed
    }
    refuted_descs = {_normalize_for_compare(h.get("description", "")) for h in refuted}

    overlap = confirmed_descs & refuted_descs
    if overlap:
        findings.append(
            ValidationFinding(
                "verdict_contradiction",
                "error",
                f"{len(overlap)} claim(s) appear in both confirmed and refuted hypotheses",
                f"Overlapping descriptions: {list(overlap)[:3]}",
            )
        )
    return findings


def check_sufficiency_consistency(
    db: Any,
) -> list[ValidationFinding]:
    """Detect confirmed hypotheses with non-sufficient sufficiency_status.

    R7-04: confirmed AND sufficiency_status != sufficient is an invariant
    violation. Legacy rows are flagged as needs_review.
    """
    findings: list[ValidationFinding] = []
    try:
        rows = db.execute(
            """
            SELECT hypothesis_id, description, sufficiency_status
            FROM hypotheses
            WHERE status = 'confirmed' AND sufficiency_status NOT IN ('sufficient', 'needs_review')
            """
        ).fetchall()
        for row in rows:
            findings.append(
                ValidationFinding(
                    "sufficiency_consistency",
                    "error",
                    f"Confirmed hypothesis {row[0]} has sufficiency_status={row[2]}",
                    f"Description: {str(row[1] or '')[:120]}",
                )
            )
        # A confirmed claim without a traceable EvidenceLink is not publishable.
        rows_no_evidence = db.execute(
            """
            SELECT h.hypothesis_id, h.description
            FROM hypotheses h
            LEFT JOIN hypothesis_evidence he ON he.hypothesis_id = h.hypothesis_id
            WHERE h.status = 'confirmed'
            GROUP BY h.hypothesis_id, h.description
            HAVING COUNT(he.link_id) = 0
            """
        ).fetchall()
        for row in rows_no_evidence:
            findings.append(
                ValidationFinding(
                    "sufficiency_consistency",
                    "error",
                    f"Confirmed hypothesis {row[0]} has no evidence links",
                    f"Description: {str(row[1] or '')[:120]}",
                )
            )
    except Exception as exc:
        findings.append(
            ValidationFinding(
                "sufficiency_consistency",
                "error",
                "Could not validate hypothesis sufficiency consistency",
                f"{type(exc).__name__}: {exc}",
            )
        )
    return findings


def check_coverage_lineage(
    db: Any,
) -> list[ValidationFinding]:
    """R8-03: Check coverage lineage completeness.

    - Available coverage entries must have at least 1 source_id
    - Coverage start_time/end_time must not contain sentinel timestamps
    - source_ids must trace back to actual evidence_sources
    """
    findings: list[ValidationFinding] = []
    try:
        # Check available coverage with empty source_ids
        rows = db.execute(
            """
            SELECT capability, source_family, source_ids
            FROM evidence_coverage
            WHERE state = 'available'
              AND (source_ids IS NULL OR CAST(source_ids AS VARCHAR) = '[]')
            """
        ).fetchall()
        for row in rows:
            findings.append(
                ValidationFinding(
                    "coverage_lineage",
                    "error",
                    f"Available coverage {row[0]} ({row[1]}) has empty source_ids",
                    "Coverage with state=available must trace back to at least 1 evidence source",
                )
            )

        # Check for sentinel timestamps in coverage
        time_policy = configured_timestamp_policy()
        start_eligible = timestamp_year_range_sql("start_time", time_policy)
        end_eligible = timestamp_year_range_sql("end_time", time_policy)
        rows = db.execute(
            f"""
            SELECT capability, source_family, start_time, end_time
            FROM evidence_coverage
            WHERE state IN ('available', 'partial')
              AND (
                NOT ({start_eligible})
                OR NOT ({end_eligible})
              )
            """
        ).fetchall()
        for row in rows:
            findings.append(
                ValidationFinding(
                    "coverage_lineage",
                    "warning",
                    f"Coverage {row[0]} ({row[1]}) has implausible timestamps",
                    f"start_time={row[2]}, end_time={row[3]}",
                )
            )

        source_rows = db.execute(
            "SELECT source_id, artifact_family, row_count, channel, hosts "
            "FROM evidence_sources"
        ).fetchall()
        sources = {
            str(row[0]): {
                "family": str(row[1] or ""),
                "row_count": int(row[2] or 0),
                "channel": str(row[3] or ""),
                "hosts": json.loads(row[4])
                if isinstance(row[4], str)
                else row[4] or [],
            }
            for row in source_rows
        }

        for source_id, source in sources.items():
            if source["family"] != "evtx" or source["row_count"] == 0:
                continue
            missing = [name for name in ("channel", "hosts") if not source[name]]
            if missing:
                findings.append(
                    ValidationFinding(
                        "coverage_lineage",
                        "warning",
                        f"EVTX source {source_id[:12]} has incomplete metadata",
                        f"missing={','.join(missing)}",
                    )
                )

        # Check source_ids validity and family consistency.
        rows = db.execute(
            """
            SELECT c.capability, c.source_family, c.source_ids
            FROM evidence_coverage c
            WHERE c.state IN ('available', 'partial')
              AND c.source_ids IS NOT NULL
              AND CAST(c.source_ids AS VARCHAR) != '[]'
            """
        ).fetchall()
        for row in rows:
            source_ids = row[2]
            if isinstance(source_ids, str):
                try:
                    source_ids = json.loads(source_ids)
                except json.JSONDecodeError:
                    source_ids = []
            if not isinstance(source_ids, list):
                continue
            for sid in source_ids:
                source = sources.get(str(sid))
                if source is None:
                    findings.append(
                        ValidationFinding(
                            "coverage_lineage",
                            "warning",
                            f"Coverage {row[0]} references non-existent source {str(sid)[:12]}",
                            "source_ids must reference existing evidence_sources rows",
                        )
                    )
                elif source["family"] != row[1]:
                    findings.append(
                        ValidationFinding(
                            "coverage_lineage",
                            "error",
                            f"Coverage {row[0]} references a source from another family",
                            f"coverage={row[1]}, source={source['family']}, source_id={str(sid)[:12]}",
                        )
                    )
    except Exception as exc:
        findings.append(
            ValidationFinding(
                "coverage_lineage",
                "error",
                "Could not validate coverage lineage",
                f"{type(exc).__name__}: {exc}",
            )
        )
    return findings


def check_work_state_consistency(db: Any) -> list[ValidationFinding]:
    """Validate the Gap/Task/Hypothesis state-machine invariants."""
    findings: list[ValidationFinding] = []
    try:
        state = db.execute(
            "SELECT objective, status FROM investigation_state WHERE state_id = 'case'"
        ).fetchone()
        if state and str(state[1] or "") == "stopped":
            active = db.execute(
                "SELECT hypothesis_id FROM hypotheses WHERE status = 'active'"
            ).fetchall()
            for (hypothesis_id,) in active:
                findings.append(
                    ValidationFinding(
                        "work_state",
                        "error",
                        f"Stopped case retains active hypothesis {hypothesis_id}",
                        "Terminal classification must create linked deferred/blocked/review work",
                    )
                )
        if state and not str(state[0] or "").strip():
            gap = db.execute(
                "SELECT 1 FROM report_gaps WHERE origin = 'configuration' "
                "AND kind = 'configuration' AND status = 'open' LIMIT 1"
            ).fetchone()
            if not gap:
                findings.append(
                    ValidationFinding(
                        "work_state",
                        "error",
                        "Investigation objective is empty without a configuration gap",
                    )
                )

        missing_work = db.execute(
            """
            SELECT h.hypothesis_id, h.status
            FROM hypotheses h
            LEFT JOIN investigation_tasks t
              ON t.hypothesis_id = h.hypothesis_id
             AND t.status IN ('open', 'in_progress')
            WHERE h.status IN ('deferred', 'blocked', 'needs_review', 'untestable')
              AND t.task_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM investigation_state s
                  WHERE s.state_id = 'case' AND s.status = 'stopped'
              )
            """
        ).fetchall()
        for hypothesis_id, status in missing_work:
            findings.append(
                ValidationFinding(
                    "work_state",
                    "error",
                    f"Classified hypothesis {hypothesis_id} ({status}) has no open Task",
                )
            )

        broken_links = db.execute(
            """
            SELECT g.gap_id, g.task_id, t.gap_id
            FROM report_gaps g
            LEFT JOIN investigation_tasks t ON t.task_id = g.task_id
            WHERE g.task_id IS NOT NULL
              AND (t.task_id IS NULL OR COALESCE(t.gap_id, '') != g.gap_id)
            """
        ).fetchall()
        for gap_id, task_id, task_gap_id in broken_links:
            findings.append(
                ValidationFinding(
                    "work_state",
                    "error",
                    f"Gap/Task link mismatch for {gap_id}",
                    f"gap.task_id={task_id}, task.gap_id={task_gap_id}",
                )
            )
    except Exception as exc:
        findings.append(
            ValidationFinding(
                "work_state",
                "error",
                "Could not validate investigation work state",
                f"{type(exc).__name__}: {exc}",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def _normalize_for_compare(text: str) -> str:
    """Normalize a hypothesis description for comparison."""
    return re.sub(r"\s+", " ", text).strip().lower()


def _validation_plan(
    report_brief: dict[str, Any],
    *,
    report_body: str | None,
    expected_language: str | None,
    db: Any | None,
) -> list[tuple[str, Callable[[], list[ValidationFinding]]]]:
    """The executed validation pipeline as (check_name, run) pairs.

    Single definition of which checks run under which inputs; consumers that
    need to report ``checks_run`` must derive it from here.
    """
    checks: list[tuple[str, Callable[[], list[ValidationFinding]]]] = [
        ("thesis_alignment", lambda: check_thesis_alignment(report_brief)),
        ("refuted_leakage", lambda: check_refuted_leakage(report_brief)),
        ("verdict_contradiction", lambda: check_verdict_contradiction(report_brief)),
    ]
    if db is not None:
        checks.extend(
            [
                ("publication_readiness", lambda: check_publication_readiness(db)),
                ("sufficiency_consistency", lambda: check_sufficiency_consistency(db)),
                (
                    "persisted_section_failures",
                    lambda: check_persisted_section_failures(db),
                ),
                ("coverage_lineage", lambda: check_coverage_lineage(db)),
                ("work_state_consistency", lambda: check_work_state_consistency(db)),
            ]
        )
    if report_body:
        checks.extend(
            [
                ("local_path_leak", lambda: check_local_path_leak(report_body)),
                ("fallback_stub", lambda: check_fallback_stub(report_body)),
                ("failure_marker", lambda: check_failure_markers(report_body)),
                (
                    "claim_traceability",
                    lambda: check_claim_traceability(report_body, db),
                ),
            ]
        )
        if expected_language:
            checks.append(
                (
                    "language_consistency",
                    lambda: check_language_consistency(report_body, expected_language),
                )
            )
    return checks


def validation_check_names(
    report_brief: dict[str, Any],
    *,
    report_body: str | None = None,
    expected_language: str | None = None,
    db: Any | None = None,
) -> list[str]:
    """Names of the checks validate_report would execute with these inputs."""
    return [
        name
        for name, _ in _validation_plan(
            report_brief,
            report_body=report_body,
            expected_language=expected_language,
            db=db,
        )
    ]


def validate_report(
    report_brief: dict[str, Any],
    *,
    report_body: str | None = None,
    expected_language: str | None = None,
    db: Any | None = None,
) -> list[ValidationFinding]:
    """Run all validation checks on a generated report.

    Args:
        report_brief: The report brief projection built from CaseDB.
        report_body: Optional full report markdown body for path leak checks.

    Returns:
        List of ``ValidationFinding`` objects (empty if all checks pass).
    """
    return [
        finding
        for _, run in _validation_plan(
            report_brief,
            report_body=report_body,
            expected_language=expected_language,
            db=db,
        )
        for finding in run()
    ]
