from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

from forensia.config import get_llm_settings
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.keypoints import EVIDENCE_ID_PATTERN

# ====================================================================
# Patterns used by quality gates
# ====================================================================

PLACEHOLDER_ENTITY_PATTERN = re.compile(
    r"(?<![\w/.-])(none|n/?a|null)(?![\w/.-])", re.IGNORECASE
)
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
HTML_FILL_PATTERN = re.compile(r"<!--\s*fill(?:[^>]*)-->", re.IGNORECASE)
FINDING_ID_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9-]*-\d{4}\b")
_OPEN_QUESTION_RE = re.compile(
    r"(?:^|[\s\(])(\?|？|TBD|TODO|FIXME|要確認|要調査|未確認|未調査|未特定|不明瞭|未解明|XXX|N\/A\?)"
)
_CITATION_TOKENS_RE = re.compile(
    r"(?:証拠|証拠ID|finding[_\s]?id|evidence|根拠は|に基づく|according to|based on the)",
    re.IGNORECASE,
)
_FINDING_ID_RE = re.compile(r"\b[a-z]+-[a-z0-9]+-[0-9]+-[a-z0-9-]+\b")
_PURE_HEDGE_RE = re.compile(
    r"(?:may|might|could|possibly|perhaps|seem(?:s|ed)?|appears? to|思われる|可能性が|かもしれない)",
    re.IGNORECASE,
)
_TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}([T\s]\d{2}:\d{2})?")
_ENGLISH_PARAGRAPH_RE = re.compile(r"^[\x20-\x7e]{120,}$", re.MULTILINE)
_JAPANESE_CHAR_RE = re.compile(r"[぀-ヿ一-鿿]")
# RPT-02: vocabulary used to detect a narrative that asserts an external/lateral
# intrusion storyline as the main thread, not tied to any specific benchmark
# scenario or finding id (Rule 16).
_STRONG_INTRUSION_THEME_RE = re.compile(
    r"lateral movement|remote service creation|external (?:attacker|actor|intrusion)"
    r"|横移動|侵入|不正アクセス|リモートサービスの作成|外部からの",
    re.IGNORECASE,
)


# ====================================================================
# Helper functions
# ====================================================================


def _normalized_text_key(text: str) -> str:
    lowered = text.casefold()
    cleaned = re.sub(r"[^a-z0-9]+", " ", lowered)
    return " ".join(cleaned.split())


def _first_heading_text(body: str) -> str:
    """Extract the first H1 heading text from a Markdown body."""
    for line in body.splitlines():
        match = HEADING_PATTERN.match(line.strip())
        if match and len(match.group(1)) == 1:
            return match.group(2).strip()
    return ""


def _timeline_rows_are_chronological(body: str) -> bool:
    """Verify that timeline Markdown table rows are sorted by first-column timestamp."""
    timestamps: list[str] = []
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        stripped = line.strip()
        if stripped.startswith("|---") or "Timestamp" in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0]
        if not first or "<!--" in first:
            continue
        timestamps.append(first)
    return timestamps == sorted(timestamps)


def _title_matches_body_heading(title: str, body: str) -> bool:
    """Check whether a section title is compatible with the first H1 heading in the body."""
    heading = _first_heading_text(body)
    if not heading:
        return True
    normalized_title = _normalized_text_key(title)
    normalized_heading = _normalized_text_key(heading)
    return (
        not normalized_title
        or not normalized_heading
        or normalized_title in normalized_heading
        or normalized_heading in normalized_title
    )


def _detect_body_language(text: str) -> str:
    """Crude heuristic: count Japanese chars vs ASCII letters; return 'ja', 'en', or 'mixed'."""
    ja_chars = len(_JAPANESE_CHAR_RE.findall(text))
    en_chars = sum(1 for ch in text if "a" <= ch.lower() <= "z")
    if ja_chars == 0 and en_chars > 50:
        return "en"
    if en_chars == 0 and ja_chars > 0:
        return "ja"
    if ja_chars > 0 and en_chars > 0:
        return (
            "ja"
            if ja_chars * 2 > en_chars
            else "en"
            if en_chars > ja_chars * 4
            else "mixed"
        )
    return "unknown"


# ====================================================================
# Quality gate types
# ====================================================================


@dataclass
class _GateCtx:
    section_key: str
    title: str
    evidence_results: list[dict[str, Any]] | None
    db: CaseDB | None
    behaviors: tuple[str, ...] = ()


QualityCheck = Callable[[str, _GateCtx], tuple[str | None, float | None]]


# ====================================================================
# Individual quality check functions
# ====================================================================


def _check_placeholder_entity(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if PLACEHOLDER_ENTITY_PATTERN.search(body):
        return "Placeholder entity values detected; additional review is required.", 0.5
    return None, None


def _check_template_marker(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if HTML_FILL_PATTERN.search(body):
        return "Template placeholder markers remain in the section body.", 0.3
    return None, None


def _check_heading_mismatch(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if not _title_matches_body_heading(ctx.title, body):
        return (
            "Section heading does not match the expected section title; review for claim/title consistency.",
            0.65,
        )
    return None, None


def _check_timeline_ordering(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if (
        "require_chronological_table" in ctx.behaviors
        and not _timeline_rows_are_chronological(body)
    ):
        return (
            "Timeline ordering requires review; events are not strictly chronological.",
            0.6,
        )
    return None, None


def _check_recommendations_strength(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if "require_recommendations_strength" in ctx.behaviors:
        lowered = body.lower()
        strength_markers = (
            "confirmed",
            "strongly suggests",
            "may indicate",
            "additional verification",
            "consider containment after verification",
            "追加の相関確認",
            "追加確認",
            "検証後",
            "証拠不足",
            "根拠",
            "中程度",
            "高信頼",
        )
        if not any(marker in lowered for marker in strength_markers):
            return (
                "Recommendations should state evidence strength or verification-first wording.",
                0.65,
            )
    return None, None


def _check_verdict_inflation(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    source_verdicts = {
        str(result.get("source_verdict") or "").strip().lower()
        for result in ctx.evidence_results or []
        if str(result.get("source_verdict") or "").strip()
    }
    if source_verdicts and "confirmed" not in source_verdicts:
        lowered = body.casefold()
        strong_markers = (
            "confirmed",
            "executed",
            "compromised",
            "attack succeeded",
            "侵害",
            "実行された",
            "確認された",
        )
        if any(marker in lowered for marker in strong_markers):
            return (
                "Section language is stronger than the evidence verdicts support; rewrite with cautious wording.",
                0.6,
            )
    return None, None


def _strong_confirmed_hypothesis_exists(db: CaseDB) -> bool:
    """True if any confirmed hypothesis is rule-seeded and not benign-context.

    Mirrors the `narrative_strength` annotation computed for the report brief
    (probes._annotate_confirmed_hypotheses): a confirmed hypothesis counts as
    strong support only when it was seeded by a detection rule whose findings
    were not themselves downgraded to a known-benign pattern.
    """
    rows = fetch_records(
        db,
        "SELECT source_rule_ids FROM hypotheses WHERE status = 'confirmed'",
    )
    for row in rows:
        raw = row.get("source_rule_ids")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = []
        rule_ids = [str(r).strip() for r in (raw or []) if str(r or "").strip()]
        if not rule_ids:
            continue
        placeholders = ", ".join("?" for _ in rule_ids)
        finding_rows = fetch_records(
            db,
            f"SELECT tags FROM findings WHERE rule_id IN ({placeholders})",
            tuple(rule_ids),
        )
        if not finding_rows:
            continue
        if not all(
            "benign-context:" in str(r.get("tags") or "").lower() for r in finding_rows
        ):
            return True
    return False


def _check_unsupported_intrusion_narrative(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    """RPT-02: narrative claiming an external/lateral-movement main thread needs
    strong (rule-seeded, non-benign) confirmed-hypothesis support.

    Confirmed verdicts derived only from generic gaps (no source_rule_ids) or
    downgraded to benign-context are not sufficient evidence for a main
    storyline asserting external intrusion or lateral movement.
    """
    if ctx.db is None:
        return None, None
    if not _STRONG_INTRUSION_THEME_RE.search(body):
        return None, None
    if _strong_confirmed_hypothesis_exists(ctx.db):
        return None, None
    return (
        "Narrative asserts an external/lateral-movement main thread, but no "
        "confirmed hypothesis is backed by rule-seeded, non-benign evidence; "
        "treat this thread as a gap, not a confirmed storyline.",
        0.5,
    )


def _check_raw_evidence_dump(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    raw_evidence_patterns = (
        "#### raw evidence",
        "### raw evidence",
        "raw_evidence_rows",
        "raw evidence moved to reports/evidence/",
    )
    lowered_body = body.casefold()
    if any(pattern in lowered_body for pattern in raw_evidence_patterns):
        raw_row_dump = any(
            token in lowered_body
            for token in ("| none |", "| null |", "| - |", ": none", ": null", ": -")
        )
        if raw_row_dump:
            return (
                "Raw evidence rows should be moved to the appendix evidence export or reports/evidence JSON, not copied into the narrative body.",
                0.55,
            )
    return None, None


def _check_output_language(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    expected_lang = str(get_llm_settings().get("output_language", "ja")).lower()
    body_for_lang = re.sub(
        r"`[^`]+`|```.*?```|\[[^\]]+\]\([^)]+\)|\|[^\n]+\|", " ", body, flags=re.DOTALL
    )
    detected_lang = _detect_body_language(body_for_lang)
    if expected_lang in {"ja", "japanese"} and detected_lang == "en":
        return (
            f"Section body appears to be in English but LLM_OUTPUT_LANGUAGE='{expected_lang}'. LLM ignored language constraint.",
            0.4,
        )
    elif expected_lang in {"en", "english"} and detected_lang == "ja":
        return (
            f"Section body appears to be in Japanese but LLM_OUTPUT_LANGUAGE='{expected_lang}'.",
            0.4,
        )
    return None, None


def _check_open_questions(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    question_hits = _OPEN_QUESTION_RE.findall(body)
    if question_hits:
        return (
            f"Unresolved-question markers remain in body ({sorted(set(question_hits))[:3]}); investigate or remove before finalizing.",
            0.55,
        )
    return None, None


def _check_empty_body(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    stripped_body = re.sub(
        r"```.*?```|\|[^\n]+\||^[#\->\s]+$", "", body, flags=re.DOTALL | re.MULTILINE
    )
    if len(stripped_body.strip()) < 80:
        return (
            "Section body has no substantive narrative (< 80 chars after stripping tables / headings).",
            0.3,
        )
    return None, None


def _check_bullet_only(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    non_bullet_lines = [
        ln
        for ln in body.splitlines()
        if ln.strip() and not ln.strip().startswith(("-", "*", "#", "|", ">"))
    ]
    if (
        not non_bullet_lines
        and len([ln for ln in body.splitlines() if ln.strip().startswith(("-", "*"))])
        >= 3
    ):
        return (
            "Section has only bullet list, no narrative paragraph. Add a short prose summary.",
            0.6,
        )
    return None, None


def _check_kp_citation(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if re.search(r"KP-\d{4}", body):
        return (
            "Body contains KP-NNNN identifiers that should not appear as evidence citations.",
            0.65,
        )
    return None, None


def _check_hedge_no_citation(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if (
        _PURE_HEDGE_RE.search(body)
        and not EVIDENCE_ID_PATTERN.search(body)
        and not _FINDING_ID_RE.search(body)
        and not _TIMESTAMP_RE.search(body)
    ):
        return (
            "Section uses hedge language (may/could/possibly) without any timestamp, evidence_id, or finding_id citation.",
            0.5,
        )
    return None, None


def _check_citation_token_no_finding_id(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if EVIDENCE_ID_PATTERN.search(body) or FINDING_ID_PATTERN.search(body):
        return None, None
    if not _CITATION_TOKENS_RE.search(body):
        return None, None
    return (
        "Body references evidence/finding language without evidence_id or finding_id citation.",
        0.75,
    )


def _check_duplicate_paragraph(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if len(p.strip()) > 40]
    if len(paragraphs) != len(set(paragraphs)):
        return "Section contains duplicate paragraphs (LLM likely looped).", 0.5
    return None, None


def _check_out_of_range_timestamp(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    for match in _TIMESTAMP_RE.finditer(body):
        ts = match.group(0)
        try:
            year = int(ts[:4])
        except ValueError:
            continue
        if year > date.today().year + 1 or year < 1990:
            return (
                f"Body contains out-of-range timestamp '{ts}' — likely fabricated or NTFS overflow.",
                0.4,
            )
    return None, None


def _check_overused_evidence_id(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if ctx.db is None:
        return None, None
    used_ids = set(EVIDENCE_ID_PATTERN.findall(body))
    if not used_ids:
        return None, None
    overused: list[str] = []
    for eid in used_ids:
        count = ctx.db.execute(
            "SELECT COUNT(DISTINCT section_key) FROM section_evidence WHERE evidence_id = ?",
            (eid,),
        ).fetchone()[0]
        if count > 2:
            overused.append(eid)
    if overused:
        return f"Evidence id reused across > 2 sections: {overused[:3]}", 0.7
    return None, None


def _check_json_object_leak(
    body: str, ctx: _GateCtx
) -> tuple[str | None, float | None]:
    if re.search(r'^\s*\{.*"body"\s*:', body, re.DOTALL):
        return (
            "Section body contains JSON object leak (raw LLM response not parsed correctly).",
            0.3,
        )
    return None, None


_SEVERE_GATE_SUBSTRINGS = [
    "JSON object leak",
    "Section block failed",
    "answered_empty_answer",
    "unknown report template keypoint",
]


def _check_failure_spam(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if "Section block failed" in body or "Block skipped" in body:
        return "Section contains failure markers.", 0.15
    return None, None


_QUALITY_CHECKS: tuple[QualityCheck, ...] = (
    _check_placeholder_entity,
    _check_template_marker,
    _check_heading_mismatch,
    _check_timeline_ordering,
    _check_recommendations_strength,
    _check_verdict_inflation,
    _check_unsupported_intrusion_narrative,
    _check_raw_evidence_dump,
    _check_output_language,
    _check_open_questions,
    _check_empty_body,
    _check_bullet_only,
    _check_hedge_no_citation,
    _check_citation_token_no_finding_id,
    _check_duplicate_paragraph,
    _check_out_of_range_timestamp,
    _check_overused_evidence_id,
    _check_kp_citation,
    _check_json_object_leak,
    _check_failure_spam,
)


def _quality_gate_section(
    section_key: str,
    title: str,
    body: str,
    gaps: list[str],
    confidence: float,
    evidence_results: list[dict[str, Any]] | None = None,
    db: CaseDB | None = None,
    behaviors: tuple[str, ...] = (),
) -> tuple[list[str], float]:
    """Apply quality-gating checks to a section body, returning augmented gaps and adjusted confidence."""
    ctx = _GateCtx(
        section_key=section_key,
        title=title,
        evidence_results=evidence_results,
        db=db,
        behaviors=behaviors,
    )
    gated_gaps = list(gaps)
    gated_confidence = confidence
    for check in _QUALITY_CHECKS:
        note, cap = check(body, ctx)
        if note and note not in gated_gaps:
            gated_gaps.append(note)
        if cap is not None:
            gated_confidence = min(gated_confidence, cap)
    for gap in gated_gaps:
        if any(severe in gap for severe in _SEVERE_GATE_SUBSTRINGS):
            gated_confidence = min(gated_confidence, 0.2)
    return gated_gaps, gated_confidence
