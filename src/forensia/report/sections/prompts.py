"""Prompt builders for optional report-section narration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from forensia.config import get_llm_settings
from forensia.context.prompt_context import _instrument_retrieval
from forensia.llm.schemas import PARAGRAPH_NARRATE_SCHEMA
from forensia.report.sections.evidence_projection import project_report_evidence_rows

if TYPE_CHECKING:
    from forensia.db.database import CaseDB


def build_paragraph_narrate_messages(
    heading: str,
    key_points: list[str],
    evidence_rows: list[dict],
    template_body: str,
    language: str = "en",
    structured_digest: str | None = None,
    report_context: dict[str, Any] | None = None,
    db: CaseDB | None = None,
    session_id: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    settings = get_llm_settings()
    language = str(settings.get("output_language", language))
    """role: section_narrator.
    Goal: write ONE markdown paragraph for the given heading using the evidence.
    NO access to other sections, NO full report_brief, NO findings list.
    """
    is_executive_summary = heading.strip().lower() == "executive summary"
    digest_block = f"\n{structured_digest}\n" if structured_digest else ""
    exec_summary_rules = ""
    if structured_digest and is_executive_summary:
        exec_summary_rules = (
            "Write what the evidence shows, not instructions to the reader.\n"
            "Lead with the 2-3 strongest observations (with dates and counts) from "
            "STRUCTURED_OBSERVATIONS and confirmed findings. The observations are ordered "
            "by materiality; do not let a lower-impact Key point or Evidence row displace a "
            "stronger observation near the top. If two or more artifact families are present, "
            "cover at least two distinct families. One sentence on open questions.\n"
            'Do not use phrases like "should be verified", "needs confirmation", "requires verification" more than once.\n'
        )
    # The Executive Summary is synthesized from the deterministic incident
    # brief. A block-local query can still support the rest of the overview,
    # but must not narrow the summary to whichever artifact family it returned.
    prompt_key_points = [] if is_executive_summary else key_points
    prompt_evidence_rows = (
        []
        if is_executive_summary
        else project_report_evidence_rows(evidence_rows, db=db)
    )
    system = (
        "<TASK>You are a section_narrator. Write one markdown paragraph for the given heading using the supplied evidence. "
        "Cite evidence_ids inline. Keep the paragraph factual and concise.</TASK>\n"
        f"Language: {language}\n"
        '<OUTPUT_SCHEMA>Return exactly one JSON object: {"body": "single markdown paragraph"}.</OUTPUT_SCHEMA>\n'
        "<RULES>\n"
        "The response MUST be valid JSON and MUST contain the key `body`. Do not return a bare string.\n"
        "Citation count: cite AT MOST 2-3 representative evidence_ids per paragraph. If many similar findings exist (same event_id pattern), state the count and cite 1-2 examples.\n"
        "Citation format: cite raw `evidence_id` strings only (e.g. evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122). Do NOT cite `finding_id` (e.g. windows-security-4648-logon-explicit-creds-0001) — those are finding labels, not evidence references. If the input shows a finding_id without an evidence_id, OMIT the citation entirely instead of using the finding_id.\n"
        "No KP-NNNN identifiers. Do not use raw internal IDs (gap-*, H-*, KP-*) in prose. Use human-readable descriptions instead.\n"
        "DATE FORMAT: Always use ISO 8601 date format (YYYY-MM-DD) for all dates and timestamps. "
        "Never use localized date formats (e.g., '2015年3月22日' or 'March 22, 2015'). "
        "Timestamps in narrative should use the format 'YYYY-MM-DD HH:MM:SS UTC'.\n"
        "No meta-statements: write what was observed, not what was reviewed. Avoid 'investigation covered', 'scope included', 'comprehensive review of' style phrasing.\n"
        "For time-basis claims, use only explicit timezone/normalization/gap facts in report_context, the template, or evidence rows. If an assumption or conflict is not established, state that limitation instead of inventing one.\n"
        "Do NOT write `## {heading}` in your output — the heading is prepended by the renderer. Only write paragraph content below the heading.\n"
        "If the status is not_searched or not_found, this function should not be called. If you see such a status, output nothing.\n"
        "Key points may be prefixed with verdict labels: [confirmed], [refuted], [finding, confidence=N]. Refuted items may only be mentioned as ruled-out. Confirmed and refuted items must not be blended into one claim.\n"
        'If a row has `"citable": false`, do NOT invent an evidence_id for it. State the factual claim without a citation token.\n'
        f"{exec_summary_rules}"
        "</RULES>\n"
        f"{digest_block}"
        "<EXAMPLE_GOOD>\n"
        "Eight explicit-credential logon attempts (4648) targeting jdoe, admin02, and tempuser were observed from WS-SALES-03$ between 14:33 and 15:55 on 2024-05-14 (evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122, evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000152). All attempts succeeded and produced no subsequent 4624 from the same src_ip, suggesting localhost credential injection rather than network-reused access.\n"
        "</EXAMPLE_GOOD>\n"
        "<EXAMPLE_BAD>\n"
        "The investigation revealed multiple high-severity findings related to logon attempts using explicit credentials (windows-security-4648-logon-explicit-creds-0001, ..., 0011).\n"
        "</EXAMPLE_BAD>\n"
        "<EXAMPLE_JSON>\n"
        '{"body":"Eight explicit-credential logon attempts targeting jdoe and admin02 were observed from WS-SALES-03$ on 2024-05-14 (evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122, evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000152)."}\n'
        "</EXAMPLE_JSON>"
    )
    user = (
        f"Heading: {heading}\n"
        f"Key points: {json.dumps(prompt_key_points, ensure_ascii=False, default=str)}\n"
        f"<TEMPLATE_CONTEXT>\n{template_body}\n</TEMPLATE_CONTEXT>\n"
        f"Report context: {json.dumps(report_context or {}, default=str, ensure_ascii=False)}\n"
        f"Evidence rows: {json.dumps(prompt_evidence_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    _instrument_retrieval(
        db,
        session_id=session_id,
        scope_kind="paragraph_narrate",
        scope_id=heading,
        phase="paragraph_narrate",
        source_kind="paragraph_narrate_builder",
        query_terms=[heading],
        candidate_count=len(system) + len(user),
        selected_refs=[],
        selected_chars=len(system) + len(user),
        budget=0,
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], PARAGRAPH_NARRATE_SCHEMA
