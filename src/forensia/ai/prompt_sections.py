"""Prompt builders for report sections, classification, and review."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from forensia.ai.llm.schemas import (
    PARAGRAPH_NARRATE_SCHEMA,
    SECTION_AGENT_CHECK_SCHEMA,
    SECTION_AGENT_PLAN_SCHEMA,
    SECTION_OUTLINE_SCHEMA,
    question_classify_schema,
    structured_classify_schema,
)
from forensia.ai.sql_schema import (
    _load_app_catalog,
    build_investigation_framework,
)
from forensia.config import get_llm_settings

if TYPE_CHECKING:
    from forensia.db.database import CaseDB


from forensia.ai.prompt_context import (
    _build_event_id_guidance,
    _build_schema_guidance,
    _collect_event_ids,
    _collect_source_verdicts,
    _format_evidence_coverage,
    _format_evidence_row,
    _lang_instruction,
    _rows_to_markdown_table,
    _slim_report_brief_for_section,
    _summarize_context_sections,
    _time_range_guidance,
    _truncate_context_sections,
)
from forensia.ai.prompt_playbook import (
    _dfir_playbook,
    _format_artifact_inference,
    _load_schema_notes,
)


def _section_verification_block(verification_notes: list[str] | None) -> str:
    return f"verification_notes_from_prior_subsections: {verification_notes or []}\n\n"


def _section_evidence_block(raw_evidence_rows: list[dict] | None) -> str:
    if not raw_evidence_rows:
        return ""
    return (
        "You are also given normalized evidence summaries derived from row-level evidence. "
        "Treat them as reference only; do not paste raw tables or raw field dumps into the narrative body. "
        "Use them to write a short, normalized one-line summary of each relevant observation. "
        "If the section needs an appendix-style evidence note, place it in a dedicated Raw Evidence subsection with concise summaries only, never with NULL/None-heavy raw rows. "
    )


def _section_coverage_block(report_brief: dict) -> str:
    return _format_evidence_coverage(report_brief)


def _format_outline(outline: list[dict]) -> str:
    if not outline:
        return ""
    lines = ["<PRIOR_BLOCKS_IN_THIS_SECTION>"]
    for entry in outline:
        heading = entry.get("heading", "")
        summary = entry.get("summary", "")
        lines.append(f"  - **{heading}:** {summary}")
    lines.append("</PRIOR_BLOCKS_IN_THIS_SECTION>")
    return "\n".join(lines)


def _section_context_block(
    context_sections: dict[str, str], current_section_outline: list[dict]
) -> str:
    trimmed_context = _summarize_context_sections(context_sections)
    lines = [f"previous_sections: {trimmed_context}\n"]
    if current_section_outline:
        lines.append("<PRIOR_BLOCKS_IN_THIS_SECTION>")
        for entry in current_section_outline:
            heading = entry.get("heading", "")
            summary = entry.get("summary", "")
            lines.append(f"  - **{heading}:** {summary}")
        lines.append("</PRIOR_BLOCKS_IN_THIS_SECTION>")
    return "\n".join(lines)


def build_report_section_messages(
    section_meta: dict[str, Any],
    evidence_results: list[dict[str, Any]],
    context_sections: dict[str, str],
    template_body: str,
    report_brief: dict[str, Any] | None = None,
    section_heading: str = "",
    current_section_outline: list[dict] | None = None,
    verification_notes: list[str] | None = None,
    raw_evidence_rows: list[dict[str, Any]] | None = None,
    time_range: dict[str, str] | None = None,
    structured_digest: str | None = None,
) -> list[dict[str, str]]:
    """Build messages for report section writing with evidence and template context."""

    placeholder = "[INSUFFICIENT EVIDENCE: reason]"
    cov = _section_coverage_block(report_brief or {})
    if cov and str(section_meta.get("section") or "").strip() == "1_overview":
        cov = f"Use the following evidence coverage summary as the canonical Evidence Scope. Do not invent sources that are not listed.\n{cov}\n"
    evidence = [
        r for r in evidence_results if str(r.get("kind") or "rows") != "rows"
    ] or evidence_results
    sv = _collect_source_verdicts(evidence_results)
    strength = ""
    if sv and all(v != "confirmed" for v in sv):
        strength = "source_verdict guidance: Every supplied evidence result is below confirmed. Use cautious language only; avoid 'confirmed', 'executed', 'compromised', 'attack succeeded', or equivalent strong assertions unless additional evidence explicitly supports them.\n"
    app_cat = (
        ", ".join(
            f"{e}={i.get('category', '?')}"
            for e, i in _load_app_catalog().get("mappings", {}).items()
        )
        or "see investigation framework"
    )

    from forensia.ai.case_profile import get_profile_event_ids

    _pb_ids: set[int] | None = get_profile_event_ids()
    if _pb_ids is not None:
        collected = _collect_event_ids(evidence_results)
        if collected:
            _pb_ids.update(collected)
    exec_rules = ""
    if structured_digest:
        exec_rules = (
            "Write what the evidence shows, not instructions to the reader.\n"
            "Lead with the 2-3 strongest observations (with dates and counts) from "
            "STRUCTURED_OBSERVATIONS and confirmed findings. One sentence on open questions.\n"
            'Do not use phrases like "should be verified", "needs confirmation", "requires verification" more than once.\n'
        )
    digest_block = f"\n{structured_digest}\n" if structured_digest else ""
    system = (
        f"{_dfir_playbook('report_section', event_ids=_pb_ids)}\n{_time_range_guidance(time_range)}"
        "<TASK>You are a DFIR report writer. Fill the provided Markdown section template using only supplied evidence.</TASK>\n"
        "<INPUT_SCHEMA>section_meta, evidence_results, previous_sections, template_body</INPUT_SCHEMA>\n"
        "<RULES>\nconfidence_matrix: confidence >= 0.8 => 'confirmed'/'observed'; confidence >= 0.5 => 'strongly suggests'; confidence < 0.5 => 'requires further investigation'.\n"
        "Do not use 'confirmed' for findings or conclusions below 0.8 confidence.\n"
        "Match wording to confidence: use cautious language for low-confidence items.\n"
        f"no_invented_facts: Write placeholder for unsupported claims: {placeholder}\n"
        "no_causation: Correlation is not proof of causation.\n"
        "confirmed_hypotheses: Reflect in appropriate sections; refuted_hypotheses only in 'Discarded Hypotheses' subsection.\n"
        "Recommended actions must scale with evidence strength.\n"
        f"app_categories: {app_cat}\n{_format_artifact_inference()}{_build_event_id_guidance(evidence_results)}{strength}{exec_rules}</RULES>\n"
        f"{_section_evidence_block(raw_evidence_rows)}{cov or ''}"
        f"{digest_block}"
        "<EXAMPLE verdict=\"report_section\">\nInput: section_meta={'section': '3_technical'}, evidence_results=[{'sample_rows': [{'evidence_id': 'E1', 'process_name': 'powershell.exe'}]}]\nOutput: \"## Process Execution\\n\\nOne suspicious process was observed: powershell.exe (evidence_id: E1).\"\n</EXAMPLE>\n"
        f"Output Markdown only (no fences). {_lang_instruction()}"
    )
    raw_block = ""
    if raw_evidence_rows:
        raw_block = f"\nnormalized_evidence_rows (summaries only; do not mirror raw tables):\n{_rows_to_markdown_table(raw_evidence_rows)}\n"
    user = (
        f"section_meta: {section_meta}\ncurrent_subsection: {section_heading or '(full section)'}\n"
        f"report_brief: {_slim_report_brief_for_section(report_brief or {}, str(section_meta.get('section') or ''))}\n"
        f"{_section_context_block(context_sections, current_section_outline or [])}"
        f"{_section_verification_block(verification_notes)}"
        f"evidence_results: {evidence}\n{raw_block}\n"
        "Complete only this current template block by replacing placeholders with evidence-based content.\n"
        f"{template_body}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_question_classify_messages(
    question: str,
    block_heading: str,
    evidence_rows: list[dict],
    expected_shape: dict | None,
    time_range: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: question_classifier.
    Goal: decide answer status and pick which evidence_rows answer the question.
    Output: {status, picked_row_indices, rationale}
    """
    schema = question_classify_schema(len(evidence_rows))
    system = (
        "<TASK>You are a question_classifier. Decide the answer status and pick which evidence rows answer the question. "
        "Do NOT write narrative.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "status": "answered | partial | not_found | not_searched | wrong_query",\n'
        '  "picked_row_indices": [0-based row indices into evidence_rows (e.g. [0, 2, 5]). Each value MUST be an integer between 0 and len(evidence_rows)-1],\n'
        '  "rationale": "string"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Output picked_row_indices as integer array indices (0-based). Never invent identifiers or use placeholders like 'evidence_rows[0]'.\n"
        "</RULES>"
    )
    user = (
        f"question: {question}\n"
        f"block_heading: {block_heading}\n"
        f"evidence_rows: {json.dumps(evidence_rows[:20], default=str, ensure_ascii=False)}\n"
        f"expected_shape: {json.dumps(expected_shape or {}, ensure_ascii=False, default=str)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], schema


def build_structured_classify_messages(
    question: str,
    block_heading: str,
    evidence_rows: list[dict],
    expected_shape: dict | None,
    time_range: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: structured_classifier.
    Goal: decide answer status and pick which evidence_rows answer a reusable QuestionSpec.
    Output: {status, picked_row_indices, rationale}
    """
    schema = structured_classify_schema(len(evidence_rows))
    system = (
        "<TASK>You are a structured_classifier. Decide the answer status and pick which evidence rows answer the question. "
        "Do NOT write narrative.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "status": "answered | partial | not_found | not_searched | wrong_query",\n'
        '  "picked_row_indices": [0-based row indices into evidence_rows (e.g. [0, 2, 5]). Each value MUST be an integer between 0 and len(evidence_rows)-1],\n'
        '  "rationale": "string"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Output picked_row_indices as integer array indices (0-based). Never invent identifiers or use placeholders like 'evidence_rows[0]'.\n"
        "Use expected_shape only as a contract for judging completeness; do not create rows or values that are not in evidence_rows.\n"
        "</RULES>"
    )
    user = (
        f"question: {question}\n"
        f"block_heading: {block_heading}\n"
        f"evidence_rows: {json.dumps(evidence_rows[:20], default=str, ensure_ascii=False)}\n"
        f"expected_shape: {json.dumps(expected_shape or {}, ensure_ascii=False, default=str)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], schema


def _filter_prior_runs_by_heading(
    prior_runs: list[dict[str, Any]], block_heading: str, limit: int = 6
) -> list[dict[str, Any]]:
    """Filter prior runs by block_heading match."""
    heading_matches = [
        run
        for run in prior_runs
        if str(run.get("block_heading") or "") == str(block_heading)
    ]
    return heading_matches[-limit:]


def build_section_agent_plan_messages(
    *,
    section_key: str,
    section_title: str,
    block_heading: str,
    template_body: str,
    report_brief: dict[str, Any],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    findings_snapshot: list[dict[str, Any]],
    keypoint_catalog: list[dict[str, str]],
    query_template_catalog: list[dict[str, Any]],
    prior_runs: list[dict[str, Any]],
    reusable_facts: list[dict[str, Any]],
    reusable_evidence: list[dict[str, Any]],
    memory_context_md: str = "",
    time_range: dict[str, str] | None = None,
    evidence_keypoints: list[str] | None = None,
    prior_section_keypoints: list[str] | None = None,
    question_spec: dict[str, Any] | None = None,
    db: CaseDB | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """Build messages for the section agent's plan phase — decide next evidence action.

    Supports action types: sql, template, keypoint, facts, write. Includes
    error-recovery logic to switch to keypoint after repeated SQL failures."""

    schema_guidance = _build_schema_guidance("evtx_events", db=db)

    EXAMPLE_SECTION_PLAN = """
<EXAMPLE verdict="section_plan">
Input: block_heading='Logon Summary', template_body='## Logon Summary\\nList all logons.', reusable_facts empty, query_template_catalog has logon templates.
Output: {"action": "sql", "purpose": "Find all logon events", "sql": "SELECT evidence_id, computer, user_name, src_ip, logon_type, timestamp FROM evtx_events WHERE event_id IN (4624, 4625)"}
</EXAMPLE>
"""
    EXAMPLE_SECTION_PLAN_TEMPLATE = """
<EXAMPLE verdict="section_plan_template">
Input: block_heading='Service Creation', template_body='## Service Creation\\nFind malicious services.', template_id available, params extractable.
Output: {"action": "template", "template_id": "service-creation", "params": {"computer": "HOST-A"}}
</EXAMPLE>
"""
    EXAMPLE_SECTION_PLAN_KEYPOINT = """
<EXAMPLE verdict="section_plan_keypoint">
Input: block_heading='Endpoint identity' with template hint evidence_keypoints=[overview_hosts]. The keypoint_catalog includes {"name": "overview_hosts", "description": "Distinct hosts observed in evidence"}.
Output: {"action": "keypoint", "keypoint": "overview_hosts", "purpose": "List hosts observed in evidence"}
</EXAMPLE>
"""

    schema_notes = _load_schema_notes()
    schema_notes_block = (
        f"<SCHEMA_NOTES>\n{schema_notes}\n</SCHEMA_NOTES>\n" if schema_notes else ""
    )

    from forensia.ai.case_profile import get_profile_event_ids

    _sa_ev = get_profile_event_ids()
    _sa_tables: set[str] | None = None
    if db is not None:
        try:
            _rows = db.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='main'"
            ).fetchall()
            _sa_tables = {str(r[0]) for r in _rows if r[0]}
        except Exception:
            pass
    system = (
        f"{_dfir_playbook('section_agent_plan', event_ids=_sa_ev, tables=_sa_tables)}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a DFIR section-planning agent. Decide next evidence-gathering action for report block.</TASK>\n"
        "<INPUT_SCHEMA>section_key, block_heading, template_block, structured_memory_context, findings_snapshot, keypoint_catalog, query_template_catalog, prior_runs</INPUT_SCHEMA>\n"
        f"{schema_notes_block}"
        "<TIME_RULES>\nIMPORTANT: The case data may be from a DIFFERENT YEAR than the current date. "
        "DO NOT use datetime('now') or CURRENT_TIMESTAMP in SQL queries — these refer to the current system time, not the case time. "
        "If a time filter is needed, use a broad time range that covers the case data window.\n</TIME_RULES>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "action": "sql|template|keypoint|facts|write",\n'
        '  "keypoint": "exact keypoint name when action=keypoint, else null",\n'
        '  "sql": "SELECT ...", '
        '  "template_id": "template-name", '
        '  "params": {"key": "value"},\n'
        '  "enough_to_write": true|false\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "facts_first: Reuse reusable_section_facts if they already answer the block question.\n"
        "question_spec_first: If semantic_question_spec is present, satisfy that contract before following wording quirks in the template.\n"
        "keypoint_preferred: Use keypoint when it matches the block topic.\n"
        "template_preferred: Use template_id+params instead of raw sql.\n"
        "error_recovery: If the prior runs show two consecutive zero-row OR query_error results, the next action must be keypoint (not sql/template). "
        "Immediately after a query_error, do NOT retry SQL — switch to keypoint or template action.\n"
        "stop_early: Set action=write when enough evidence exists.\n"
        "If template_evidence_keypoints is non-empty and action=keypoint is appropriate, prefer those names verbatim.\n"
        "Avoid re-using keypoints already used by other sections (listed in prior_section_keypoints_in_this_report). Choose different evidence for this section.\n"
        "</RULES>\n"
        f"{build_investigation_framework(db)}"
        f"{schema_guidance}"
        f"{EXAMPLE_SECTION_PLAN}{EXAMPLE_SECTION_PLAN_TEMPLATE}{EXAMPLE_SECTION_PLAN_KEYPOINT}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"report_brief: {_slim_report_brief_for_section(report_brief, section_key)}\n\n"
        f"previous_sections: {_truncate_context_sections(context_sections)}\n\n"
        f"current_section_outline: {_format_outline(current_section_outline or [])}\n\n"
        f"findings_snapshot: {findings_snapshot[:10]}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"keypoint_catalog: {keypoint_catalog}\n\n"
        f"query_template_catalog: {query_template_catalog}\n\n"
        f"template_evidence_keypoints: {evidence_keypoints or []}\n\n"
        f"semantic_question_spec: {question_spec or {}}\n\n"
        f"prior_section_keypoints_in_this_report: {prior_section_keypoints or []}\n\n"
        f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_AGENT_PLAN_SCHEMA


def build_section_agent_check_messages(
    *,
    section_key: str,
    section_title: str,
    block_heading: str,
    template_body: str,
    collected_results: list[dict[str, Any]],
    latest_result: dict[str, Any],
    prior_runs: list[dict[str, Any]],
    reusable_facts: list[dict[str, Any]],
    reusable_evidence: list[dict[str, Any]],
    memory_context_md: str = "",
    time_range: dict[str, str] | None = None,
    question_spec: dict[str, Any] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """Build messages for the section agent's check phase — verify evidence sufficiency.

    Injects contradiction-history context and status taxonomy
    (answered/partial/not_found/not_searched/insufficient_evidence/wrong_query)."""

    contradicted_history = [
        run
        for run in prior_runs
        if run.get("verdict") in {"block_contradicted", "refuted"}
    ]
    EXAMPLE_SECTION_CHECK = """
<EXAMPLE verdict="section_check">
Input: collected_results has 3 rows with process_name='powershell.exe', template_body='## Suspicious Processes\\nList suspicious processes.'.
Output: {"verdict": "block_supported", "status": "answered", "rationale": "Evidence shows powershell.exe execution. Block can be written.", "fact_updates": []}
</EXAMPLE>
"""
    EXAMPLE_SECTION_CHECK_REFUTED = """
<EXAMPLE verdict="section_check_contradicted">
Input: collected_results empty, template_body='## Malicious Services\\nList malicious services.'. prior runs show queries returned nothing.
Output: {"verdict": "block_contradicted", "status": "not_found", "rationale": "No service-related evidence found in collected results.", "missing_questions": ["Query for event_id 4697/7045 returned 0 rows earlier"]}
</EXAMPLE>
"""
    from forensia.ai.case_profile import get_profile_event_ids

    _sac_ids: set[int] | None = get_profile_event_ids()
    if _sac_ids is not None:
        for result in (collected_results or []) + [latest_result]:
            if not isinstance(result, dict):
                continue
            for row in result.get("sample_rows") or []:
                if not isinstance(row, dict):
                    continue
                ev = row.get("event_id")
                if ev is not None:
                    try:
                        _sac_ids.add(int(ev))
                    except TypeError, ValueError:
                        pass
    system = (
        f"{_dfir_playbook('section_agent_check', event_ids=_sac_ids)}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a DFIR section-check agent. Judge if collected evidence suffices to write the report block.</TASK>\n"
        "<INPUT_SCHEMA>collected_results, latest_result, reusable_section_facts, reusable_section_evidence, structured_memory_context, template_block</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "verdict": "block_supported|block_needs_more|block_contradicted",\n'
        '  "status": "answered|partial|not_found|not_searched|insufficient_evidence|wrong_query",\n'
        '  "rationale": "explanation string",\n'
        '  "missing_questions": [],\n'
        '  "fact_updates": [{"fact_type": "string", "fact_key": "string", "fact_value": "any", "confidence": 0.9}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "block_supported: Evidence answers the block question; ready to write.\n"
        "If semantic_question_spec is present, judge sufficiency against its required_fields, required_sources, render_columns, and status_rules.\n"
        "block_needs_more: More evidence needed; another query may help.\n"
        "block_contradicted: Evidence contradicts the template claim; explain contradiction.\n"
        "status rules: answered when evidence supports the block, partial when some evidence exists but not enough, not_found only after an appropriate search has been run and returned zero rows repeatedly, not_searched when the matching query/keypoint was never executed, wrong_query when the search hit the wrong artifact family, insufficient_evidence for other unresolved cases.\n"
        "Never use not_found unless the relevant search has actually run.\n"
        "block_supported requires at least 2 DIFFERENT KINDS of evidence (different event_id families, different keypoint sources). If all evidence is the same type (e.g. all 4648 findings), verdict should be 'partial' or 'needs_more', not 'block_supported'.\n"
        "</RULES>\n"
    )
    if contradicted_history:
        system += "PREVIOUSLY CONTRADICTED ATTEMPTS ARE SHOWN ABOVE - avoid the same contradiction. "
    system += f"{EXAMPLE_SECTION_CHECK}{EXAMPLE_SECTION_CHECK_REFUTED}Output JSON only. {_lang_instruction()} "
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
        f"semantic_question_spec: {question_spec or {}}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"latest_result: {latest_result}\n\n"
        f"collected_results: {collected_results}\n\n"
    )
    if contradicted_history:
        user += f"contradicted_attempts_previous_iterations: {contradicted_history}\n\n"
    user += f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_AGENT_CHECK_SCHEMA


def build_section_outline_messages(
    template_body: str,
    relevant_evidence: list[dict],
    time_range: dict[str, str] | None = None,
    section_meta: dict | None = None,
    prior_section_keypoints: list[str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: section_outliner.
    Goal: assign each evidence item to ONE paragraph; produce outline JSON.
    """
    system = (
        "<TASK>You are a section_outliner. Decide what concrete claims this section should make based on the supplied evidence rows, and assign supporting evidence IDs to each claim. Do NOT write narrative prose — only output the outline JSON.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "outline": [{\n'
        '    "heading": "exact heading from template (verbatim)",\n'
        "    \"key_points\": [\"concrete claims, each grounded in 1-3 specific evidence rows. Each claim should name an actor/action/target/timestamp where possible. NO meta-statements like 'Summary of findings' or 'List of activity'\"],\n"
        '    "evidence_ids": ["actual evidence_id strings copied from the evidence_rows above (e.g. evtx-security-000000000122). NOT keypoint names. NOT finding_ids."]\n'
        "  }]\n"
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "When 5+ evidence rows share the same pattern (same event_id, same finding_id prefix), summarize them as ONE key_point referencing 1-2 representative evidence_ids, not all of them.\n"
        "Each key_point MUST be a falsifiable claim, not a topic label.\n"
        "If the evidence is insufficient to make a substantive claim, return an empty outline list.\n"
        "If prior_section_keypoints is non-empty, avoid re-using those same keypoints for this section — choose different evidence.\n"
        "If evidence_id is '?' (unknown), do NOT include it in evidence_ids array — only reference evidence with real identifiers.\n"
        "Do not use raw internal IDs (gap-*, H-*, KP-*) in prose. Use human-readable descriptions instead.\n"
        "</RULES>\n"
        "<EXAMPLE>\n"
        'Input evidence rows: [{"evidence_id": "evtx-security-000000000122", "summary": "4648 logon WS-SALES-03->jdoe 2024-05-14 14:33:54"}, {"evidence_id": "evtx-security-000000000152", "summary": "4648 logon WS-SALES-03->jdoe 2024-05-14 14:34:28"}]\n'
        'Output: {"outline": [{"heading": "Executive Summary", "key_points": ["Two explicit-credential logon attempts (4648) from WS-SALES-03$ targeting jdoe were observed within 60 seconds on 2024-05-14"], "evidence_ids": ["evtx-security-000000000122"]}]}\n'
        "</EXAMPLE>\n"
        "Output JSON only. "
    )
    evidence_summary = "\n".join(
        _format_evidence_row(e) for e in (relevant_evidence or [])[:30]
    )
    user = (
        f"section_meta: {json.dumps(section_meta, ensure_ascii=False, default=str)}\n"
        f"available_evidence:\n{evidence_summary or 'No evidence available.'}\n"
        f"prior_section_keypoints: {prior_section_keypoints or []}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_OUTLINE_SCHEMA


def build_paragraph_narrate_messages(
    heading: str,
    key_points: list[str],
    evidence_rows: list[dict],
    template_body: str,
    language: str = "en",
    structured_digest: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    settings = get_llm_settings()
    language = str(settings.get("output_language", language))
    """role: section_narrator.
    Goal: write ONE markdown paragraph for the given heading using the evidence.
    NO access to other sections, NO full report_brief, NO findings list.
    """
    digest_block = f"\n{structured_digest}\n" if structured_digest else ""
    exec_summary_rules = ""
    if structured_digest:
        exec_summary_rules = (
            "Write what the evidence shows, not instructions to the reader.\n"
            "Lead with the 2-3 strongest observations (with dates and counts) from "
            "STRUCTURED_OBSERVATIONS and confirmed findings. One sentence on open questions.\n"
            'Do not use phrases like "should be verified", "needs confirmation", "requires verification" more than once.\n'
        )
    system = (
        "<TASK>You are a section_narrator. Write one markdown paragraph for the given heading using the supplied evidence. "
        "Cite evidence_ids inline. Keep the paragraph factual and concise.</TASK>\n"
        f"Language: {language}\n"
        '<OUTPUT_SCHEMA>Return exactly one JSON object: {"body": "single markdown paragraph"}.</OUTPUT_SCHEMA>\n'
        "<RULES>\n"
        "The response MUST be valid JSON and MUST contain the key `body`. Do not return a bare string.\n"
        "Citation count: cite AT MOST 2-3 representative evidence_ids per paragraph. If many similar findings exist (same event_id pattern), state the count and cite 1-2 examples.\n"
        "Citation format: cite raw `evidence_id` strings only (e.g. evtx-security-000000000122). Do NOT cite `finding_id` (e.g. windows-security-4648-logon-explicit-creds-0001) — those are finding labels, not evidence references. If the input shows a finding_id without an evidence_id, OMIT the citation entirely instead of using the finding_id.\n"
        "No KP-NNNN identifiers. Do not use raw internal IDs (gap-*, H-*, KP-*) in prose. Use human-readable descriptions instead.\n"
        "DATE FORMAT: Always use ISO 8601 date format (YYYY-MM-DD) for all dates and timestamps. "
        "Never use localized date formats (e.g., '2015年3月22日' or 'March 22, 2015'). "
        "Timestamps in narrative should use the format 'YYYY-MM-DD HH:MM:SS UTC'.\n"
        "No meta-statements: write what was observed, not what was reviewed. Avoid 'investigation covered', 'scope included', 'comprehensive review of' style phrasing.\n"
        "Do NOT write `## {heading}` in your output — the heading is prepended by the renderer. Only write paragraph content below the heading.\n"
        "If the status is not_searched or not_found, this function should not be called. If you see such a status, output nothing.\n"
        "Key points may be prefixed with verdict labels: [confirmed], [refuted], [finding, confidence=N]. Refuted items may only be mentioned as ruled-out. Confirmed and refuted items must not be blended into one claim.\n"
        'If a row has `"citable": false`, do NOT invent an evidence_id for it. State the factual claim without a citation token.\n'
        f"{exec_summary_rules}"
        "</RULES>\n"
        f"{digest_block}"
        "<EXAMPLE_GOOD>\n"
        "Eight explicit-credential logon attempts (4648) targeting jdoe, admin02, and tempuser were observed from WS-SALES-03$ between 14:33 and 15:55 on 2024-05-14 (evtx-security-000000000122, evtx-security-000000000152). All attempts succeeded and produced no subsequent 4624 from the same src_ip, suggesting localhost credential injection rather than network-reused access.\n"
        "</EXAMPLE_GOOD>\n"
        "<EXAMPLE_BAD>\n"
        "The investigation revealed multiple high-severity findings related to logon attempts using explicit credentials (windows-security-4648-logon-explicit-creds-0001, ..., 0011).\n"
        "</EXAMPLE_BAD>\n"
        "<EXAMPLE_JSON>\n"
        '{"body":"Eight explicit-credential logon attempts targeting jdoe and admin02 were observed from WS-SALES-03$ on 2024-05-14 (evtx-security-000000000122, evtx-security-000000000152)."}\n'
        "</EXAMPLE_JSON>"
    )
    user = (
        f"Heading: {heading}\n"
        f"Key points: {json.dumps(key_points, ensure_ascii=False, default=str)}\n"
        f"Template body context: {template_body[:500]}\n"
        f"Evidence rows: {json.dumps(evidence_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], PARAGRAPH_NARRATE_SCHEMA


SECTION_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["pass", "rewrite"]},
        "problems": {"type": "array", "items": {"type": "string"}},
        "guidance": {"type": "string"},
    },
    "required": ["verdict", "problems", "guidance"],
}


def build_section_review_messages(
    heading: str,
    body: str,
    digest: str | None,
    deterministic_problems: list[str],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    system = (
        "<TASK>You are a section_reviewer. Evaluate the narrative paragraph for the given heading. "
        "Check: does it state what happened, who/when, and what remains open? Does it cite at most 2-3 "
        "representative evidence IDs (not enumerate findings)? Is it factual, concise, and self-contained? "
        "Output verdict 'pass' if acceptable, 'rewrite' if needs improvement, with specific guidance.</TASK>\n"
        '<OUTPUT_SCHEMA>{"verdict": "pass"|"rewrite", "problems": ["..."], "guidance": "..."}</OUTPUT_SCHEMA>\n'
        "<RULES>\n"
        "- Executive Summary must state what happened, who/when, and what remains open in ≤2 paragraphs\n"
        "- At most 3 representative evidence IDs per paragraph\n"
        "- Must not enumerate findings or list finding_ids\n"
        "- Must not contain internal IDs (gap-*, H-*, KP-*)\n"
        "- Must not contain pseudo-citations like (some_label)\n"
        "- If body is the insufficient-evidence placeholder but digest has data, always rewrite\n"
        "</RULES>\n"
    )
    digest_block = f"\nSection table digest:\n{digest}\n" if digest else ""
    problems_block = (
        f"\nDeterministic problems found:\n{chr(10).join('- ' + p for p in deterministic_problems)}\n"
        if deterministic_problems
        else ""
    )
    user = f"Heading: {heading}\n\nBody:\n{body}\n{digest_block}{problems_block}"
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_REVIEW_SCHEMA

