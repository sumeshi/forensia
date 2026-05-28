from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from forensia.config import get_llm_settings
from forensia.core.session import ENTITY_TYPE_ALIASES, Hypothesis, PlannedQuery
from forensia.ai.sql_schema import build_investigation_framework, _load_app_catalog, _load_fp_reduction_guidance


@dataclass(frozen=True, slots=True)
class RuleContext:
    rule_id: str
    correlate_event_ids: list[int]
    confirm_when: dict[str, Any]
    refute_when: dict[str, Any]


@lru_cache(maxsize=1)
def _get_cached_rules() -> list[Any]:
    """Load and cache all rules at module level to avoid repeated file I/O."""
    from forensia.rules.loader import load_rules_from_dir
    from pathlib import Path
    rules_path = Path(__file__).parent.parent / "rulepacks"
    return load_rules_from_dir(rules_path)


def resolve_rule_context(hypothesis: Hypothesis | None) -> RuleContext | None:
    """Resolve rule context for a hypothesis by looking up source rule declarations.
    
    If the hypothesis was generated from a rule finding, return the rule's
    correlate_with, confirm_when, and refute_when declarations.
    Merges multiple source_rule_ids into a single RuleContext.
    """
    if hypothesis is None or not hasattr(hypothesis, 'source_rule_ids'):
        return None
    source_rule_ids = getattr(hypothesis, 'source_rule_ids', [])
    if not source_rule_ids:
        return None
    
    rules = _get_cached_rules()
    merged_correlate_ids: set[int] = set()
    merged_confirm_when: dict[str, Any] = {}
    merged_refute_when: dict[str, Any] = {}
    found_rule_id = source_rule_ids[0]
    
    for rule_id in source_rule_ids:
        for rule in rules:
            if rule.id == rule_id:
                for corr in rule.correlate_with:
                    merged_correlate_ids.update(corr.event_ids)
                if rule.hypotheses:
                    confirm = rule.hypotheses[0].confirm_when or {}
                    refute = rule.hypotheses[0].refute_when or {}
                    # Merge shallow dicts, first rule takes precedence for conflicts
                    if confirm and not merged_confirm_when:
                        merged_confirm_when = dict(confirm)
                    if refute and not merged_refute_when:
                        merged_refute_when = dict(refute)
                break
    
    return RuleContext(
        rule_id=found_rule_id,
        correlate_event_ids=sorted(merged_correlate_ids),
        confirm_when=merged_confirm_when,
        refute_when=merged_refute_when,
    )


@lru_cache(maxsize=1)
def _load_schema_hints() -> dict[str, dict[str, Any]]:
    """Load schema hints from rulepacks/_schema/*.yaml for planner guidance.
    
    Cached at module level to avoid repeated file I/O.
    """
    import yaml
    from pathlib import Path
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    hints: dict[str, dict[str, Any]] = {}
    if not schema_dir.exists():
        return hints
    for path in schema_dir.glob("*.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and isinstance(data, dict):
                table_name = data.get("table")
                if table_name:
                    hints[str(table_name)] = data
        except Exception:
            continue
    return hints


@lru_cache(maxsize=1)
def _load_event_id_hints() -> dict[int, dict[str, Any]]:
    import yaml
    from pathlib import Path

    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    path = schema_dir / "event_ids.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    events: dict[int, dict[str, Any]] = {}
    raw_events = data.get("events") if isinstance(data, dict) else {}
    if not isinstance(raw_events, dict):
        return {}
    for key, value in raw_events.items():
        try:
            event_id = int(key)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            events[event_id] = value
    return events


def _lang_instruction() -> str:
    output = str(get_llm_settings()["output_language"])
    return f"All string values must be written in {output}. JSON keys and enum values (verdict, status, entity_type) remain in English."


def _output_language() -> str:
    return str(get_llm_settings()["output_language"]).lower()


def _mandatory_missing_checks_guidance() -> str:
    return """
Mandatory missing_checks:
   - If a logon is confirmed → add: 'Other host logons from the same src_ip', 'Presence of 4688/4104 within 15 minutes after logon'
   - If process execution is confirmed → add: 'Confirm parent process name', 'Check whether the executing user aligns with normal duties'
   - If service/task creation is confirmed → add: 'Path of the executable behind the service', 'Presence of 7036 (service start)'
   - If Defender disable is confirmed → add: 'Presence of 4688/4104 immediately afterward', 'Correlation with 1116 (malware detection)'
   - If account-related: add: 'Owner organization confirmation', 'User interview required'
"""


def _slim_findings(items: list[dict[str, Any]], max_findings: int) -> list[dict[str, Any]]:
    fields = ("finding_id", "title", "severity", "confidence", "status", "summary")
    slimmed: list[dict[str, Any]] = []
    for item in items[:max_findings]:
        slimmed.append({field: item.get(field) for field in fields})
    return slimmed


def _truncate_context_sections(context_sections: dict[str, str], max_chars: int = 1500) -> dict[str, str]:
    trimmed: dict[str, str] = {}
    for section_key, body in context_sections.items():
        text = str(body or "").strip()
        if not text:
            continue
        trimmed[str(section_key)] = text[:max_chars]
    return trimmed


def _build_schema_guidance(table_name: str = "evtx_events") -> str:
    """Build the schema_card section of planner prompts (PROMPT-6).

    Centralized so hypothesis-plan and section-plan prompts cannot drift.
    """
    schema_hints = _load_schema_hints()
    if not schema_hints:
        return ""
    table_hints = schema_hints.get(table_name, {})
    cols = table_hints.get("columns", [])
    extractors = table_hints.get("json_field_extractors", {})
    parts: list[str] = []
    if cols:
        parts.append(
            f"Schema guidance for {table_name} table — allowed_columns: {cols}. "
            "Do NOT write column names outside this list in SELECT/WHERE clauses. "
        )
    if extractors:
        parts.append(
            f"For fields not in allowed_columns, use json_field_extractors: {extractors}. "
        )
    return "".join(parts)


def _collect_event_ids(evidence_results: list[dict[str, Any]]) -> list[int]:
    event_ids: list[int] = []
    seen: set[int] = set()
    for result in evidence_results:
        for row in (result.get("sample_rows") or []) + (result.get("head_rows") or []) + (result.get("tail_rows") or []):
            if not isinstance(row, dict):
                continue
            value = row.get("event_id")
            try:
                event_id = int(value)
            except (TypeError, ValueError):
                continue
            if event_id in seen:
                continue
            seen.add(event_id)
            event_ids.append(event_id)
    return event_ids


def _build_event_id_guidance(evidence_results: list[dict[str, Any]]) -> str:
    event_hints = _load_event_id_hints()
    if not event_hints:
        return ""
    parts: list[str] = []
    for event_id in _collect_event_ids(evidence_results):
        hint = event_hints.get(event_id)
        if not hint:
            continue
        allowed_claims = hint.get("allowed_claims") or []
        disallowed = hint.get("disallowed_without_extra") or []
        required_fields = hint.get("required_fields") or []
        parts.append(
            f"Event ID {event_id} ({hint.get('title', 'unknown')}): required_fields={required_fields}, "
            f"allowed_claims={allowed_claims}, disallowed_without_extra={disallowed}. "
        )
    return "".join(parts)


def _collect_source_verdicts(evidence_results: list[dict[str, Any]]) -> list[str]:
    verdicts: list[str] = []
    seen: set[str] = set()
    for result in evidence_results:
        verdict = str(result.get("source_verdict") or "").strip().lower()
        if not verdict or verdict in seen:
            continue
        seen.add(verdict)
        verdicts.append(verdict)
    return verdicts


def _format_evidence_coverage(report_brief: dict[str, Any] | None) -> str:
    if not report_brief:
        return ""
    coverage = report_brief.get("evidence_coverage")
    if not isinstance(coverage, dict):
        return ""
    sections = coverage.get("sections")
    if not isinstance(sections, dict) or not sections:
        return ""
    lines: list[str] = ["Evidence coverage summary:"]
    for section_key, items in sections.items():
        if not isinstance(items, list):
            continue
        compact = ", ".join(
            f"{row.get('source')} (rows={row.get('rows')}, used={row.get('used_in_answer')})"
            for row in items[:6]
            if isinstance(row, dict)
        )
        if compact:
            lines.append(f"- {section_key}: {compact}")
    return "\n".join(lines)


def _slim_history(items: list[dict[str, Any]], max_items: int = 10) -> list[dict[str, Any]]:
    """Project history items to only the fields needed for broad planning context."""
    slimmed: list[dict[str, Any]] = []
    for item in items[:max_items]:
        slimmed.append({
            "query_id": item.get("query_id"),
            "hypothesis_id": item.get("hypothesis_id"),
            "verdict": item.get("verdict"),
            "rationale": item.get("summary"),
        })
    return slimmed


def build_broad_plan_messages(
    overview_md: str,
    extra_context_md: str,
    iteration: int,
    findings_snapshot: list[dict[str, Any]],
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
    history: list[dict[str, Any]],
    observed_keypoints: list[str] | None = None,
    max_findings: int = 10,
    max_resolved: int = 20,
) -> list[dict[str, str]]:
    findings = _slim_findings(findings_snapshot, max_findings)
    recent_resolved = resolved_hypotheses[-max_resolved:]
    slimmed_history = _slim_history(history, 10)
    EXAMPLE_BROAD_PLAN = '''
<EXAMPLE verdict="broad_plan">
Input: unresolved findings show suspicious service creation on HOST-A. Active hypotheses empty. Kill chain shows no lateral movement covered.
Output: {"read_more": ["findings/F-123.md"], "hypotheses": [{"id": "<assigned by system>", "description": "RDP lateral movement used to deploy malicious service on HOST-A", "required_entities": ["src_ip", "computer", "target_user", "service_name"], "source_rule_ids": ["windows-system-7045-service-install"]}], "stop": false, "stop_reason": ""}
</EXAMPLE>
'''

    system = (
        "<TASK>You are a DFIR investigator running broad planning. Propose NEW hypotheses only.</TASK>\n"
        "<INPUT_SCHEMA>overview_md, unresolved_findings, observed_keypoints, active_hypotheses, resolved_hypotheses, recent_history</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "hypothesis_quality: Must satisfy ALL: Falsifiable, Specific, Non-redundant, Evidence-grounded.\n"
        "hypothesis_output_schema: Each hypothesis MUST include required_entities, confirm_when, refute_when.\n"
        "prohibited_phrases: 'unknown', 'cannot confirm', 'insufficient evidence'.\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "read_more": ["memory/facts.md", "memory/details/fact-NNN.md", "entities/ip/192.168.1.1.md"],\n'
        '  "hypotheses": [{"id": "H-123", "description": "...", "required_entities": ["src_ip", "computer"], "confirm_when": {"co_observed_event_ids": [4624, 7045]}, "refute_when": {"zero_rows": true}}],\n'
        '  "stop": false,\n'
        '  "stop_reason": ""\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        f"{EXAMPLE_BROAD_PLAN}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        "Current investigation state:\n"
        f"plan_cycle: {iteration}\n"
        f"overview_md:\n{overview_md}\n\n"
        f"extra_context_md:\n{extra_context_md}\n\n"
        f"unresolved_findings: {findings}\n"
        f"observed_keypoints: {observed_keypoints or []}\n"
        f"active_hypotheses: {[item.model_dump() for item in active_hypotheses]}\n"
        f"resolved_hypotheses: {[item.model_dump() for item in recent_resolved]}\n"
        f"recent_history: {slimmed_history}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_hypothesis_plan_messages(
    overview_md: str,
    extra_context_md: str,
    iteration: int,
    hypothesis: Hypothesis,
    finding_candidates: list[dict[str, Any]],
    hypothesis_history: list[dict[str, Any]],
    query_templates: list[dict[str, Any]],
    query_index: int = 1,
    max_queries: int = 5,
) -> list[dict[str, str]]:
    executed_query_ids = [item.get("query_id") for item in hypothesis_history if item.get("query_id")]
    queries_remaining = max_queries - query_index + 1
    if queries_remaining <= 1:
        convergence_note = (
            f"IMPORTANT: This is query {query_index} of {max_queries} — your LAST allowed query for this hypothesis. "
            "You must either propose one final decisive query that can definitively confirm or refute the hypothesis, "
            "or set needs_more=false with a stop_reason explaining why the hypothesis cannot be resolved further. "
            "Do not propose an exploratory query that is likely to return inconclusive results."
        )
    else:
        convergence_note = (
            f"This is query {query_index} of {max_queries} ({queries_remaining} queries remaining for this hypothesis). "
            "Prioritize queries that can directly confirm or refute the hypothesis over broad exploratory ones."
        )
    
    schema_guidance = _build_schema_guidance("evtx_events")

    EXAMPLE_HYPOTHESIS_PLAN = '''
<EXAMPLE verdict="hypothesis_plan">
Input: hypothesis='RDP used to HOST-B by admin'. Query history empty. Templates available for logon queries.
Output: {"read_more": [], "hypothesis": {"id": "H-5", "description": "RDP used to HOST-B by admin"}, "query": {"query_id": "Q-5a", "hypothesis_id": "H-5", "purpose": "Find RDP logons to HOST-B by admin", "template_id": "logon-by-user", "params": {"computer": "HOST-B", "user": "admin", "logon_type": "10"}}, "needs_more": true, "stop_reason": ""}
</EXAMPLE>
'''

    system = (
        "<TASK>You are a DFIR investigator. Propose exactly one read-only query to test the current hypothesis.</TASK>\n"
        "<INPUT_SCHEMA>hypothesis, related_findings, hypothesis_history, query_templates</INPUT_SCHEMA>\n"
        f"Memory context: facts.md, tasks.md, memory/details/fact-NNN.md paths.\n"
        f"Already-executed query IDs for this hypothesis: {executed_query_ids}\n"
        f"{build_investigation_framework()}"
        f"{schema_guidance}"
        "<RULES>\n"
        "convergence: On last query, propose decisive test. Do not output exploratory queries.\n"
        "use_templates: Prefer template_id+params; only use raw sql when no template fits.\n"
        "</RULES>\n"
        f"{convergence_note}\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "read_more": [],\n'
        '  "hypothesis": {"id": "H-123", "description": "...", "required_entities": [], "confirm_when": {}, "refute_when": {}},\n'
        '  "query": {"query_id": "Q-123", "hypothesis_id": "H-123", "purpose": "...", "template_id": "...", "params": {}},\n'
        '  "needs_more": true|false,\n'
        '  "stop_reason": ""\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        f"{EXAMPLE_HYPOTHESIS_PLAN}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        "Current hypothesis-planning state:\n"
        f"plan_cycle: {iteration}\n"
        f"queries_remaining: {queries_remaining}\n"
        f"overview_md:\n{overview_md}\n\n"
        f"extra_context_md:\n{extra_context_md}\n\n"
        f"hypothesis: {hypothesis.model_dump()}\n"
        f"related_findings: {finding_candidates}\n"
        f"hypothesis_history: {hypothesis_history}\n"
        f"query_templates: {query_templates}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]




def build_check_messages(
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    overview_md: str,
    memory_context_md: str,
    query_index: int = 1,
    max_queries: int = 5,
    observed_evidence_ids: list[str] | None = None,
    rule_context: RuleContext | None = None,
    fallback_info: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    queries_remaining = max_queries - query_index
    if queries_remaining == 0:
        strictness_note = (
            f"CONVERGENCE REQUIRED: This is query {query_index} of {max_queries} — the FINAL check for this hypothesis. "
            "You must commit to a definitive verdict now. "
            "If any evidence leans one way, use 'confirmed' or 'refuted'. "
            "Reserve 'inconclusive' only when the result is genuinely ambiguous AND no further query could resolve it. "
            "Do not output 'newlead' on the final query — new leads will not be pursued at this stage."
        )
    elif queries_remaining == 1:
        strictness_note = (
            f"This is query {query_index} of {max_queries} — one query remains after this. "
            "Be willing to lean toward a verdict if the evidence is suggestive but not conclusive. "
            "Use 'newlead' only if you have identified a genuinely distinct attack surface not yet investigated."
        )
    else:
        strictness_note = (
            f"This is query {query_index} of {max_queries} ({queries_remaining} checks remaining). "
            "Apply standard evidentiary rigor."
        )
    evidence_id_guidance = ""
    if observed_evidence_ids:
        evidence_id_guidance = (
            f"The following evidence_ids are valid for this query: {observed_evidence_ids[:50]}. "
            "Only reference evidence_ids from this list in your output. "
        )
    zero_evidence = int(result_summary.get("row_count") or 0) == 0
    zero_evidence_note = ""
    if zero_evidence:
        zero_evidence_note = (
            "IMPORTANT: The query result contains 0 rows — 'confirmed' verdict is forbidden. "
            "Use 'refuted' if the hypothesis is clearly disproven, or 'inconclusive' if the result is ambiguous. "
        )
    entity_type_list = list(ENTITY_TYPE_ALIASES.keys())
    entity_constraint = (
        f"When adding entities, entity_type must be one of: {entity_type_list}. "
        "Do not emit placeholder values ('n/a', 'unknown', empty string) as entity names or types. "
    )
    rule_verdict_guidance = ""
    if rule_context:
        confirm_conditions = rule_context.confirm_when or {}
        refute_conditions = rule_context.refute_when or {}
        rule_verdict_guidance = (
            f"Rule-based verdict criteria (from {rule_context.rule_id}): "
            f"Confirm when: {confirm_conditions}. "
            f"Refute when: {refute_conditions}. "
            "If rule criteria are met, use them as the primary verdict basis. "
        )
    fallback_guidance = ""
    if fallback_info:
        phase = fallback_info.get("phase", "")
        source_rule = fallback_info.get("source_rule_id", "")
        event_ids = fallback_info.get("event_ids") or []
        keywords = fallback_info.get("keywords") or []
        fallback_guidance = (
            f"IMPORTANT: This result was obtained via fallback_search phase '{phase}' "
            f"from rule '{source_rule}'. "
            "The primary query returned 0 rows, but this fallback phase found relevant evidence. "
            f"{f'Event IDs from the query were {event_ids}. ' if event_ids else ''}"
            f"{f'String-search keywords used were {keywords}. ' if keywords else ''}"
            "Use this context when determining verdict and rationale. "
        )
    EXAMPLE_CONFIRMED = '''
<EXAMPLE verdict="confirmed">
Input: hypothesis requires entities {src_ip, computer, target_user} to confirm lateral movement.
Query returned rows showing src_ip='192.168.10.50', computer='HOST-B', target_user='admin' all in the same rows.
Output: {"query_id": "Q123", "verdict": "confirmed", "rationale": "All required entities co-observed in results. src_ip 192.168.10.50 accessed HOST-B with admin account.", "finding_updates": [{"finding_id": "F456", "new_status": "accepted", "confidence_delta": 0.2}], "memory_updates": {"facts": [{"fact_type": "lateral_movement", "fact_key": "source_ip->host", "fact_value": "192.168.10.50->HOST-B", "evidence_ids": ["E789"]}]}}
</EXAMPLE>
'''
    EXAMPLE_REFUTED_ZERO = '''
<EXAMPLE verdict="refuted">
Input: hypothesis suggests admin account was created for attacker persistence.
Query returned 0 rows, no 4720 (user creation) events for 'admin' found.
Output: {"query_id": "Q124", "verdict": "refuted", "rationale": "Zero rows for admin account creation. The account may be pre-existing or the log was cleared.", "finding_updates": [], "memory_updates": {"refuted_hypotheses": [{"hypothesis_id": "H99", "reason": "No creation evidence found"}]}}
</EXAMPLE>
'''
    EXAMPLE_INCONCLUSIVE = '''
<EXAMPLE verdict="inconclusive">
Input: hypothesis requires {src_ip, computer} for lateral movement. Query returned 1 row with computer='HOST-B' but no src_ip.
Output: {"query_id": "Q125", "verdict": "inconclusive", "rationale": "Missing src_ip in observed row. Need query to identify source IP of logon events to HOST-B.", "finding_updates": [], "memory_updates": {}}
</EXAMPLE>
'''

    system = (
        "<TASK>You are a DFIR review analyst. Evaluate SQL results against hypothesis and output structured findings.</TASK>\n"
        "<INPUT_SCHEMA>SQL result summary, hypothesis with required_entities, finding candidates, evidence_ids list</INPUT_SCHEMA>\n"
        "<RULES>\n"
        f"evidence_ids: Only reference evidence_ids from this query: {observed_evidence_ids[:50] if observed_evidence_ids else 'none available'}\n"
        f"zero_evidence: {zero_evidence_note}\n"
        f"entity_constraint: entity_type must be one of: {entity_type_list}. No placeholder values.\n"
        f"rule_based: {rule_verdict_guidance}\n"
        f"fallback: {fallback_guidance}\n"
        "</RULES>\n"
        "<MEMORY_RULES>\n"
        "facts: always include observed evidence_ids from the current query result. Do not emit speculative or unconfirmed items into memory_updates.facts. If you cannot cite observed evidence_ids, omit the fact.\n"
        "finding_updates format: finding_id, new_status (accepted or suppressed), confidence_delta\n"
        "suspicious_evidence format: evidence_id, reason, confidence (0.0-1.0)\n"
        "entities require entity_type and role.\n"
        "</MEMORY_RULES>\n"
        f"{_load_fp_reduction_guidance()}{_mandatory_missing_checks_guidance()}"
        "<VERDICT_RULES>\n"
        "confirmed — required_entities co-observed in same rows (NOT direct causation). Confidence >= 0.7.\n"
        "refuted — zero rows or observed entities contradict hypothesis. Confidence < 0.3.\n"
        "inconclusive — some entities observed; MUST list missing entity types in rationale.\n"
        "newlead — genuinely new attack surface or actor. Name the specific entity.\n"
        "Prohibited phrases: 'direct causation not proven', 'full attack chain not visible', 'requires further investigation', 'cannot be determined', 'insufficient evidence'. State exactly what entity is missing.\n"
        "</VERDICT_RULES>\n"
        f"{strictness_note}\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "query_id": "Q-123",\n'
        '  "verdict": "confirmed",\n'
        '  "finding_updates": [{"finding_id": "F-456", "new_status": "accepted", "confidence_delta": 0.2}],\n'
        '  "suspicious_evidence": [{"evidence_id": "E-789", "reason": "encoded command line", "confidence": 0.9}],\n'
        '  "new_hypotheses": [],\n'
        '  "memory_updates": {"facts": [{"fact_type": "lateral_movement", "fact_key": "src_ip->host", "fact_value": "192.168.1.1->HOST-A", "evidence_ids": ["E-789"]}],\n'
        '  "report_text": "RDP logon observed from external IP to HOST-A",\n'
        '  "missing_checks": [],\n'
        '  "notes": ""\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        f"{EXAMPLE_CONFIRMED}{EXAMPLE_REFUTED_ZERO}{EXAMPLE_INCONCLUSIVE}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        "Evaluate the following query result.\n"
        f"overview_md:\n{overview_md}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"planned_query: {planned_query.model_dump()}\n"
        f"hypothesis: {hypothesis.model_dump() if hypothesis else None}\n"
        f"finding_candidates: {finding_candidates}\n"
        f"result_summary: {result_summary}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_check_verdict_messages(
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
    rule_context: RuleContext | None = None,
    fallback_info: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    zero_evidence = int(result_summary.get("row_count") or 0) == 0
    rule_verdict_guidance = ""
    if rule_context:
        confirm = rule_context.confirm_when or {}
        refute = rule_context.refute_when or {}
        rule_verdict_guidance = f"Rule-based verdict criteria (from {rule_context.rule_id}): Confirm when: {confirm}. Refute when: {refute}. "

    system = (
        "<TASK>You are a DFIR review analyst. Determine verdict based on SQL results.</TASK>\n"
        "<INPUT_SCHEMA>SQL result summary, hypothesis, rule_context</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "confirmed: required_entities co-observed in same rows (NOT direct causation).\n"
        "refuted: zero rows or observed entities contradict hypothesis.\n"
        "inconclusive: some entities observed; MUST list missing entity types.\n"
        f"{rule_verdict_guidance}\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>{\"query_id\": \"Q-123\", \"verdict\": \"confirmed|refuted|inconclusive|newlead\", \"rationale\": \"explanation\"}\n"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"planned_query: {planned_query.model_dump()}\n"
        f"hypothesis: {hypothesis.model_dump() if hypothesis else None}\n"
        f"result_summary: {result_summary}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_check_memory_updates_messages(
    verdict: str,
    result_summary: dict[str, Any],
    finding_candidates: list[dict[str, Any]],
    overview_md: str | None = None,
) -> list[dict[str, str]]:
    system = (
        "<TASK>You are a DFIR review analyst. Extract durable memory updates based on verdict.</TASK>\n"
        "<INPUT_SCHEMA>verdict, SQL result, finding candidates</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "facts: Include evidence_ids; for co-observed entities, facts, timestamps.\n"
        "timeline: Include evidence_ids; central attack timestamps.\n"
        "tasks: Unresolved questions with kind (internal_db_check/external_lookup/human_decision).\n"
        "entities: entity_type + name + role; include evidence_ids.\n"
        "refuted_hypotheses/resolved_gaps: When hypothesis disproven or gap resolved.\n"
        "Only output items you can cite with evidence_ids.\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>{\"memory_updates\": {\"facts\": [...], \"timeline\": [...], \"tasks\": [...], \"entities\": [...], \"refuted_hypotheses\": [...], \"resolved_gaps\": [...]}}\n"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"verdict: {verdict}\n"
        f"result_summary: {result_summary}\n"
        f"finding_candidates: {finding_candidates}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_check_suspicious_evidence_messages(
    result_summary: dict[str, Any],
) -> list[dict[str, str]]:
    system = (
        "<TASK>You are a DFIR review analyst. Identify suspicious evidence from SQL results.</TASK>\n"
        "<INPUT_SCHEMA>SQL result rows (sample_rows)</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "suspicious_evidence: List evidence_ids with reason and confidence (0.0-1.0).\n"
        "reason: Why this evidence is suspicious (encoded command, unusual time, external IP, etc.).\n"
        "report_text: Brief summary sentence in output language.\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>{\"suspicious_evidence\": [{\"evidence_id\": \"E-123\", \"reason\": \"...\", \"confidence\": 0.9}], \"report_text\": \"...\"}\n"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = f"sample_rows: {result_summary.get('sample_rows') or []}\n"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_column_selection_messages(
    headers: list[str],
    section_key: str,
    template_body: str,
) -> list[dict[str, str]]:
    system = (
        "You are a DFIR analyst. "
        "Given a list of column names from query results and the report section context, "
        "select only the columns that are analytically relevant for this section. "
        "Drop: internal row IDs, empty/null-only fields, columns redundant with another column, "
        "and any field that a reader of this section would not care about. "
        "Output JSON only: {\"columns\": [\"col_a\", \"col_b\", ...]}"
    )
    user = (
        f"section_key: {section_key}\n\n"
        f"template_context (first 600 chars):\n{template_body[:600]}\n\n"
        f"available_columns: {headers}\n\n"
        "Return only the column names worth including in the evidence table."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _rows_to_markdown_table(rows: list[dict[str, Any]], max_rows: int = 30) -> str:
    if not rows:
        return ""
    keys = list(rows[0].keys())
    header = "| " + " | ".join(keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    data_lines = []
    for row in rows[:max_rows]:
        cells = [str(row.get(k, "")).replace("|", "\\|").replace("\n", " ") for k in keys]
        data_lines.append("| " + " | ".join(cells) + " |")
    return "\n".join([header, separator, *data_lines])


def build_report_section_messages(
    section_meta: dict[str, Any],
    evidence_results: list[dict[str, Any]],
    context_sections: dict[str, str],
    template_body: str,
    report_brief: dict[str, Any] | None = None,
    section_heading: str = "",
    current_section_outputs: dict[str, str] | None = None,
    verification_notes: list[str] | None = None,
    raw_evidence_rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    trimmed_context_sections = _truncate_context_sections(context_sections)
    trimmed_current_outputs = _truncate_context_sections(current_section_outputs or {}, max_chars=1200)
    insufficient_evidence_placeholder = (
        "【調査不足: 理由】"
        if _output_language().startswith("ja")
        else "[INSUFFICIENT EVIDENCE: reason]"
    )
    raw_table_guidance = ""
    if raw_evidence_rows:
        raw_table_guidance = (
            "You are also given normalized evidence summaries derived from row-level evidence. "
            "Treat them as reference only; do not paste raw tables or raw field dumps into the narrative body. "
            "Use them to write a short, normalized one-line summary of each relevant observation. "
            "If the section needs an appendix-style evidence note, place it in a dedicated Raw Evidence subsection with concise summaries only, never with NULL/None-heavy raw rows. "
        )
    coverage_guidance = _format_evidence_coverage(report_brief)
    if str(section_meta.get("section") or "").strip() == "1_overview" and coverage_guidance:
        coverage_guidance = (
            "Use the following evidence coverage summary as the canonical Evidence Scope. "
            "Do not invent sources that are not listed.\n"
            f"{coverage_guidance}\n"
        )
    # Strip sample_rows from evidence_results to avoid sending the same rows twice when raw_evidence_rows is provided.
    evidence_for_prompt: list[dict[str, Any]] = [result for result in evidence_results if str(result.get("kind") or "rows") == "rows"]
    if not evidence_for_prompt:
        evidence_for_prompt = evidence_results
    if raw_evidence_rows:
        evidence_for_prompt = [
            {k: v for k, v in result.items() if k != "sample_rows"}
            for result in evidence_results
        ]
    EXAMPLE_REPORT_SECTION = '''
<EXAMPLE verdict="report_section">
Input: section_meta={'section': '3_technical'}, template_body='## Process Execution\\nLook for suspicious processes.', evidence_results=[{'sample_rows': [{'evidence_id': 'E1', 'process_name': 'powershell.exe', 'command_line': '-enc ...'}]}]
Output: "## Process Execution\\n\\nOne suspicious process was observed: powershell.exe with encoded command line (evidence_id: E1)."
</EXAMPLE>
'''

    app_catalog = _load_app_catalog()
    app_cat_compact = ", ".join(
        f"{exe}={info.get('category', '?')}"
        for exe, info in app_catalog.get("mappings", {}).items()
    ) or "see investigation framework"
    event_guidance = _build_event_id_guidance(evidence_results)
    source_verdicts = _collect_source_verdicts(evidence_results)
    strength_guidance = ""
    if source_verdicts and all(verdict != "confirmed" for verdict in source_verdicts):
        strength_guidance = (
            "source_verdict guidance: Every supplied evidence result is below confirmed. "
            "Use cautious language only; avoid 'confirmed', 'executed', 'compromised', 'attack succeeded', or equivalent strong assertions unless additional evidence explicitly supports them.\n"
        )

    system = (
        "<TASK>You are a DFIR report writer. Fill the provided Markdown section template using only supplied evidence.</TASK>\n"
        "<INPUT_SCHEMA>section_meta, evidence_results, previous_sections, template_body</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "confidence_matrix: confidence >= 0.8 => 'confirmed'/'observed'; confidence >= 0.5 and < 0.8 => 'strongly suggests'; confidence < 0.5 => 'requires further investigation'.\n"
        "Do not use 'confirmed' for findings or conclusions below 0.8 confidence.\n"
        "Match wording to confidence: use cautious language for low-confidence items.\n"
        f"no_invented_facts: Write placeholder only for unsupported claims. Placeholder: {insufficient_evidence_placeholder}\n"
        "no_causation: Correlation is not proof of causation.\n"
        "confirmed_hypotheses: Reflect in appropriate sections; refuted_hypotheses only in 'Discarded Hypotheses' subsection.\n"
        "Recommended actions must scale with evidence strength.\n"
        f"app_categories: {app_cat_compact}\n"
        f"{event_guidance}"
        f"{strength_guidance}"
        "</RULES>\n"
    )
    if raw_table_guidance:
        system += f"{raw_table_guidance}\n"
    if coverage_guidance:
        system += f"{coverage_guidance}\n"
    system += f"{EXAMPLE_REPORT_SECTION}"
    system += f"Output Markdown only (no fences). {_lang_instruction()}"
    raw_block = ""
    if raw_evidence_rows:
        table_md = _rows_to_markdown_table(raw_evidence_rows)
        raw_block = f"\nnormalized_evidence_rows (summaries only; do not mirror raw tables):\n{table_md}\n"
    user = (
        f"section_meta: {section_meta}\n\n"
        f"current_subsection: {section_heading or '(full section)'}\n\n"
        f"report_brief: {report_brief or {}}\n\n"
        f"previous_sections: {trimmed_context_sections}\n\n"
        f"current_section_progress: {trimmed_current_outputs}\n\n"
        f"verification_notes_from_prior_subsections: {verification_notes or []}\n\n"
        f"evidence_coverage: {report_brief.get('evidence_coverage') if isinstance(report_brief, dict) else {}}\n\n"
        f"evidence_results: {evidence_for_prompt}\n"
        f"{raw_block}\n"
        "Complete only this current template block by replacing placeholders and comments with evidence-based content. "
        "If verification_notes indicate contradiction, explicitly state what evidence refutes the claim and why.\n\n"
        f"{template_body}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_benchmark_section_messages(
    section_meta: dict[str, Any],
    evidence_results: list[dict[str, Any]],
    template_body: str,
    report_brief: dict[str, Any] | None = None,
    block_heading: str = "",
    raw_evidence_rows: list[dict[str, Any]] | None = None,
    verification_notes: list[str] | None = None,
    benchmark_id: str | None = None,
) -> list[dict[str, str]]:
    raw_evidence_rows = raw_evidence_rows or []
    evidence_for_prompt = [result for result in evidence_results if str(result.get("kind") or "rows") == "rows"]
    if not evidence_for_prompt:
        evidence_for_prompt = evidence_results
    summary_lines = []
    for row in raw_evidence_rows:
        summary = str(row.get("summary") or "").strip()
        if summary:
            summary_lines.append(f"- {summary}")
    block_id = str(benchmark_id or "").strip()
    if not block_id:
        block_id = str(section_meta.get("id") or "").strip()
    system = (
        "<TASK>You are a benchmark answer writer for a DFIR appendix block.</TASK>\n"
        "<INPUT_SCHEMA>section_meta, block_heading, template_body, evidence_results, raw_evidence_rows</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  \"id\": \"Q8\",\n'
        '  \"status\": \"answered|partial|not_found|not_searched|insufficient_evidence|wrong_query\",\n'
        '  \"answer\": [\"concise normalized statements\"],\n'
        '  \"missing_reason\": [\"why evidence is missing or incomplete\"],\n'
        '  \"queries_run\": [\"keypoint or SQL query identifiers actually used\"]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Return exactly one JSON object.\n"
        "Do not return markdown, code fences, or prose outside JSON.\n"
        "Output JSON only.\n"
        "Keep answer items short and normalized; no raw tables and no NULL/None-heavy dumps.\n"
        "If evidence is incomplete, status must be partial or insufficient_evidence, and missing_reason must explain what is missing.\n"
        "If no relevant search ran, use not_searched.\n"
        "If the relevant search returned zero rows after search, use not_found.\n"
        "queries_run should list only the concrete keypoint/template/sql identifiers that were actually executed.\n"
        "</RULES>\n"
    )
    user = (
        f"section_meta: {section_meta}\n\n"
        f"block_heading: {block_heading}\n\n"
        f"benchmark_id: {block_id}\n\n"
        f"report_brief: {report_brief or {}}\n\n"
        f"verification_notes: {verification_notes or []}\n\n"
        f"evidence_results: {evidence_for_prompt}\n\n"
        f"normalized_evidence_rows:\n" + ("\n".join(summary_lines) if summary_lines else "- none") + "\n\n"
        f"template_body:\n{template_body}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _filter_prior_runs_by_heading(prior_runs: list[dict[str, Any]], block_heading: str, limit: int = 6) -> list[dict[str, Any]]:
    """Filter prior runs by block_heading match first, then fall back to recency."""
    heading_matches = [run for run in prior_runs if str(run.get("block_heading") or "") == str(block_heading)]
    if heading_matches:
        return heading_matches[-limit:]
    return prior_runs[-limit:]


def build_section_agent_plan_messages(
    *,
    section_key: str,
    section_title: str,
    block_heading: str,
    template_body: str,
    report_brief: dict[str, Any],
    context_sections: dict[str, str],
    current_section_outputs: dict[str, str],
    findings_snapshot: list[dict[str, Any]],
    keypoint_catalog: list[dict[str, str]],
    query_template_catalog: list[dict[str, Any]],
    prior_runs: list[dict[str, Any]],
    reusable_facts: list[dict[str, Any]],
    reusable_evidence: list[dict[str, Any]],
    memory_context_md: str = "",
) -> list[dict[str, str]]:
    schema_guidance = _build_schema_guidance("evtx_events")

    EXAMPLE_SECTION_PLAN = '''
<EXAMPLE verdict="section_plan">
Input: block_heading='Logon Summary', template_body='## Logon Summary\\nList all logons.', reusable_facts empty, query_template_catalog has logon templates.
Output: {"action": "sql", "purpose": "Find all logon events", "sql": "SELECT evidence_id, computer, user_name, src_ip, logon_type, timestamp FROM evtx_events WHERE event_id IN (4624, 4625)"}
</EXAMPLE>
'''
    EXAMPLE_SECTION_PLAN_TEMPLATE = '''
<EXAMPLE verdict="section_plan_template">
Input: block_heading='Service Creation', template_body='## Service Creation\\nFind malicious services.', template_id available, params extractable.
Output: {"action": "template", "template_id": "service-creation", "params": {"computer": "HOST-A"}}
</EXAMPLE>
'''

    system = (
        "<TASK>You are a DFIR section-planning agent. Decide next evidence-gathering action for report block.</TASK>\n"
        "<INPUT_SCHEMA>section_key, block_heading, template_block, structured_memory_context, findings_snapshot, keypoint_catalog, query_template_catalog, prior_runs</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "action": "sql|template|keypoint|facts|write",\n'
        '  "sql": "SELECT ...", '
        '  "template_id": "template-name", '
        '  "params": {"key": "value"},\n'
        '  "enough_to_write": true|false\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "facts_first: Reuse reusable_section_facts if they already answer the block question.\n"
        "keypoint_preferred: Use keypoint when it matches the block topic.\n"
        "template_preferred: Use template_id+params instead of raw sql.\n"
        "stop_early: Set action=write when enough evidence exists.\n"
        "</RULES>\n"
        f"{build_investigation_framework()}"
        f"{schema_guidance}"
        f"{EXAMPLE_SECTION_PLAN}{EXAMPLE_SECTION_PLAN_TEMPLATE}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"report_brief: {report_brief}\n\n"
        f"previous_sections: {_truncate_context_sections(context_sections)}\n\n"
        f"current_section_progress: {_truncate_context_sections(current_section_outputs or {}, max_chars=1200)}\n\n"
        f"findings_snapshot: {findings_snapshot[:10]}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"keypoint_catalog: {keypoint_catalog}\n\n"
        f"query_template_catalog: {query_template_catalog}\n\n"
        f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


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
) -> list[dict[str, str]]:
    contradicted_history = [run for run in prior_runs if run.get("verdict") in {"block_contradicted", "refuted"}]
    EXAMPLE_SECTION_CHECK = '''
<EXAMPLE verdict="section_check">
Input: collected_results has 3 rows with process_name='powershell.exe', template_body='## Suspicious Processes\\nList suspicious processes.'.
Output: {"verdict": "block_supported", "status": "answered", "rationale": "Evidence shows powershell.exe execution. Block can be written.", "fact_updates": []}
</EXAMPLE>
'''
    EXAMPLE_SECTION_CHECK_REFUTED = '''
<EXAMPLE verdict="section_check_contradicted">
Input: collected_results empty, template_body='## Malicious Services\\nList malicious services.'. prior runs show queries returned nothing.
Output: {"verdict": "block_contradicted", "status": "not_found", "rationale": "No service-related evidence found in collected results.", "missing_questions": ["Query for event_id 4697/7045 returned 0 rows earlier"]}
</EXAMPLE>
'''
    system = (
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
        "block_needs_more: More evidence needed; another query may help.\n"
        "block_contradicted: Evidence contradicts the template claim; explain contradiction.\n"
        "status rules: answered when evidence supports the block, partial when some evidence exists but not enough, not_found only after an appropriate search has been run and returned zero rows repeatedly, not_searched when the matching query/keypoint was never executed, wrong_query when the search hit the wrong artifact family, insufficient_evidence for other unresolved cases.\n"
        "Never use not_found unless the relevant search has actually run.\n"
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
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"latest_result: {latest_result}\n\n"
        f"collected_results: {collected_results}\n\n"
    )
    if contradicted_history:
        user += f"contradicted_attempts_previous_iterations: {contradicted_history}\n\n"
    user += f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
