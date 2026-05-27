from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from forensia.config import get_llm_settings
from forensia.core.session import ENTITY_TYPE_ALIASES, Hypothesis, PlannedQuery
from forensia.ai.sql_schema import build_investigation_framework


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


def _lang_instruction() -> str:
    settings = get_llm_settings()
    thinking = settings["thinking_language"]
    output = settings["output_language"]
    if thinking == output:
        return f"Write all output in {output}."
    return (
        f"Think and reason internally in {thinking} to maximize reasoning quality. "
        f"Write all human-readable text fields in {output}: "
        "report_text, summary, notes, reason, description, purpose, stop_reason, "
        "all items in missing_checks arrays, and all free-text strings inside memory_updates. "
        f"Hypothesis descriptions and LLM assessment text must always be in {output}."
    )


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
    max_findings: int = 10,
    max_resolved: int = 20,
) -> list[dict[str, str]]:
    findings = _slim_findings(findings_snapshot, max_findings)
    recent_resolved = resolved_hypotheses[-max_resolved:]
    slimmed_history = _slim_history(history, 10)
    system = (
        "You are a DFIR investigator running the broad planning phase. "
        "Treat overview.md as your primary memory index. Request additional Markdown files only when necessary. "
        "Useful memory files include facts.md, timeline.md, tasks.md, archive/refuted.md, "
        "archive/resolved_gaps.md, hypotheses/<hypothesis_id>.md, keypoints/KP-NNNN.md, "
        "entities/host/*.md, entities/user/*.md, and entities/ip/*.md. "
        "Confirmed fact details are stored in memory/details/fact-NNN.md and can be requested via read_more "
        "when you need full context on a specific fact. "
        "Each hypothesis card is stored at hypotheses/<hypothesis_id>.md using the stable hypothesis id "
        "(for example, hypotheses/H-1.md). Request that exact path in read_more when you want the current state of a hypothesis. "
        "KeyPoint cards can be loaded from keypoints/KP-NNNN.md when a rule finding needs closer review. "
        "Stable facts belong in facts.md, key timestamps belong in timeline.md, "
        "unresolved questions and current work items belong in tasks.md, "
        "analyst storyline also belongs in overview.md, and durable named actors belong in entities/*/*.md. "
        "Do not make claims without evidence. "
        "Output JSON only. "
        f"{_lang_instruction()} "
        "Broad planning means you propose NEW hypotheses only. "
        "Do not output SQL in this phase. "
        "Hypothesis quality criteria — a hypothesis must satisfy ALL of the following:\n"
        "  - Falsifiable: it can be confirmed or refuted by a specific SQL query against the available tables.\n"
        "  - Specific: it names a concrete actor, technique, time range, or host rather than a vague claim.\n"
        "  - Non-redundant: it is meaningfully different from every active and resolved hypothesis.\n"
        "  - Evidence-grounded: at least one unresolved finding or known fact suggests it is worth investigating.\n"
        "Hypothesis output schema — each hypothesis MUST include:\n"
        "  - required_entities: list of entity names that must co-occur to confirm (extract from the claim).\n"
        "  - confirm_when: {co_observed_event_ids: [...], same_host: bool, within_minutes: int} for correlation-based confirmation.\n"
        "  - refute_when: {zero_rows: true} for refutation on empty results.\n"
        "Prohibited phrases in hypothesis descriptions: 'unknown', 'cannot confirm', 'insufficient evidence'.\n"
        "Kill chain coverage — before proposing, mentally check each phase for open questions:\n"
        "  Initial Access | Execution | Persistence | Privilege Escalation | "
        "Defense Evasion | Credential Access | Discovery | Lateral Movement | Exfiltration.\n"
        "  Prioritize phases not yet covered by active or resolved hypotheses.\n"
        "Set stop=true only when ALL of the following hold:\n"
        "  - No unresolved findings remain that suggest a new attack phase.\n"
        "  - All active hypotheses are already queued.\n"
        "  - The resolved hypothesis list covers the key kill chain phases visible in the evidence.\n"
        "Use only these JSON keys: read_more, hypotheses, stop, stop_reason."
    )
    user = (
        "Current investigation state:\n"
        f"plan_cycle: {iteration}\n"
        f"overview_md:\n{overview_md}\n\n"
        f"extra_context_md:\n{extra_context_md}\n\n"
        f"unresolved_findings: {findings}\n"
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
    
    schema_hints = _load_schema_hints()
    schema_guidance = ""
    if schema_hints:
        evtx_cols = schema_hints.get("evtx_events", {}).get("columns", [])
        evtx_extractors = schema_hints.get("evtx_events", {}).get("json_field_extractors", {})
        if evtx_cols:
            schema_guidance = (
                f"Schema guidance for evtx_events table — allowed_columns: {evtx_cols}. "
                "Do NOT write column names outside this list in SELECT/WHERE clauses. "
            )
        if evtx_extractors:
            schema_guidance += (
                f"For fields not in allowed_columns, use json_field_extractors: {evtx_extractors}. "
            )
    
    system = (
        "You are a DFIR investigator running the hypothesis-specific planning phase. "
        "You must propose exactly one read-only query that tests the current hypothesis, "
        "or declare that no more useful SQL remains. "
        "Confirmed fact details are stored in memory/details/fact-NNN.md and can be requested via read_more "
        "when you need full context on a specific fact. "
        f"{build_investigation_framework()}"
        f"{schema_guidance}"
        "Output JSON only. "
        f"{_lang_instruction()} "
        f"{convergence_note} "
        f"Already-executed query IDs for this hypothesis: {executed_query_ids}. "
        "Do not duplicate the same query purpose. "
        "Prefer using query templates. In query, either set template_id + params, "
        "or as a fallback set raw sql when no template fits. "
        "Use only these JSON keys: read_more, hypothesis, query, needs_more, stop_reason. "
        "Inside query use only: query_id, hypothesis_id, purpose, template_id, params, sql."
    )
    user = (
        "Current hypothesis-planning state:\n"
        f"plan_cycle: {iteration}\n"
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


_FP_REDUCTION_GUIDANCE_PREFIX = """
False-positive reduction — apply before raising confidence:
  The following are generally NORMAL and should not be flagged as suspicious on their own:
    - LogonType=3 from the same domain to a file server or DC during business hours.
    - LogonType=3 from known backup agents or monitoring systems.
    - LogonType=5 service logons from recognized service accounts.
  Raise confidence only when ONE OR MORE of these risk amplifiers are present:
    + Source IP is external or from an unusual subnet.
    + Activity occurs outside business hours (night, weekend).
    + Target share is ADMIN$, C$, or IPC$ (administrative shares).
    + A failed-logon burst (4625 ≥5 times) immediately precedes the success.
    + The user account is not normally associated with that computer.
    + AV/Defender was disabled (5001) shortly before the process execution.
    + Audit log was cleared (1102/104) shortly before or after.
  Lower confidence when:
    - Activity is within business hours, from known internal IPs.
    - The account is a known service or IT-admin account.
    - The action can be explained by routine IT operations.
"""


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
        fallback_guidance = (
            f"IMPORTANT: This result was obtained via fallback_search phase '{phase}' "
            f"from rule '{source_rule}'. "
            "The primary query returned 0 rows, but this fallback phase found relevant evidence. "
            "Use this context when determining verdict and rationale. "
        )
    system = (
        "You are a DFIR review analyst. "
        "Use the SQL result summary together with the provided structured memory context. "
        "Do not assert facts not present in the evidence or memory. "
        "Determine whether the result confirms, refutes, is inconclusive for the hypothesis, or represents a new finding. "
        "Keep facts, hypotheses, and gaps separate. Correlated events are not the same as confirmed causation. "
        "Never treat None, N/A, -, null, or empty strings as real users, hosts, IPs, services, or paths. "
        f"{evidence_id_guidance}"
        f"{zero_evidence_note}"
        f"{entity_constraint}"
        f"{rule_verdict_guidance}"
        f"{fallback_guidance}"
        "Always reference evidence_id values. "
        "For durable memory updates, use only observed evidence_id values that are present in this query result "
        "or in the provided finding candidates. "
        "When a fact becomes durable, write it into memory_updates.facts and always include observed evidence_ids. "
        "When a timestamp is central to the attack timeline, write it into memory_updates.timeline and always include "
        "observed evidence_ids. "
        "When a question remains unresolved, write it into memory_updates.tasks with kind set to "
        "internal_db_check, external_lookup, or human_decision. "
        "When a concise analyst storyline should survive compaction, write it into memory_updates.overview. "
        "When a hypothesis is disproved, write a record into memory_updates.refuted_hypotheses. "
        "When a gap is resolved, write it into memory_updates.resolved_gaps with text and observed evidence_ids. "
        "When a host, user, or IP becomes important enough to track, write it into "
        "memory_updates.entities with entity_type set to user, group, host, ip, process, service, file, registry, or unknown. "
        "Each entity update may also include role using actor_user, target_user, target_group, source_ip, "
        "source_host, source_account, destination_host, service_name, service_path, process_name, file_path, "
        "registry_key, or unknown. "
        "Do not emit speculative or unconfirmed items into memory_updates.facts, memory_updates.timeline, "
        "or memory_updates.resolved_gaps. "
        "If you cannot cite observed evidence_ids, do not output that durable item; keep it in missing_checks, tasks, "
        "or notes instead. "
        f"{_FP_REDUCTION_GUIDANCE_PREFIX}{_mandatory_missing_checks_guidance()}"
        "Generic verdict criteria (use unless rule_context overrides):\n"
        "  confirmed — the hypothesis required_entities are co-observed in the same rows (NOT direct causation).\n"
        "    Required entities are extracted from hypothesis description: name the entities that must appear together.\n"
        "    Example: For 'lateral movement via service', confirmed if src_ip, computer, target_user, service_name all appear.\n"
        "  refuted — zero rows returned, or observed entities contradict the hypothesis.\n"
        "  inconclusive — only some required entities observed; MUST list missing entity types in rationale.\n"
        "Prohibited rationale phrases (indicate lazy analysis):\n"
        "  Do NOT use: 'direct causation not proven', 'full attack chain not visible', 'requires further investigation',\n"
        "  'cannot be determined', 'insufficient evidence' alone. State exactly what entity is missing.\n"
        "Verdict decision rules:\n"
        "  confirmed — direct evidence_ids prove the hypothesis is true. Confidence >= 0.7.\n"
        "  refuted   — direct evidence contradicts or zero matching rows exist after an appropriate query. Confidence < 0.3.\n"
        "  newlead   — the result reveals a genuinely new attack surface or actor not yet in any hypothesis. "
        "Use ONLY when you can name the specific new entity or technique.\n"
        "  inconclusive — evidence is ambiguous, incomplete, or explainable by normal operations. "
        "Do NOT use when a clearer verdict is defensible.\n"
        "confidence_delta calibration for finding_updates:\n"
        "  Strong corroboration (direct match, multiple evidence_ids): +0.15 to +0.25\n"
        "  Weak corroboration (suggestive but indirect): +0.05 to +0.10\n"
        "  Contradicting evidence: -0.10 to -0.20\n"
        "  Zero rows / no evidence: 0.0 (never raise confidence on empty results)\n"
        f"{strictness_note} "
        "Output JSON only. "
        f"{_lang_instruction()} "
        "Use only these JSON keys: query_id, verdict, finding_updates, suspicious_evidence, "
        "new_hypotheses, memory_updates, report_text, missing_checks, notes. "
        "In finding_updates items, use keys: finding_id, new_status (accepted or suppressed), "
        "confidence_delta (signed float). "
        "In suspicious_evidence items, use keys: evidence_id, reason, confidence (0.0-1.0). "
        "verdict must be one of: confirmed, refuted, inconclusive, newlead."
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
            "You are also given raw_evidence_rows — the flat evidence rows before filtering. "
            "Apply two-dimensional filtering before embedding: "
            "(1) Row filter: keep only rows relevant to this section; discard noise, duplicates, and rows with no analytic value. Aim for 5–25 rows. "
            "(2) Column filter: drop columns that add no value (internal IDs, empty fields, redundant duplicates of another column). "
            "Embed the filtered rows as a Markdown table under a '#### Raw Evidence' sub-heading inside the section body. "
            "If no rows survive filtering, omit the table entirely. "
        )
    # Strip sample_rows from evidence_results to avoid sending the same rows twice when raw_evidence_rows is provided.
    evidence_for_prompt: list[dict[str, Any]] = evidence_results
    if raw_evidence_rows:
        evidence_for_prompt = [
            {k: v for k, v in result.items() if k != "sample_rows"}
            for result in evidence_results
        ]
    system = (
        "You are a DFIR report writer. "
        "Fill the provided Markdown section template using only the supplied evidence and prior completed sections. "
        "Do not invent facts. If something cannot be supported, write "
        f"{insufficient_evidence_placeholder} in that place. "
        "Keep confirmed facts, hypotheses, and unresolved gaps clearly separated. "
        "Do not present correlation as proof of causation. "
        "Correlation-derived conclusions such as network logon followed by service creation must be labeled as hypotheses unless direct evidence_id support confirms the technique. "
        "Never output None, N/A, -, null, or empty strings as important entities. "
        "Avoid repeating claims already covered in other sections unless you are adding new evidence, scope, or analysis. "
        "Match wording to confidence. "
        "Use this language-confidence matrix exactly: confidence >= 0.8 => use 'confirmed' or 'observed'; "
        "confidence >= 0.5 and < 0.8 => use 'strongly suggests' or 'may indicate'; "
        "confidence < 0.5 => use 'requires further investigation' or 'cannot be confirmed'. "
        "Do not use 'confirmed' for findings or conclusions below 0.8 confidence. "
        "Application category mapping to preserve: GOOGLEDRIVESYNC.EXE=cloud_sync, SCHTASKS.EXE=persistence_tool, "
        "CONSENT.EXE=uac_related, UNINST.EXE=uninstaller. "
        "If writing a timeline, keep events in chronological order and state the time basis when known. "
        "Recommended actions must scale with evidence strength and should not overstate weak signals. "
        "Do not output markdown fences or explanations outside the completed section body. "
        f"{raw_table_guidance}"
        f"{_lang_instruction()}"
    )
    raw_block = ""
    if raw_evidence_rows:
        table_md = _rows_to_markdown_table(raw_evidence_rows)
        raw_block = f"\nraw_evidence_rows (apply row+column filter before embedding):\n{table_md}\n"
    user = (
        f"section_meta: {section_meta}\n\n"
        f"current_subsection: {section_heading or '(full section)'}\n\n"
        f"report_brief: {report_brief or {}}\n\n"
        f"previous_sections: {trimmed_context_sections}\n\n"
        f"current_section_progress: {trimmed_current_outputs}\n\n"
        f"verification_notes_from_prior_subsections: {verification_notes or []}\n\n"
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
) -> list[dict[str, str]]:
    schema_hints = _load_schema_hints()
    schema_guidance = ""
    if schema_hints:
        evtx_cols = schema_hints.get("evtx_events", {}).get("columns", [])
        evtx_extractors = schema_hints.get("evtx_events", {}).get("json_field_extractors", {})
        if evtx_cols:
            schema_guidance = (
                f"Schema guidance: evtx_events allowed_columns = {evtx_cols}. "
                "Do NOT write column names outside this list in SELECT/WHERE clauses. "
            )
        if evtx_extractors:
            schema_guidance += f"For fields not in allowed_columns, use json_field_extractors = {evtx_extractors}. "
    
    system = (
        "You are a DFIR section-planning agent for report writing. "
        "Read the current Markdown block and decide the next best evidence-gathering action. "
        "Prefer reusing named keypoints when they clearly fit. Use read-only SQL only when keypoints are insufficient. "
        "Stop once you have enough evidence to write the block without inventing facts. "
        f"{build_investigation_framework()}"
        f"{schema_guidance}"
        "Output JSON only. "
        f"{_lang_instruction()} "
        "Use only these JSON keys: action, purpose, keypoint, template_id, params, sql, enough_to_write. "
        "action must be one of: facts, keypoint, template, sql, write. "
        "When action=facts, reuse the supplied reusable_section_facts/reusable_section_evidence and do not request a new query. "
        "When action=keypoint, set keypoint to one catalog name. "
        "When action=template, set template_id and params using one supplied query template. Prefer this over raw SQL when a template fits. "
        "When action=sql, set sql to one DuckDB-compatible SELECT/WITH query. "
        "When action=write, set enough_to_write=true."
    )
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
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
) -> list[dict[str, str]]:
    refuted_history = [run for run in prior_runs if run.get("verdict") == "refuted"]
    system = (
        "You are a DFIR section-check agent. "
        "Judge whether the collected evidence is sufficient to write the current report block. "
        "Do not demand more queries if the current result set already supports the requested block. "
        "If evidence contradicts the template claim, set verdict=refuted and explain the contradiction in rationale. "
        "For refuted claims, include specific evidence_ids that contradict the claim in missing_questions, "
        "and describe what additional evidence would resolve the contradiction. "
    )
    if refuted_history:
        system += (
            "PREVIOUSLY REFUTED ATTEMPTS ARE SHOWN ABOVE - avoid the same contradiction. "
        )
    system += (
        "Output JSON only. "
        f"{_lang_instruction()} "
        "Use only these JSON keys: verdict, rationale, missing_questions, fact_updates. "
        "verdict must be one of: sufficient, need_more, refuted. "
        "fact_updates must be a list of objects with keys: fact_type, fact_key, fact_value, confidence."
    )
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"latest_result: {latest_result}\n\n"
        f"collected_results: {collected_results}\n\n"
    )
    if refuted_history:
        user += f"refuted_attempts_previous_iterations: {refuted_history}\n\n"
    user += f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
