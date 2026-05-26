from __future__ import annotations

from typing import Any

from forensia.config import get_llm_settings
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.ai.sql_schema import build_investigation_framework


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
        f"Hypothesis descriptions and LLM assessment text must always be in {output}. "
        "JSON keys and enum values (verdict, status, phase, etc.) remain in English."
    )


def _output_language() -> str:
    return str(get_llm_settings()["output_language"]).lower()


def _mandatory_missing_checks_guidance() -> str:
    if _output_language().startswith("ja"):
        return """
Mandatory missing_checks:
  - If a logon is confirmed → add: 'src_ip からの他ホストへのログオンの有無', '4688/4104 の有無 (ログオン後15分以内)'
  - If process execution is confirmed → add: '親プロセス名の確認', '実行ユーザの通常業務との整合性'
  - If service/task creation is confirmed → add: 'サービスパスの実行ファイルの場所', '7036(サービス開始)の有無'
  - If Defender disable is confirmed → add: '直後の4688/4104 の有無', '1116(マルウェア検知)との相関'
"""
    return """
Mandatory missing_checks:
  - If a logon is confirmed → add: 'Other host logons from the same src_ip', 'Presence of 4688/4104 within 15 minutes after logon'
  - If process execution is confirmed → add: 'Confirm parent process name', 'Check whether the executing user aligns with normal duties'
  - If service/task creation is confirmed → add: 'Path of the executable behind the service', 'Presence of 7036 (service start)'
  - If Defender disable is confirmed → add: 'Presence of 4688/4104 immediately afterward', 'Correlation with 1116 (malware detection)'
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
        f"recent_history: {history[-10:]}\n"
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
) -> list[dict[str, str]]:
    executed_query_ids = [item.get("query_id") for item in hypothesis_history if item.get("query_id")]
    system = (
        "You are a DFIR investigator running the hypothesis-specific planning phase. "
        "You must propose exactly one read-only query that tests the current hypothesis, "
        "or declare that no more useful SQL remains. "
        "Confirmed fact details are stored in memory/details/fact-NNN.md and can be requested via read_more "
        "when you need full context on a specific fact. "
        f"{build_investigation_framework()}"
        "Output JSON only. "
        f"{_lang_instruction()} "
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
) -> list[dict[str, str]]:
    system = (
        "You are a DFIR review analyst. "
        "Use the SQL result summary together with the provided structured memory context. "
        "Do not assert facts not present in the evidence or memory. "
        "Determine whether the result confirms, refutes, is inconclusive for the hypothesis, or represents a new finding. "
        "Keep facts, hypotheses, and gaps separate. Correlated events are not the same as confirmed causation. "
        "Never treat None, N/A, -, null, or empty strings as real users, hosts, IPs, services, or paths. "
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
        "Output JSON only. "
        f"{_lang_instruction()} "
        "Use only these JSON keys: query_id, verdict, finding_updates, suspicious_evidence, "
        "new_hypotheses, memory_updates, report_text, missing_checks, notes. "
        "In finding_updates items, use keys: finding_id, new_status (accepted or suppressed), "
        "confidence_delta (signed float, e.g. 0.15 to raise, -0.2 to lower). "
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


def build_report_section_messages(
    section_meta: dict[str, Any],
    evidence_results: list[dict[str, Any]],
    context_sections: dict[str, str],
    template_body: str,
    report_brief: dict[str, Any] | None = None,
    section_heading: str = "",
    current_section_outputs: dict[str, str] | None = None,
    verification_notes: list[str] | None = None,
) -> list[dict[str, str]]:
    trimmed_context_sections = _truncate_context_sections(context_sections)
    trimmed_current_outputs = _truncate_context_sections(current_section_outputs or {}, max_chars=1200)
    insufficient_evidence_placeholder = (
        "【調査不足: 理由】"
        if _output_language().startswith("ja")
        else "[INSUFFICIENT EVIDENCE: reason]"
    )
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
        f"{_lang_instruction()}"
    )
    user = (
        f"section_meta: {section_meta}\n\n"
        f"current_subsection: {section_heading or '(full section)'}\n\n"
        f"report_brief: {report_brief or {}}\n\n"
        f"previous_sections: {trimmed_context_sections}\n\n"
        f"current_section_progress: {trimmed_current_outputs}\n\n"
        f"verification_notes_from_prior_subsections: {verification_notes or []}\n\n"
        f"evidence_results: {evidence_results}\n\n"
        "Complete only this current template block by replacing placeholders and comments with evidence-based content. "
        "If verification_notes indicate contradiction, explicitly state what evidence refutes the claim and why.\n\n"
        f"{template_body}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


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
    system = (
        "You are a DFIR section-planning agent for report writing. "
        "Read the current Markdown block and decide the next best evidence-gathering action. "
        "Prefer reusing named keypoints when they clearly fit. Use read-only SQL only when keypoints are insufficient. "
        "Stop once you have enough evidence to write the block without inventing facts. "
        f"{build_investigation_framework()}"
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
        f"prior_runs: {prior_runs[-6:]}\n"
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
    user += f"prior_runs: {prior_runs[-6:]}\n"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
