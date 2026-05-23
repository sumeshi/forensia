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


def _truncate_context_sections(context_sections: dict[str, str], max_chars: int = 600) -> dict[str, str]:
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
        "archive/resolved_gaps.md, hypotheses/*.md, keypoints/KP-NNNN.md, "
        "entities/host/*.md, entities/user/*.md, and entities/ip/*.md. "
        "Confirmed fact details are stored in memory/details/fact-NNN.md and can be requested via read_more "
        "when you need full context on a specific fact. "
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
        "Always reference evidence_id values. "
        "When a fact becomes durable, write it into memory_updates.facts. "
        "When a timestamp is central to the attack timeline, write it into memory_updates.timeline. "
        "When a question remains unresolved, write it into memory_updates.tasks with kind set to "
        "internal_db_check, external_lookup, or human_decision. "
        "When a concise analyst storyline should survive compaction, write it into memory_updates.overview. "
        "When a hypothesis is disproved, write a record into memory_updates.refuted_hypotheses. "
        "When a gap is resolved, write it into memory_updates.resolved_gaps with text and evidence_ids. "
        "When a host, user, or IP becomes important enough to track, write it into "
        "memory_updates.entities with entity_type set to host, user, or ip. "
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
) -> list[dict[str, str]]:
    trimmed_context_sections = _truncate_context_sections(context_sections)
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
        "Do not output markdown fences or explanations outside the completed section body. "
        f"{_lang_instruction()}"
    )
    user = (
        f"section_meta: {section_meta}\n\n"
        f"report_brief: {report_brief or {}}\n\n"
        f"previous_sections: {trimmed_context_sections}\n\n"
        f"evidence_results: {evidence_results}\n\n"
        "Complete this section template by replacing placeholders and comments with evidence-based content:\n\n"
        f"{template_body}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
