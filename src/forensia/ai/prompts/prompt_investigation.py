"""Prompt builders for the investigation loop (query, SQL, verdict, memory)."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from forensia.ai.llm.schemas import (
    FINDING_EXTRACTOR_SCHEMA,
    MEMORY_UPDATER_SCHEMA,
    SQL_SELF_CHECK_SCHEMA,
    VERDICT_REVIEW_SCHEMA,
    gap_identifier_schema,
    hypothesis_drafter_schema,
)
from forensia.core.session import Hypothesis
from forensia.knowledge.catalog import (
    load_benign_context_rules,
)

if TYPE_CHECKING:
    pass


from forensia.ai.prompts.prompt_context import (
    _case_profile_guidance,
    _time_range_guidance,
)
from forensia.ai.prompts.prompt_playbook import (
    _dfir_playbook,
    _sections_for_hypothesis,
)


def render_prior_attempts(recent_history: list[dict[str, Any]], limit: int = 5) -> str:
    """Render hypothesis attempt history as a compact structured block.

    Accepts both HistoryEntry dumps (query_id / verdict / summary /
    evidence_ids / template_id / purpose) and hypothesis_reasoning rows
    (phase / verdict / query_id / body). Fields absent from a row are
    omitted — nothing is fabricated. Free text is demoted to a
    120-char note; the structured fields carry the signal.
    """
    entries = [item for item in (recent_history or []) if isinstance(item, dict)]
    if not entries:
        return "<PRIOR_ATTEMPTS>\n(none)\n</PRIOR_ATTEMPTS>\n"
    entries = entries[-limit:]
    lines: list[str] = []
    tried_query_ids: list[str] = []
    for idx, item in enumerate(entries, 1):
        parts: list[str] = []
        query_id = str(item.get("query_id") or "").strip()
        if query_id:
            parts.append(f"query_id={query_id}")
            if query_id not in tried_query_ids:
                tried_query_ids.append(query_id)
        template_id = str(item.get("template_id") or "").strip()
        if template_id:
            parts.append(f"template={template_id}")
        verdict = str(item.get("verdict") or "").strip()
        if verdict:
            parts.append(f"verdict={verdict}")
        evidence_ids = item.get("evidence_ids")
        if isinstance(evidence_ids, list):
            parts.append(f"evidence_count={len(evidence_ids)}")
        purpose = str(item.get("purpose") or "").strip().replace("\n", " ")
        if purpose:
            parts.append(f"purpose={purpose[:80]}")
        note = (
            str(item.get("summary") or item.get("body") or "")
            .strip()
            .replace("\n", " ")
        )
        if note:
            parts.append(f"note={note[:120]}")
        lines.append(f"- attempt {idx}: " + ", ".join(parts))
    block = "<PRIOR_ATTEMPTS>\n" + "\n".join(lines)
    if tried_query_ids:
        block += "\ndo_not_repeat_query_ids: " + ", ".join(tried_query_ids)
    return block + "\n</PRIOR_ATTEMPTS>\n"


_load_benign_context_rules = load_benign_context_rules


def build_query_intent_messages(
    hypothesis,
    recent_history: list[dict],
    active_hypotheses: list[Hypothesis],
    time_range: dict[str, str] | None = None,
    schema_context: str = "",
    extra_context_md: str = "",
    prior_check_feedback: str = "",
    case_profile: str | None = None,
    findings_snapshot: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Build messages for the query_intent_planner phase.

    Decides WHAT data to fetch for this hypothesis, not HOW.
    Uses read_more expansion for memory context.
    """
    from forensia.ai.case_profile import get_profile_event_ids

    _pb_ids: set[int] | None = get_profile_event_ids()
    if (
        _pb_ids is not None
        and hasattr(hypothesis, "confirm_when")
        and isinstance(hypothesis.confirm_when, dict)
    ):
        extra = hypothesis.confirm_when.get("co_observed_event_ids", [])
        if extra:
            _pb_ids.update(int(e) for e in extra if e is not None)

    # --- CONFIRMED_FINDINGS block (top 5 by severity) ---
    confirmed_findings_block = ""
    if findings_snapshot:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings_snapshot,
            key=lambda f: severity_rank.get(str(f.get("severity") or "").lower(), 4),
        )
        top5 = sorted_findings[:5]
        lines = []
        for f in top5:
            title = str(f.get("title") or "").strip()[:80]
            hypothesis_id = str(f.get("hypothesis_id") or "").strip()
            finding_id = str(f.get("finding_id") or "").strip()
            evidence_ids = f.get("evidence_ids") or []
            if isinstance(evidence_ids, str):
                try:
                    evidence_ids = json.loads(evidence_ids)
                except json.JSONDecodeError, TypeError:
                    evidence_ids = [evidence_ids] if evidence_ids else []
            evidence_str = ",".join(str(e) for e in (evidence_ids or [])[:3])
            severity = str(f.get("severity") or "unknown").lower()
            line = f"  - [{severity}] {title}"
            if hypothesis_id or finding_id:
                line += " ("
                if hypothesis_id:
                    line += hypothesis_id
                if finding_id:
                    line += f", finding_id: {finding_id}"
                line += ")"
            if evidence_str:
                line += f" (evidence: {evidence_str})"
            # Truncate to 160 chars per line
            if len(line) > 160:
                line = line[:157] + "..."
            lines.append(line)
        if lines:
            confirmed_findings_block = (
                "\n<CONFIRMED_FINDINGS>\n"
                + "\n".join(lines)
                + "\n</CONFIRMED_FINDINGS>\n"
            )

    system = (
        f"{_dfir_playbook('hypothesis_plan', event_ids=_pb_ids, sections=_sections_for_hypothesis(hypothesis))}\n"
        f"{_time_range_guidance(time_range)}"
        f"{_case_profile_guidance(case_profile)}"
        "<TASK>You are a query_intent_planner. Decide WHAT data to fetch for the given hypothesis. Do NOT write SQL.</TASK>\n"
        "<INPUT_SCHEMA>\n"
        f"hypothesis: {hypothesis.model_dump() if hasattr(hypothesis, 'model_dump') else hypothesis}\n"
        f"{render_prior_attempts(recent_history)}"
        f"time_range: {json.dumps(time_range, ensure_ascii=False, default=str)}\n"
        f"schema: {schema_context}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "read_more": ["list of memory paths for additional context, or empty list"],\n'
        '  "intent": "string — one sentence describing what data to retrieve",\n'
        '  "target_table": "evtx_events | mft_entries | mft_timeline | prefetch_executions",\n'
        '  "filters_required": ["list of column-level filters needed"],\n'
        '  "time_window": "string describing time bounds",\n'
        '  "expected_row_shape": "string describing expected columns"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "If EXECUTION_ERROR is present, you MUST change the query — at minimum change the table list, the WHERE clause, or eliminate the failing JOIN. Never repeat the same SQL that caused an execution error.\n"
        "If prior_check_feedback names specific missing event_ids or evidence types, the new SQL MUST include those event_ids or evidence types. Never ignore prior check feedback.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis.description: {hypothesis.description}\n"
        f"hypothesis.required_entities: {getattr(hypothesis, 'required_entities', [])}\n"
        f"active_hypotheses: {[h.model_dump() if hasattr(h, 'model_dump') else dict(h) for h in active_hypotheses]}\n"
        f"extra_context:\n{extra_context_md}\n"
        f"prior_check_feedback:\n{prior_check_feedback or '(no prior checks)'}\n"
    )
    if confirmed_findings_block:
        system += confirmed_findings_block
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_sql_composer_messages(
    intent: dict,
    table_schema_card: str = "",
    template_catalog: list[dict] | None = None,
    time_range: dict[str, str] | None = None,
    prior_check_feedback: str = "",
) -> list[dict[str, str]]:
    """Build messages for the sql_composer phase.

    Produces a valid DuckDB SELECT statement that satisfies `intent`.
    Idempotent — no read_more cycle needed.
    """
    from forensia.ai.case_profile import get_profile_event_ids

    system = (
        f"{_dfir_playbook('hypothesis_plan', event_ids=get_profile_event_ids())}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a sql_composer. Write a DuckDB SQL query that satisfies the given intent. Output template_id or raw SQL.</TASK>\n"
        "<INPUT_SCHEMA>\n"
        f"intent: {json.dumps(intent, ensure_ascii=False, default=str)}\n"
        f"table_schema: {table_schema_card}\n"
        f"template_catalog: {json.dumps(template_catalog[:10], ensure_ascii=False, default=str)}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "template_id": "string OR null. MUST be either (a) JSON null, or (b) an exact template_id from template_catalog. NEVER the literal string \\"null\\".",\n'
        '  "sql": "string | null — raw SELECT if no template_id matches. Use SQL_COOKBOOK snippets as reference style.",\n'
        '  "params": {"key": "value"},\n'
        '  "purpose": "string — why this query answers the hypothesis"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Exactly ONE of template_id or sql MUST be non-null. The other MUST be null.\n"
        "template_id MUST be an exact match to a template_catalog entry (use null otherwise).\n"
        "Target dialect is DuckDB. Do NOT use SQLite syntax (datetime('now', ...), strftime via SQLite quirks) or MySQL/Postgres syntax (DATE_SUB, INTERVAL ... MINUTE keyword form, NOW()). "
        "For relative time windows on historical evidence, anchor to a literal TIMESTAMP within the case time range, not the current system clock: "
        "`WHERE ts BETWEEN TIMESTAMP '2024-01-15 10:00:00' AND TIMESTAMP '2024-01-15 10:15:00'`. "
        "For interval arithmetic use `ts + INTERVAL 15 MINUTE` or `ts - INTERVAL '15' MINUTE` (DuckDB form), never `DATE_SUB(...)`.\n"
        "Only `evtx_events` carries `computer` / `user_name` columns. `mft_entries`, `mft_timeline`, `prefetch_executions`, and `prefetch_timeline` are single-host filesystem/prefetch artifacts with NO host column. "
        "Do NOT write `JOIN mft_entries m ON e.computer = m.computer` or any host/user equality JOIN across evtx and mft/prefetch — it fails at bind time. "
        "When the intent calls for 'correlate evtx with mft/prefetch', either (a) issue two separate SELECTs and let the verdict step merge them, or (b) JOIN by `file_path` string match against `process_name` / `command_line` / `message`, optionally narrowed by a timestamp BETWEEN window. Only columns listed under each table's SCHEMA_CARD block exist; never invent columns from the table alias.\n"
        "When raw SQL is used: ensure all COALESCE arguments have the same data type. Use json_extract_string (returns VARCHAR) when COALESCE-ing with a VARCHAR column, never json_extract (returns JSON).\n"
        "Never put a VARCHAR-returning function (json_extract_string) and an INTEGER column in the same COALESCE without explicit CAST. "
        "Use: COALESCE(CAST(json_extract_string(json, '$.x') AS BIGINT), int_col) for integer unification, "
        "or COALESCE(CAST(json_extract_string(json, '$.x') AS VARCHAR), CAST(int_col AS VARCHAR)) for string unification.\n"
        "If EXECUTION_ERROR is present, you MUST change the query — at minimum change the table list, the WHERE clause, or eliminate the failing JOIN. Never repeat the same SQL that caused an execution error.\n"
        "If prior_check_feedback names specific missing event_ids or evidence types, the new SQL MUST include those event_ids or evidence types. Never ignore prior check feedback.\n"
        "</RULES>"
    )
    user = json.dumps(
        {
            "intent": intent,
            "prior_check_feedback": prior_check_feedback or "(no prior checks)",
        },
        ensure_ascii=False,
        default=str,
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_sql_self_check_messages(
    intent: dict[str, Any],
    schema_card: str,
) -> tuple[list[dict[str, str]], dict]:
    system = (
        "<TASK>You are a SQL schema validator. Check whether the intent can be expressed as valid SQL against the given schema.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "target_table_exists": true,\n'
        '  "required_columns_present": ["col1", "col2"],\n'
        '  "missing_columns": [],\n'
        '  "join_keys": [{"left_table": "...", "left_col": "...", "right_table": "...", "right_col": "..."}],\n'
        '  "time_column": "timestamp | si_modified | exec_time | ...",\n'
        '  "ready_to_compose": true,\n'
        '  "blockers": "string — empty if ready_to_compose=true, else what is missing"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Check that all columns referenced in the intent exist in the schema card.\n"
        "If JOIN is needed, verify the join key columns exist in both tables.\n"
        "If ready_to_compose is false, describe what's blocking in the blockers field.\n"
        "</RULES>\n"
    )
    user = (
        f"intent: {json.dumps(intent, ensure_ascii=False, default=str)}\n"
        f"schema_card:\n{schema_card}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SQL_SELF_CHECK_SCHEMA


def build_verdict_review_messages(
    hypothesis,
    planned_query,
    result_summary: dict,
    time_range: dict[str, str] | None = None,
    strictness_note: str = "",
    fallback_info: dict | None = None,
    benign_annotations: dict[int, list[str]] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: verdict_reviewer.
    Goal: classify the SQL result vs hypothesis as confirmed/refuted/inconclusive.
    Output JSON: {verdict, rationale, confidence}
    """
    fallback_notice = ""
    if fallback_info:
        phase = fallback_info.get("phase", "unknown")
        fallback_notice = (
            "\nFALLBACK_NOTICE: the rows below were NOT returned by the planned query; "
            f"they come from a fallback search ({phase}). They may belong to a different "
            "event family. You may NOT answer 'confirmed' for the original hypothesis "
            "from fallback rows; choose 'newlead' if they suggest a different lead, "
            "otherwise 'inconclusive'.\n"
        )

    benign_notes_block = ""
    if benign_annotations:
        benign_rules = _load_benign_context_rules()
        rule_notes = {
            r["id"]: r.get("note", "") for r in benign_rules if isinstance(r, dict)
        }
        benign_lines: list[str] = []
        for row_idx in sorted(benign_annotations.keys())[:3]:
            rule_ids = benign_annotations[row_idx]
            notes = [rule_notes.get(rid, rid) for rid in rule_ids]
            benign_lines.append(f"  Row {row_idx}: {'; '.join(notes)}")
        if benign_lines:
            benign_notes_block = (
                "\nBenign-context notes for relevant evidence rows:\n"
                + "\n".join(benign_lines)
                + "\n"
            )

    from forensia.ai.case_profile import get_profile_event_ids

    _pb_ids: set[int] | None = get_profile_event_ids()
    if _pb_ids is not None:
        if hasattr(hypothesis, "confirm_when") and isinstance(
            hypothesis.confirm_when, dict
        ):
            extra = hypothesis.confirm_when.get("co_observed_event_ids", [])
            if extra:
                _pb_ids.update(int(e) for e in extra if e is not None)
        for row in (result_summary or {}).get("sample_rows") or []:
            if not isinstance(row, dict):
                continue
            ev = row.get("event_id")
            if ev is not None:
                try:
                    _pb_ids.add(int(ev))
                except TypeError, ValueError:
                    pass

    system = (
        f"{_dfir_playbook('check', event_ids=_pb_ids, sections=_sections_for_hypothesis(hypothesis, (result_summary or {}).get('sample_rows')))}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a verdict_reviewer. Classify the SQL result against the hypothesis as confirmed, refuted, or inconclusive.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "verdict": "confirmed | refuted | inconclusive",\n'
        '  "rationale": "string — concise reason (< 200 chars)",\n'
        '  "confidence": 0.0-1.0,\n'
        '  "missing_questions": ["specific event_id, table, or evidence type that would resolve the hypothesis (required when verdict=inconclusive, MUST be non-empty in that case)"]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        f"{fallback_notice}"
        "When verdict=inconclusive, missing_questions MUST contain at least 1 specific item naming the missing evidence (e.g. 'event_id 4663', 'mft_entries WHERE file_path LIKE %.docx%', 'browser executable in prefetch_executions'). Do NOT leave it empty.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"query: {planned_query.sql if hasattr(planned_query, 'sql') else planned_query}\n"
        f"result_summary: {json.dumps(result_summary, ensure_ascii=False, default=str)}\n"
        f"{strictness_note}"
        f"{benign_notes_block}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], VERDICT_REVIEW_SCHEMA


def build_finding_extractor_messages(
    hypothesis,
    result_rows: list[dict],
    verdict: str,
    rationale: str,
    time_range: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: finding_extractor.
    Goal: extract finding entries IFF verdict == confirmed.
    Called only when verdict is confirmed.
    """
    system = (
        "<TASK>You are a finding_extractor. Extract findings from the confirmed query results. Only output findings if the evidence clearly supports a specific security event.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "findings": [{"title": "string", "severity": "low|medium|high|critical", "evidence_ids": ["str"], "claim_type": "observation|interpretation"}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Each finding MUST be labeled claim_type.\n"
        "observation: states only what the rows show (who/what/when/where).\n"
        "interpretation: states what it might mean (attack, staging, exfiltration...).\n"
        "An interpretation MUST reference at least one observation finding in its text.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"verdict: {verdict}\n"
        f"rationale: {rationale}\n"
        f"result_rows: {json.dumps(result_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], FINDING_EXTRACTOR_SCHEMA


def build_memory_updater_messages(
    hypothesis,
    verdict: str,
    rationale: str,
    time_range: dict[str, str] | None = None,
    result_summary: dict | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: memory_updater.
    Goal: propose durable memory writes (facts, timeline anchors, entity cards, etc.).
    """
    evidence_block = ""
    if result_summary:
        evidence_block = (
            f"\nevidence_rows: {json.dumps(result_summary.get('sample_rows') or [], default=str, ensure_ascii=False)[:3000]}\n"
            f"observed_evidence_ids: {result_summary.get('evidence_ids')}\n"
        )

    system = (
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a memory_updater. Propose durable memory writes based on the investigation result.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "memory_updates": {\n'
        '    "facts": [{"text": "string", "evidence_ids": ["evtx-...", "mft-..."], "claim_type": "observation|interpretation"}],\n'
        '    "timeline": [{"timestamp": "ISO 8601", "description": "string", "evidence_ids": ["..."]}],\n'
        '    "tasks": [{"text": "string", "kind": "followup | verification | gap"}],\n'
        '    "overview": ["short single-line summary"],\n'
        '    "refuted_hypotheses": [{"hypothesis_id": "H-001", "description": "...", "reason": "..."}],\n'
        '    "resolved_gaps": [{"text": "string", "evidence_ids": ["..."]}],\n'
        '    "entities": [{"entity_type": "user | host | ip | process | service | file | registry | group | machine_account", "name": "string — the entity identifier", "role": "attacker | victim | actor_candidate | observed_user | suspicious_user | newly_created_user | machine_account | unknown", "notes": "1-2 sentences explaining why this entity matters in the case"}]\n'
        "  },\n"
        '  "new_hypotheses": [{"description": "...", "required_entities": ["..."]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Omit any sub-key whose array would be empty — never emit empty arrays. Every fact/timeline/resolved_gap entry MUST cite at least one evidence_id observed in the SQL result; entries without evidence_ids are dropped.\n"
        "Each fact MUST be labeled claim_type.\n"
        "observation: states only what the rows show (who/what/when/where).\n"
        "interpretation: states what it might mean (attack, staging, exfiltration...).\n"
        "An interpretation MUST reference at least one observation fact in its text.\n"
        "ALWAYS register an `entities` entry for every distinct user, host, IP, process, or service that the verdict rationale attributes a role to — this is what populates the Top Entities panel. Use the entity_type / role enums above; freeform values are dropped.\n"
        "Use ONLY evidence_ids from observed_evidence_ids. Use ONLY entity names that literally appear as values in evidence_rows (user_name, target_user, computer, src_ip, process_name, service_name, executable_name, file_name, file_path). Never invent descriptive names like 'Source IP Address'.\n"
        "Examples (entity shapes only):\n"
        '  {"entity_type": "user", "name": "alice", "role": "victim", "notes": "Lost session token after 4624 logon from 10.0.0.5 at 03:14 UTC."}\n'
        '  {"entity_type": "host", "name": "WIN10-DC01", "role": "actor_candidate", "notes": "Source of repeated 4625 failures then a successful 4624 logon within 5 minutes."}\n'
        '  {"entity_type": "ip", "name": "10.0.0.5", "role": "attacker", "notes": "Originating IP for 30+ failed Kerberos pre-auth attempts (4771)."}\n'
        "</RULES>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"verdict: {verdict}\n"
        f"rationale: {rationale}\n"
        f"{evidence_block}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], MEMORY_UPDATER_SCHEMA


def build_gap_identifier_messages(
    observed_keypoints: list[dict],
    uncovered_keypoints: list[dict],
    active_hypotheses_slim: list[dict],
    time_range: dict[str, str] | None = None,
    status_callback: Callable[[str], None] | None = None,
    case_profile: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: gap_identifier.
    Goal: identify which uncovered_keypoints lack active hypothesis coverage.
    """
    slim_observed = [
        {
            "keypoint": kp.get("keypoint") or kp.get("name", ""),
            "row_count": kp.get("row_count", 0),
        }
        for kp in (observed_keypoints or [])
    ]
    available_keypoint_names = [
        kp.get("name") or kp.get("keypoint", "")
        for kp in (observed_keypoints + uncovered_keypoints)[:80]
        if kp.get("name") or kp.get("keypoint")
    ]
    if not available_keypoint_names and (observed_keypoints or uncovered_keypoints):
        logging.warning(
            "gap_identifier: available_keypoint_names empty — check key names: observed has 'keypoint' vs prompt expects 'name'"
        )
    schema = gap_identifier_schema(available_keypoint_names)
    system = (
        "<TASK>You are a gap_identifier. From available_keypoints, pick the ones that lack active hypothesis coverage.</TASK>\n"
        f"{_case_profile_guidance(case_profile)}"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "gap_areas": [{"keypoint_id": "EXACT name from available_keypoints", "why_uncovered": "str", "required_entities": ["snake_case column names"]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "keypoint_id MUST be exact substring match of an entry in available_keypoints. Inventing names will make the agent fail to resolve them.\n"
        "required_entities MUST be snake_case DB column identifiers (e.g. src_ip, target_user, computer, logon_type). NEVER natural language phrases.\n"
        "If active hypotheses already cover all available keypoints, return an empty gap_areas list.\n"
        "</RULES>\n"
        "<EXAMPLE>\n"
        'Input observed_keypoints=[{name: "overview_hosts"}], uncovered_keypoints=[{name: "account_bruteforce_clusters"}], active_hypotheses=[].\n'
        'Output: {"gap_areas": [{"keypoint_id": "account_bruteforce_clusters", "why_uncovered": "no hypothesis targets 4625 clusters yet", "required_entities": ["src_ip", "target_user"]}]}\n'
        "</EXAMPLE>"
    )
    user = (
        f"available_keypoints: {json.dumps([{'name': kp.get('name') or kp.get('keypoint'), 'description': kp.get('description', '')[:80]} for kp in (observed_keypoints + uncovered_keypoints)[:80]], ensure_ascii=False, default=str)}\n"
        f"observed_keypoints: {json.dumps(slim_observed, ensure_ascii=False, default=str)}\n"
        f"uncovered_keypoints: {json.dumps(uncovered_keypoints, ensure_ascii=False, default=str)}\n"
        f"active_hypotheses: {json.dumps(active_hypotheses_slim, ensure_ascii=False, default=str)}\n"
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    total_chars = sum(len(m["content"]) for m in messages)
    if status_callback:
        status_callback(
            f"[gap_identifier] prompt size: {total_chars} chars / ~{total_chars // 4} tokens"
        )
    return messages, schema


def build_hypothesis_drafter_messages(
    gap_area: dict,
    available_rules: list[dict],
    time_range: dict[str, str] | None = None,
    status_callback: Callable[[str], None] | None = None,
    case_profile: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: hypothesis_drafter.
    Goal: draft ONE hypothesis targeting the given gap_area.
    """
    schema = hypothesis_drafter_schema()
    system = (
        "<TASK>You are a hypothesis_drafter. Draft ONE falsifiable hypothesis targeting the given gap_area.</TASK>\n"
        f"{_case_profile_guidance(case_profile)}"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "hypothesis": {\n'
        '    "description": "str (one investigative claim that can be confirmed or refuted by SQL evidence)",\n'
        '    "required_entities": ["snake_case column names such as src_ip, target_user, computer, logon_type, process_name, file_path"],\n'
        '    "source_rule_ids": ["rule_id from available_rules if any aligns, else empty list"],\n'
        '    "confirm_when": {"co_observed_event_ids": [int, ...], "same_host": bool, "within_minutes": int},\n'
        '    "refute_when": {"zero_rows": true}\n'
        "  }\n"
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "confirm_when MUST be a JSON object (not a string). Use co_observed_event_ids as a list of integer Windows event IDs (e.g. [4624, 4625, 4768]).\n"
        "required_entities MUST be column-like identifiers (snake_case), not natural language phrases. Example: src_ip, target_user, computer.\n"
        "confirm_when.co_observed_event_ids MUST be event IDs commonly logged by DEFAULT Windows audit policy. Avoid event IDs that require non-default auditing such as:\n"
        "  - 4663 (Object Access) — requires explicit SACL / Object Access auditing\n"
        "  - 5140/5145 (file share access) — requires File Share auditing\n"
        "  - 4658 / 4660 — Object Access subcategory\n"
        "If the hypothesis fundamentally needs these IDs, state in the description that it is only testable when corresponding audit policy is enabled.\n"
        "event_id semantics:\n"
        "  - 4624/4625 = logon success/failure\n"
        "  - 4648 = explicit credential logon attempt\n"
        "  - 4688 = process creation (NOT 'browser activity' — for browser look at mft_entries / prefetch_executions)\n"
        "  - 4697 / 7045 = service installation\n"
        "  - 4698 = scheduled task creation\n"
        "  - 1102 / 104 = log clearing\n"
        "For browser usage, file activity, or process artifact analysis, prefer mft_entries + prefetch_executions tables over event IDs.\n"
        "Output JSON only.\n"
        "</RULES>\n"
        "<EXAMPLE>\n"
        'Input gap_area: {"keypoint_id": "account_bruteforce_clusters", "required_entities": ["src_ip", "target_user"]}\n'
        'Output: {"hypothesis": {"description": "Repeated 4625 failures from a single src_ip targeting one or more users indicate brute-force attempts that may have been followed by a successful 4624 logon.", "required_entities": ["src_ip", "target_user", "computer"], "source_rule_ids": ["windows-security-4625-failed-logon"], "confirm_when": {"co_observed_event_ids": [4625, 4624], "same_host": true, "within_minutes": 30}, "refute_when": {"zero_rows": true}}}\n'
        "</EXAMPLE>\n"
        "<EXAMPLE_GOOD>\n"
        'Input: gap_area={"keypoint_id": "host_execution_activity", "required_entities": ["computer", "process_name"]}\n'
        'Output: {"hypothesis": {"description": "Unauthorized execution of LOLBAS binaries (powershell.exe, mshta.exe) on WS-SALES-03 indicates initial code execution.", "required_entities": ["computer", "process_name", "command_line"], "source_rule_ids": ["windows-security-4688-suspicious-tools"], "confirm_when": {"co_observed_event_ids": [4688, 4624], "same_host": true, "within_minutes": 5}, "refute_when": {"zero_rows": true}}}\n'
        "</EXAMPLE_GOOD>\n"
        "<EXAMPLE_BAD>\n"
        'Output: {"hypothesis": {"description": "...", "required_entities": ["user_identity", "computer_name", "logon_type", "credential_usage"]}}\n'
        "Reason: required_entities must be snake_case column-like names (target_user, computer, logon_type), not natural language. NEVER use natural language for required_entities.\n"
        "</EXAMPLE_BAD>\n"
        "<EXAMPLE_BAD>\n"
        'Output: {"hypothesis": {"description": "Logon (4624) followed by file access (4663) or browser activity (4688)...", "confirm_when": {"co_observed_event_ids": [4624, 4663, 4688]}}}\n'
        'Reason: 4663 requires Object Access auditing (rarely enabled), and 4688 is process creation not "browser activity". Better: split into two hypotheses — one tested via 4624 + mft_entries WHERE file_path LIKE patterns, another via 4624 + prefetch_executions filtered to browser executable names.\n'
        "</EXAMPLE_BAD>\n"
    )
    # T-09: Slim each rule to essential fields only
    slim_rules: list[dict[str, Any]] = []
    for rule in available_rules[:5]:
        if not isinstance(rule, dict):
            continue
        slim_hypotheses: list[dict[str, Any]] = []
        for h in rule.get("hypotheses") or []:
            if isinstance(h, dict):
                slim_hypotheses.append(
                    {
                        "description": h.get("description", ""),
                        "confirm_when": h.get("confirm_when"),
                    }
                )
        slim_rules.append(
            {
                "id": rule.get("id", ""),
                "title": rule.get("title", ""),
                "tags": rule.get("tags", []),
                "hypotheses": slim_hypotheses,
            }
        )
    user = (
        f"gap_area: {json.dumps(gap_area, ensure_ascii=False, default=str)}\n"
        f"available_rules: {json.dumps(slim_rules, ensure_ascii=False, default=str)}\n"
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    total_chars = sum(len(m["content"]) for m in messages)
    if status_callback:
        status_callback(
            f"[hypothesis_drafter] prompt size: {total_chars} chars / ~{total_chars // 4} tokens"
        )
    return messages, schema
