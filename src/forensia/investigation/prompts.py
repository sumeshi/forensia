"""Prompt builders for the investigation loop."""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import Callable
from typing import Any

from forensia.context.case_profile import CaseEvidenceProfile, observed_event_contexts
from forensia.context.playbook import (
    _dfir_playbook,
    _sections_for_hypothesis,
)
from forensia.context.prompt_context import (
    _case_profile_guidance,
    _org_knowledge_guidance,
    _time_range_guidance,
    capture_prompt_retrieval,
    prompt_value_projection,
)
from forensia.context.sql_templates import query_template_catalog_for_tables
from forensia.core.session import Hypothesis
from forensia.db.evidence_lookup import canonical_record_table, routed_family
from forensia.db.query import normalize_value
from forensia.db.schema import load_live_schema
from forensia.investigation.case_policy import case_policy_block
from forensia.knowledge.catalog import load_benign_context_rules
from forensia.knowledge.coverage import (
    disclosure_tables_for_spec,
    observation_catalog,
)
from forensia.knowledge.retrieval import knowledge_terms_for_hypothesis, select_snippets
from forensia.llm.schemas import (
    FINDING_EXTRACTOR_SCHEMA,
    SNAKE_CASE_COLUMNS,
    VERDICT_REVIEW_SCHEMA,
    gap_identifier_schema,
    hypothesis_drafter_schema,
)


def _work_disclosure_tables(
    hypothesis: Any, spec_payload: Any = None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """One spec → disclosure correspondence read for prompt assembly (V2-08).

    Uses ``knowledge.coverage.disclosure_tables_for_spec`` — the artifact
    capability catalog that Coverage and the work judgment already share — so
    schema cards, playbook artifact gating, and template disclosure all derive
    from one correspondence.  The caller may pass the canonical Case State
    spec payload (the planner's authoritative read); without it the
    in-session hypothesis spec is used.  Draft-phase hypotheses without a
    canonical spec disclose nothing family-specific (never a widened default).
    """
    spec = (
        spec_payload
        if spec_payload is not None
        else getattr(hypothesis, "verification_spec", None)
    )
    return disclosure_tables_for_spec(spec)


def _template_catalog_block(entries: list[dict[str, Any]]) -> str:
    """Render the executable-template entries disclosed for this work (V2-08).

    The bounded subset from the spec/capability correspondence; the host still
    re-renders each chosen template and validates the SQL independently of
    this prompt content.
    """
    if not entries:
        return ""
    lines = [
        "<TEMPLATE_CATALOG>",
        "Executable query templates selected for this work's artifact tables. "
        "Use template_id + params (the host re-renders and validates the SQL); "
        "unknown cases still adapt a bounded SELECT with template_id=null and non-empty sql.",
        "<INDEX>",
    ]
    for entry in entries:
        lines.append(
            f"- id={entry['template_id']} | params={json.dumps(entry['parameters'])} | "
            f"{entry['description']}"
        )
    lines.append("</INDEX>")
    lines.append("</TEMPLATE_CATALOG>")
    return "\n".join(lines) + "\n"


def _query_intent_examples(
    tables: tuple[str, ...] | list[str], templates: list[dict[str, Any]]
) -> str:
    """Render complete actions using the same bounded catalog shown above."""
    if not tables:
        return ""
    table = tables[0]
    record_id = "artifact_id" if table.startswith("registry") else "evidence_id"
    actions = [
        {
            "action": {
                "intent": "inspect matching evidence",
                "target_table": table,
                "template_id": None,
                "sql": f"SELECT {record_id} FROM {table} LIMIT 20",
            }
        }
    ]
    if templates:
        template = templates[0]
        params = {
            name: template["parameters"][name].get("default")
            or (
                template["parameters"][name].get("minimum", 1)
                if template["parameters"][name]["type"] == "integer"
                else "example"
            )
            for name in template["required_params"]
        }
        actions.append(
            {
                "action": {
                    "intent": "inspect matching evidence",
                    "target_table": template["tables"][0],
                    "template_id": template["template_id"],
                    "params": params,
                    "sql": "",
                }
            }
        )
    labels = ("RAW_SQL_EXAMPLE", "RECIPE_EXAMPLE")
    return "\n".join(
        f"{labels[index]}: {json.dumps(action, ensure_ascii=False)}"
        for index, action in enumerate(actions)
    )


def _org_knowledge_block(
    *,
    title: str = "",
    description: str = "",
    tables: list[str] | None = None,
    extra_words: list[str] | None = None,
    tags: list[str] | None = None,
    db: Any | None = None,
    session_id: str | None = None,
    phase: str = "hypothesis_plan",
) -> str:
    """Build an ``<ORG_KNOWLEDGE>`` block from the global knowledge index.

    Returns empty string if no knowledge docs are loaded.  When a ``db`` is
    supplied the adopted sections and their size are recorded once in the
    existing Trace retrieval events (V2-08).
    """
    from forensia.knowledge.external import get_knowledge_docs

    docs = get_knowledge_docs()
    if not docs:
        return ""
    terms = knowledge_terms_for_hypothesis(
        title=title,
        description=description,
        tables=tables,
        extra_words=extra_words,
    )
    if not terms:
        return ""
    snippets = select_snippets(
        docs,
        query_terms=terms,
        tags=tags or [],
    )
    return _org_knowledge_guidance(snippets, db, session_id, phase=phase)


def render_prior_attempts(recent_history: list[dict[str, Any]], limit: int = 10) -> str:
    """Render hypothesis attempt history as a compact structured block.

    Each attempt is keyed by its durable receipt reference. Display query IDs
    only as labels because they can repeat across resumed cycles.
    """
    entries = [item for item in (recent_history or []) if isinstance(item, dict)]
    if not entries:
        return "<PRIOR_ATTEMPTS>\n(none)\n</PRIOR_ATTEMPTS>\n"
    entries = entries[-limit:]
    lines: list[str] = []
    for idx, item in enumerate(entries, 1):
        parts: list[str] = []
        attempt_ref = str(item.get("attempt_ref") or "").strip()
        if attempt_ref:
            parts.append(f"attempt_ref={attempt_ref}")
        query_id = str(item.get("query_id") or "").strip()
        if query_id:
            parts.append(f"query_id={query_id}")
        for field in (
            "iteration",
            "status",
            "retrieval_outcome",
            "returned_count",
            "query_fingerprint",
            "verification_spec_fingerprint",
            "evidence_scope_fingerprint",
        ):
            value = item.get(field)
            if value not in (None, ""):
                parts.append(f"{field}={value}")
        evidence_ids = item.get("evidence_ids")
        if isinstance(evidence_ids, list):
            parts.append(
                f"evidence_ids=[{','.join(str(value) for value in evidence_ids[:8])}]"
            )
        purpose = str(item.get("purpose") or "").strip().replace("\n", " ")
        if purpose:
            parts.append(f"purpose={purpose[:120]}")
        normalized_sql = str(item.get("normalized_sql") or "").strip()
        if normalized_sql:
            parts.append(f"sql={json.dumps(normalized_sql, ensure_ascii=False)}")
        reason = str(item.get("reason") or "").strip().replace("\n", " ")
        if reason:
            parts.append(f"reason={reason[:120]}")
        lines.append(f"- attempt {idx}: " + ", ".join(parts))
    return (
        "<PRIOR_ATTEMPTS>\n"
        "Attempts are ordered oldest to newest. Query IDs may repeat after resume; compare receipt, query, spec, and evidence-scope fingerprints.\n"
        + "\n".join(lines)
        + "\n</PRIOR_ATTEMPTS>\n"
    )


_load_benign_context_rules = load_benign_context_rules


def _hypothesis_prompt_projection(
    hypothesis: Any, *, peer: bool = False
) -> dict[str, Any]:
    """Project durable hypothesis state into the planner's prompt contract."""
    if hasattr(hypothesis, "model_dump"):
        payload = hypothesis.model_dump(mode="json")
    elif isinstance(hypothesis, dict):
        payload = dict(hypothesis)
    else:
        return {"description": str(hypothesis)}
    fields = ("id", "description", "status", "verdict", "target_keypoint_id")
    projected = {key: payload[key] for key in fields if payload.get(key) is not None}
    if not peer:
        projected["required_entities"] = payload.get("required_entities") or []
        projected["verification_spec"] = payload.get("verification_spec") or {}
    return projected


_PROMPT_ROW_NOISE_FIELDS = {
    "ingested_at",
    "provider_guid",
    "source_file",
    "source_path",
    "_source",
    "raw",
    "raw_json",
}

_RAW_EVENT_CONTEXT_CHARS = 1800
_RAW_EVENT_CONTEXT_FIELD_CHARS = 320
_RAW_EVENT_CONTEXT_FIELDS = 20


def _raw_event_context(value: Any) -> dict[str, Any]:
    """Keep whole bounded event fields and identify fields omitted for size."""
    if isinstance(value, str):
        try:
            raw = json.loads(value)
        except json.JSONDecodeError, TypeError:
            return {}
    elif isinstance(value, dict):
        raw = value
    else:
        return {}
    if not isinstance(raw, dict):
        return {}

    event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
    winlog = raw.get("winlog") if isinstance(raw.get("winlog"), dict) else {}
    provider = winlog.get("provider")
    provider_name = provider.get("name") if isinstance(provider, dict) else provider
    candidates: list[tuple[str, str, str | None, Any]] = [
        ("channel", "channel", None, winlog.get("channel") or raw.get("channel")),
        ("provider", "provider", None, provider_name or event.get("provider")),
        (
            "event_id",
            "event_id",
            None,
            winlog.get("event_id") or event.get("code"),
        ),
    ]
    for group_name in ("event_data", "user_data"):
        group = winlog.get(group_name)
        if isinstance(group, dict):
            candidates.extend(
                (f"{group_name}.{key}", group_name, str(key), item)
                for key, item in group.items()
            )
        elif group not in (None, "", {}):
            candidates.append((group_name, group_name, None, group))
    if raw.get("message") not in (None, "", {}):
        candidates.append(("message", "message", None, raw["message"]))

    context: dict[str, Any] = {}
    omitted: list[str] = []
    used_chars = 0
    selected_fields = 0
    for field_id, group_name, key, item in candidates:
        if item in (None, "", {}):
            continue
        item_chars = len(
            json.dumps(
                {key: item} if key is not None else {group_name: item},
                ensure_ascii=False,
                default=str,
            )
        )
        if (
            item_chars > _RAW_EVENT_CONTEXT_FIELD_CHARS
            or used_chars + item_chars > _RAW_EVENT_CONTEXT_CHARS
            or selected_fields >= _RAW_EVENT_CONTEXT_FIELDS
        ):
            omitted.append(field_id)
            continue
        if key is None:
            context[group_name] = item
        else:
            context.setdefault(group_name, {})[key] = item
        used_chars += item_chars
        selected_fields += 1
    if omitted:
        omitted_field_ids: list[str] = []
        omitted_ids_chars = 0
        for field_id in omitted:
            field_id_chars = len(json.dumps(field_id, ensure_ascii=False))
            if (
                len(omitted_field_ids) >= _RAW_EVENT_CONTEXT_FIELDS
                or omitted_ids_chars + field_id_chars > 512
            ):
                continue
            omitted_field_ids.append(field_id)
            omitted_ids_chars += field_id_chars
        context["omitted_field_count"] = len(omitted)
        context["omitted_field_ids"] = omitted_field_ids
    return context


def _result_summary_prompt_projection(
    result_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    """Remove duplicate samples and bound raw event context for LLM prompts."""
    source = result_summary or {}
    projected = {
        key: value
        for key, value in source.items()
        if key not in {"head_rows", "tail_rows", "sample_rows"}
    }
    rows: list[dict[str, Any]] = []
    represented_raw_groups: set[tuple[str, str, str]] = set()
    for source_row in source.get("sample_rows") or []:
        if not isinstance(source_row, dict):
            continue
        row = {
            key: prompt_value_projection(value)
            for key, value in source_row.items()
            if key not in _PROMPT_ROW_NOISE_FIELDS
        }
        raw_context = _raw_event_context(
            source_row.get("raw") or source_row.get("raw_json")
        )
        group = (
            str(row.get("channel") or raw_context.get("channel") or ""),
            str(row.get("provider") or raw_context.get("provider") or ""),
            str(row.get("event_id") or raw_context.get("event_id") or ""),
        )
        if raw_context and group not in represented_raw_groups:
            row["raw_event_context"] = raw_context
            represented_raw_groups.add(group)
        rows.append(row)
    projected["sample_rows"] = rows
    return projected


@capture_prompt_retrieval
def build_query_intent_messages(
    hypothesis,
    recent_history: list[dict],
    active_hypotheses: list[Hypothesis],
    time_range: dict[str, str] | None = None,
    schema_context: str = "",
    host_feedback: str = "",
    prior_check_feedback: str = "",
    case_profile: CaseEvidenceProfile | None = None,
    case_policy: Any | None = None,
    findings_snapshot: list[dict[str, Any]] | None = None,
    working_state_block: str = "",
    db: Any | None = None,
    session_id: str | None = None,
    spec_payload: Any = None,
    eligible_tables: tuple[str, ...] | None = None,
    test_intent: str = "primary_verification",
) -> list[dict[str, str]]:
    """Build messages for the query_intent_planner phase.

    Decides WHAT data to fetch for this hypothesis, not HOW.
    ``working_state_block`` is the bounded Case/Trace working-state projection.

    Disclosure (V2-08): one spec/phase/artifact pathway selects everything
    that appears here — ``schema_tables`` cards (spec capability families'
    primary tables), the bounded executable ``<TEMPLATE_CATALOG>`` subset,
    the playbook's artifact catalogs (gated to the same families), and the
    ``<ORG_KNOWLEDGE>`` snippets (instrumented into Trace when a ``db`` is
    supplied). Disclosure is reference only: the typed action menu, host
    validation and phasing are never extended by any of it.
    """
    disclosure_tables, _primary_tables = _work_disclosure_tables(
        hypothesis, spec_payload
    )
    planning_tables = (
        eligible_tables if eligible_tables is not None else disclosure_tables
    )
    template_catalog = query_template_catalog_for_tables(planning_tables or ())
    template_catalog_md = _template_catalog_block(template_catalog)
    action_examples = _query_intent_examples(planning_tables, template_catalog)
    playbook_tables = set(planning_tables) or None
    profile_event_ids = (
        set(case_profile.event_ids)
        if case_profile and case_profile.event_ids is not None
        else None
    )
    hypothesis_event_ids: set[int] = set()
    if hypothesis.verification_spec.support_conditions:
        extra = hypothesis.verification_spec.support_conditions.get(
            "co_observed_event_ids", []
        )
        hypothesis_event_ids.update(int(e) for e in extra if e is not None)
    _pb_ids: set[int] | None = hypothesis_event_ids or profile_event_ids

    # Rule matches help choose work; they do not establish activity.
    rule_match_leads_block = ""
    if findings_snapshot:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings_snapshot,
            key=lambda f: severity_rank.get(str(f.get("severity") or "").lower(), 4),
        )
        top5 = sorted_findings[:5]
        lines = []
        for f in top5:
            title = str(f.get("title") or "").strip().replace("\n", " ")[:80]
            hypothesis_id = str(f.get("hypothesis_id") or "").strip()
            finding_id = str(f.get("finding_id") or "").strip()
            evidence_ids = f.get("evidence_ids") or []
            if isinstance(evidence_ids, str):
                try:
                    evidence_ids = json.loads(evidence_ids)
                except json.JSONDecodeError, TypeError:
                    evidence_ids = [evidence_ids] if evidence_ids else []
            evidence_ids = [str(e) for e in evidence_ids if e]
            evidence_str = ",".join(evidence_ids[:3])
            severity = str(f.get("severity") or "unknown").lower()
            line = f"  - [{severity}] {title or 'Rule match'}"
            if hypothesis_id or finding_id:
                line += " ("
                if hypothesis_id:
                    line += hypothesis_id
                if finding_id:
                    line += f"; finding_id={finding_id}"
                line += ")"
            if evidence_str:
                line += f" evidence_ids=[{evidence_str}]"
                omitted = len(evidence_ids) - len(evidence_ids[:3])
                if omitted:
                    line += f" (+{omitted} omitted)"
            lines.append(line)
        if lines:
            rule_match_leads_block = (
                "\n<RULE_MATCH_LEADS status=unverified>\n"
                "Rule matches are leads, not confirmed activity. Verify against evidence.\n"
                + "\n".join(lines)
                + "\n</RULE_MATCH_LEADS>\n"
            )

    knowledge_extra = list(getattr(hypothesis, "required_entities", []) or [])
    if prior_check_feedback:
        knowledge_extra.append(prior_check_feedback)
    knowledge_extra.extend(
        str(item.get("summary") or item.get("body") or item.get("purpose") or "")[:240]
        for item in recent_history[-3:]
        if isinstance(item, dict)
    )
    system = (
        (f"{case_policy_block(case_policy)}" if case_policy is not None else "")
        + f"{_dfir_playbook('hypothesis_plan', event_ids=_pb_ids, tables=playbook_tables, sections=_sections_for_hypothesis(hypothesis), db=db, session_id=session_id)}\n"
        f"{_time_range_guidance(time_range)}"
        f"{_case_profile_guidance(case_profile.summary if case_profile else None)}"
        f"{_org_knowledge_block(description=getattr(hypothesis, 'description', ''), extra_words=knowledge_extra, db=db, session_id=session_id, phase='hypothesis_plan')}"
        f"<TASK>You are the bounded query action planner. This action is {test_intent}. "
        + (
            "Choose one action using either an exact executable template_catalog ID with params or a bounded SELECT fallback. Cookbook/RECIPE_INDEX IDs are reference-only and must be adapted into raw SQL with template_id=null. "
            if template_catalog
            else "The executable template catalog is empty; use only a bounded raw SELECT with template_id=null. "
        )
        + "The host validates and executes it; do not delegate SQL composition to another model.</TASK>\n"
        + "<INPUT_SCHEMA>\n"
        f"hypothesis: {json.dumps(_hypothesis_prompt_projection(hypothesis), ensure_ascii=False, default=str)}\n"
        f"{render_prior_attempts(recent_history)}"
        f"time_range: {json.dumps(time_range, ensure_ascii=False, default=str)}\n"
        f"eligible_tables: {json.dumps(planning_tables)}\n"
        f"{template_catalog_md}"
        f"schema: {schema_context}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "Return exactly one action as JSON. Fields: intent (string), target_table "
        "(string from eligible_tables), template_id (string for a catalog recipe, "
        "otherwise null), sql (non-empty SELECT for raw SQL, otherwise empty); "
        "params is an object only for recipes. Raw SQL must select canonical "
        "evidence_id (or Registry artifact_id) and use eligible_tables.\n"
        "Types and complete examples (one JSON object per line): intent string; "
        "target_table string from eligible_tables; template_id string or null; "
        "sql string; params object only when template_id is a string.\n"
        f"{action_examples}\n" + "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        + (
            "The action MUST include a complete intent, known target_table, and one path: copy an executable template ID from <TEMPLATE_CATALOG>, provide params, and set sql to empty; or set template_id to null and provide a bounded SELECT. RECIPE_INDEX IDs are never valid template IDs. Do not emit an empty or ambiguous action.\n"
            if template_catalog
            else "The executable template catalog is empty, so use only the raw SQL path: set template_id to null and provide a bounded SELECT. Do not include params or invent a template ID.\n"
        )
        + "If EXECUTION_ERROR is present, you MUST change the query — at minimum change the table list, the WHERE clause, or eliminate the failing JOIN. Never repeat the same SQL that caused an execution error.\n"
        + "Address prior_check_feedback within eligible_tables. If required evidence is outside the eligible catalog, report the unmet requirement instead of proposing an unauthorized query.\n"
        + "Keep the original subject, time scope, and proposition. Consider a plausible alternative explanation and choose a search whose results could distinguish it from the hypothesis. In intent, state what the search can support or contradict. Do not invent an alternative when the evidence cannot distinguish one.\n"
        + (
            "This is corroboration after the typed primary search. Do not repeat that primary query or merely reselect values already supplied. Use the previous result and missing requirements to seek new support or counterevidence, preserving the subject. Use only tables listed in the selected schema cards; cross-family corroboration is allowed only when those tables are listed. Keep the purpose and evidence family explicit.\n"
            if test_intent == "corroboration"
            else "This is the primary verification search. Keep its family and typed observation field in scope.\n"
        )
        + "</RULES>"
    )
    current_id = str(getattr(hypothesis, "id", "") or "")
    peer_hypotheses = [
        _hypothesis_prompt_projection(item, peer=True)
        for item in active_hypotheses
        if str(getattr(item, "id", "") or "") != current_id
    ]
    user = (
        f"{working_state_block}"
        f"peer_active_hypotheses: {json.dumps(peer_hypotheses, ensure_ascii=False, default=str)}\n"
        f"host_feedback:\n{host_feedback}\n"
        f"prior_check_feedback:\n{prior_check_feedback or '(no prior checks)'}\n"
    )
    if rule_match_leads_block:
        system += rule_match_leads_block
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


@capture_prompt_retrieval
def build_verdict_review_messages(
    hypothesis,
    planned_query,
    result_summary: dict,
    time_range: dict[str, str] | None = None,
    strictness_note: str = "",
    fallback_info: dict | None = None,
    benign_annotations: dict[int, list[str]] | None = None,
    db: Any | None = None,
    session_id: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: verdict_reviewer.
    Classify the SQL result as confirmed/refuted/inconclusive/newlead.
    Inconclusive responses identify missing evidence; newlead may add follow-ups.
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

    _pb_ids: set[int] = set()
    if hypothesis.verification_spec.support_conditions:
        extra = hypothesis.verification_spec.support_conditions.get(
            "co_observed_event_ids", []
        )
        for event_id in extra:
            try:
                _pb_ids.add(int(event_id))
            except TypeError, ValueError:
                pass
    for event_id in (result_summary or {}).get("event_id_set") or []:
        try:
            _pb_ids.add(int(event_id))
        except TypeError, ValueError:
            pass
    for row in (result_summary or {}).get("sample_rows") or []:
        if not isinstance(row, dict):
            continue
        try:
            _pb_ids.add(int(row.get("event_id")))
        except TypeError, ValueError:
            pass
    prompt_result_summary = _result_summary_prompt_projection(result_summary)
    prompt_hypothesis = _hypothesis_prompt_projection(hypothesis)

    # V2-08: the check prompt is disclosed from the same spec/capability
    # correspondence as the plan prompt: artifact catalogs gate to the work's
    # families, and the playbook build is recorded in Trace when a db/session
    # is supplied. Disclosure grants no permission; the checker proposes a
    # semantic verdict that the deterministic gates still verify.
    disclosure_tables, _ = _work_disclosure_tables(hypothesis)
    playbook_tables = set(disclosure_tables) or None
    system = (
        f"{_dfir_playbook('check', event_ids=_pb_ids, tables=playbook_tables, sections=_sections_for_hypothesis(hypothesis, (result_summary or {}).get('sample_rows')), db=db, session_id=session_id)}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a verdict_reviewer. Classify the SQL result as confirmed, refuted, inconclusive, or newlead.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "verdict": "confirmed | refuted | inconclusive | newlead",\n'
        '  "rationale": "string — concise reason (< 200 chars)",\n'
        '  "confidence": 0.0-1.0,\n'
        '  "missing_questions": ["specific missing evidence; non-empty only when verdict=inconclusive"],\n'
        '  "new_hypotheses": [{"description": "...", "required_entities": ["..."], "confirm_when": {}, "refute_when": {}, "source_rule_ids": ["..."]}] (up to 3; id optional)\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "row_count counts citable rows; observed_row_count counts retrieved rows. Missing IDs or partial retrieval are not evidence of absence. Read retrieval_evaluation before interpreting a zero row_count.\n"
        "Evaluate the original proposition, not a stronger accusation. Consider whether the returned evidence also fits an alternative explanation and identify the observation that distinguishes them. A benign explanation does not refute a claim that only describes an activity. No counterevidence is not proof of the hypothesis.\n"
        "Use only evidence actually returned in this result for the verdict; prompt context and earlier observations are leads, not newly retrieved support. If the alternatives cannot be distinguished, return inconclusive with the specific missing evidence. Do not manufacture a counterargument or require malicious intent when the hypothesis does not assert it.\n"
        f"{fallback_notice}"
        "When verdict=inconclusive, missing_questions MUST contain at least 1 specific item naming the missing evidence (e.g. 'event_id 4663', 'mft_entries WHERE file_path LIKE %.docx%', 'browser executable in prefetch_executions'). Do NOT leave it empty.\n"
        "For confirmed, refuted, or newlead, return an empty missing_questions array.\n"
        "When verdict=newlead, include at most 3 concrete follow-up hypotheses with testable confirm_when conditions and useful refute_when conditions. Omit id unless you have a valid H-NNN id; otherwise the host assigns one. Otherwise omit new_hypotheses.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis: {json.dumps(prompt_hypothesis, ensure_ascii=False, default=str)}\n"
        f"query: {planned_query.sql if hasattr(planned_query, 'sql') else planned_query}\n"
        f"result_summary: {json.dumps(prompt_result_summary, ensure_ascii=False, default=str)}\n"
        f"{strictness_note}"
        f"{benign_notes_block}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], VERDICT_REVIEW_SCHEMA


@capture_prompt_retrieval
def build_finding_extractor_messages(
    hypothesis,
    result_rows: list[dict],
    verdict: str,
    rationale: str,
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


@capture_prompt_retrieval
def build_gap_identifier_messages(
    observed_keypoints: list[dict],
    uncovered_keypoints: list[dict],
    active_hypotheses_slim: list[dict],
    status_callback: Callable[[str], None] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
    case_policy: Any | None = None,
    db: Any | None = None,
    session_id: str | None = None,
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
    _gap_extra = [
        kp.get("name") or kp.get("keypoint", "")
        for kp in (observed_keypoints + uncovered_keypoints)[:20]
        if kp.get("name") or kp.get("keypoint")
    ]
    system = (
        (f"{case_policy_block(case_policy)}" if case_policy is not None else "")
        + "<TASK>You are a gap_identifier. From available_keypoints, pick the ones that lack active hypothesis coverage.</TASK>\n"
        f"{_case_profile_guidance(case_profile.summary if case_profile else None)}"
        f"{_org_knowledge_block(extra_words=_gap_extra, db=db, session_id=session_id, phase='plan_broad_gap')}"
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


def build_gap_discovery_messages(
    question: str,
    *,
    schema_context: str,
    request_catalog: dict[str, list[str]],
    case_policy: Any | None = None,
    feedback: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    fixed_contract_retry = (
        isinstance(feedback, dict) and feedback.get("contract_validated") is True
    )
    empty_contract_retry = fixed_contract_retry and feedback.get("status") == "empty"
    contract_response_instruction = (
        "The host has already validated and fixed request_contract. Return only the action property and omit request_contract entirely. "
        if fixed_contract_retry
        else "Before querying, return request_contract and action as sibling properties of the root response. A resolved request_contract uses exactly one artifact family across all scope_filters and requirements; use only exact family-to-field mappings in available_question_fields. If the whole request cannot be represented within one family, keep it unresolved rather than dropping requirements. Include every explicit subject/time scope filter and requested field or predicate. "
    )
    request_contract_guidance = (
        "For unknown requested values use kind=observed_value and omit operator/value; never fill them from search results. "
        "For a question about a known predicate use kind=predicate with its exact operator/value. "
        "Contract status means whether the request can be represented with available fields, not whether its answer is known. If a requested value is unknown but its field is available, set status=resolved; put only literal subject/time constraints stated in the question in scope_filters, and put requested unknown fields in requirements. Use status=unresolved with requirements=[] only when a requested field or constraint cannot be represented with available fields. "
        if not fixed_contract_retry
        else ""
    )
    scope_operator_guidance = "For scope_filters, equals means one exact value or complete path. For a declared path field, path_under means a descendant of the stated directory path: match whole path components, case-insensitively, treating / and \\ as separators; do not treat %, _, or other characters as wildcards. Keep drive, leading-slash, and UNC roots intact. Choose the operator that matches the requested relation before validation; the host never silently converts between equals and path_under. An unvalidated contract may be corrected, while a validated retry keeps its fixed contract. "
    zero_row_retry = (
        "The previous query returned no scoped evidence. Keep the fixed contract's artifact family and scope; do not relax scope filters or predicates. Try one materially different bounded SELECT within that same family, removing incidental filters or using another justified field from the supplied schema. Do not invent search values or treat zero results as proof of absence. Do not repeat the prior SQL; if no distinct search is justified, return the prior action unchanged so the host can stop without executing it again. "
        if empty_contract_retry
        else ""
    )
    contract_retry_instruction = (
        "The previous SQL action was rejected. Keep the host-fixed request_contract and artifact family; return only a corrected action and do not include request_contract. Correct the SQL using the previous rejection reason. "
        if fixed_contract_retry and not empty_contract_retry
        else "On a correction retry, preserve the previous request_contract only when previous_attempt.contract_validated is true; otherwise correct the contract as needed. "
        if not fixed_contract_retry
        else ""
    )
    return [
        {
            "role": "system",
            "content": (
                "Find evidence relevant to the user's exact unresolved question. "
                + contract_response_instruction
                + request_contract_guidance
                + scope_operator_guidance
                + contract_retry_instruction
                + zero_row_retry
                + "Choose one bounded SELECT using only the supplied tables and columns. "
                "Return evidence_id (artifact_id for Registry) for every candidate; do not aggregate away IDs. "
                "Unknown answers are what the query must discover, never invented search literals. "
                "Preserve explicit subjects, files and time scope. A result is only a lead, "
                "not proof of completeness, absence, intent or causality. Use raw SQL with template_id null."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "question": question,
                    "available_question_fields": request_catalog,
                    "policy": str(getattr(case_policy, "body", "") or ""),
                    "available_schema": schema_context,
                    "previous_attempt": feedback,
                },
                ensure_ascii=False,
                default=str,
            ),
        },
    ]


def _has_observed_value(value: Any) -> bool:
    value = normalize_value(value)
    if isinstance(value, list):
        return any(
            isinstance(item, (str, int, float))
            and not (isinstance(item, str) and not item.strip())
            for item in value
        )
    return value is not None and not (isinstance(value, str) and not value.strip())


@capture_prompt_retrieval
def build_hypothesis_drafter_messages(
    gap_area: dict,
    available_rules: list[dict],
    status_callback: Callable[[str], None] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
    case_policy: Any | None = None,
    db: Any | None = None,
    session_id: str | None = None,
    observed_candidate: dict[str, Any] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """Draft one testable hypothesis from a real observation or existing gap."""
    typed_catalog = observation_catalog()
    candidate_family = (
        str(((observed_candidate or {}).get("scope") or {}).get("source_family") or "")
        .strip()
        .lower()
    )
    question_candidate = bool((observed_candidate or {}).get("request_contract"))
    observation_only = candidate_family in typed_catalog and (
        candidate_family != "evtx" or question_candidate
    )
    requested_observations = {
        (str(item.get("family") or "").strip().lower(), str(item.get("field") or ""))
        for item in ((observed_candidate or {}).get("request_contract") or {}).get(
            "requirements", []
        )
        if isinstance(item, dict)
    }
    if observation_only:
        typed_catalog = {candidate_family: typed_catalog[candidate_family]}
    evidence_fields = (
        "evidence_id",
        "_source",
        "source_file",
        "timestamp",
        "timestamp_kind",
        "channel",
        "provider",
        "event_id",
        "command_line",
        "computer",
        "host",
        "service_name",
        "logon_type",
        "subject_user",
        "target_user",
        "target_group",
        "target_server",
        "src_ip",
        "dst_ip",
        "file_path",
        "si_created",
        "si_modified",
        "fn_created",
        "fn_modified",
        "is_directory",
        "is_deleted",
        "process_name",
        "executable_name",
        "last_exec_time",
        "exec_times",
        "exec_count",
        "filenames",
        "volumes",
        "plugin",
        "hive",
        "key_path",
        "value_name",
        "value_data",
        "object_dn",
    )
    if candidate_family:
        metadata_fields = {
            "evidence_id",
            "_source",
            "source_file",
            "event_id",
            "channel",
            "provider",
        }
        candidate_fields = set(
            typed_catalog.get(candidate_family, {}).get("fields", [])
        )
        evidence_fields = tuple(
            sorted(
                metadata_fields
                | (
                    {
                        field
                        for family, field in requested_observations
                        if family == candidate_family
                    }
                    if question_candidate
                    else set(evidence_fields) & candidate_fields
                )
            )
        )
    typed_observations: dict[str, dict[str, Any]] = {}
    typed_observation_examples: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in (observed_candidate or {}).get("evidence", [])[:3]:
        if not isinstance(row, dict):
            continue
        family = routed_family(str(row.get("evidence_id") or ""))
        if (
            family is None
            or family == "evtx"
            and not question_candidate
            or row.get("_source") != canonical_record_table(family)
            or family not in typed_catalog
        ):
            continue
        fields = [
            field
            for field in typed_catalog[family]["fields"]
            if field in evidence_fields
            and (not question_candidate or (family, field) in requested_observations)
            and _has_observed_value(row.get(field))
        ]
        if fields:
            definition = typed_observations.setdefault(
                family,
                {
                    "capabilities": typed_catalog[family]["capabilities"],
                    "fields": [],
                    "boolean_fields": [],
                },
            )
            boolean_fields = set(typed_catalog[family]["boolean_fields"])
            for field in fields:
                target = "boolean_fields" if field in boolean_fields else "fields"
                definition[target] = sorted(set(definition[target] + [field]))
                value = normalize_value(row[field])
                operator = "equals"
                if isinstance(value, list):
                    value = next(
                        (
                            item
                            for item in value[:3]
                            if isinstance(item, str) and item.strip()
                        ),
                        None,
                    )
                    operator = "contains"
                evidence_id = str(row.get("evidence_id") or "").strip()
                if not evidence_id or not isinstance(value, (str, int, float, bool)):
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                try:
                    value_key = json.dumps(value, ensure_ascii=False, allow_nan=False)
                except TypeError, ValueError:
                    continue
                example = typed_observation_examples.setdefault(
                    (family, field, operator, value_key),
                    {"value": value, "evidence_ids": set()},
                )
                example["evidence_ids"].add(evidence_id)
    if observed_candidate is None and db is not None:
        available_tables = load_live_schema(db)
        for family, definition in typed_catalog.items():
            table = canonical_record_table(family)
            if family == "evtx" or table not in available_tables:
                continue
            if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is None:
                continue
            typed_observations[family] = {
                "capabilities": definition["capabilities"],
                "fields": sorted(
                    set(definition["fields"]) - set(definition["boolean_fields"])
                ),
                "boolean_fields": definition["boolean_fields"],
            }
    typed_observation_entries = []
    for family, definition in sorted(typed_observations.items()):
        operators = ["equals", "contains", "greater_than"]
        if question_candidate:
            operators = set()
            requirements = [
                item
                for item in (observed_candidate.get("request_contract") or {}).get(
                    "requirements", []
                )
                if isinstance(item, dict)
                and str(item.get("family") or "").strip().lower() == family
            ]
            for field in (*definition["fields"], *definition["boolean_fields"]):
                field_requirements = [
                    item for item in requirements if item.get("field") == field
                ]
                if any(
                    item.get("kind") == "observed_value" for item in field_requirements
                ):
                    operators.update(
                        "contains" if isinstance(value, list) else "equals"
                        for row in (observed_candidate.get("evidence") or [])
                        if isinstance(row, dict)
                        and routed_family(str(row.get("evidence_id") or "")) == family
                        and row.get("_source") == canonical_record_table(family)
                        and _has_observed_value(row.get(field))
                        and (value := normalize_value(row.get(field))) is not None
                    )
                operators.update(
                    str(item["operator"])
                    for item in field_requirements
                    if item.get("kind") == "predicate" and item.get("operator")
                )
            operators = sorted(operators)
        typed_observation_entries.append(
            {
                "family": family,
                **definition,
                "operators": operators,
                **(
                    {"boolean_operators": ["equals"]}
                    if definition["boolean_fields"]
                    else {}
                ),
            }
        )
    typed_condition_examples = []
    for count in (1, 2):
        for (
            family,
            field,
            operator,
            _value_key,
        ), example in typed_observation_examples.items():
            if len(example["evidence_ids"]) < count:
                continue
            condition = {
                "observation": {
                    "family": family,
                    "capability": typed_observations[family]["capabilities"][0],
                    "field": field,
                    "operator": operator,
                    "value": example["value"],
                },
                **({"min_count": count} if count > 1 else {}),
            }
            typed_condition_examples.append(condition)
            break
    from forensia.db.schema import declared_schema

    canonical_table = (
        canonical_record_table(candidate_family) if candidate_family else None
    )
    canonical_columns = (
        set(declared_schema().get(canonical_table, ())) if canonical_table else set()
    )
    allowed_entities = (
        sorted(
            canonical_columns
            & (set(SNAKE_CASE_COLUMNS) - {"evidence_id"})
            & {
                str(key)
                for row in (observed_candidate or {}).get("evidence", [])
                if isinstance(row, dict)
                for key, value in row.items()
                if value not in (None, "", [])
            }
        )
        if canonical_table
        else None
    )
    if allowed_entities is None and db is not None:
        live_schema = load_live_schema(db)
        allowed_entities = sorted(
            (set(SNAKE_CASE_COLUMNS) - {"evidence_id"})
            & {
                column
                for family in typed_catalog
                for column in live_schema.get(canonical_record_table(family), ())
            }
        )
    schema = hypothesis_drafter_schema(
        observation_only=observation_only,
        allowed_entities=allowed_entities,
    )
    confirm_properties = schema["properties"]["hypothesis"]["properties"][
        "confirm_when"
    ]["properties"]
    if db is not None:
        live_schema = load_live_schema(db)
        counts = [
            int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for family in typed_catalog
            if (table := canonical_record_table(family)) in live_schema
        ]
        target_ids = {
            row.get("evidence_id")
            for row in (observed_candidate or {}).get("evidence", [])
            if isinstance(row, dict) and row.get("evidence_id")
        }
        maximum = (
            len(target_ids)
            if observation_only and target_ids
            else max(counts, default=1)
        )
        confirm_properties["min_count"]["maximum"] = max(1, maximum)
    observation_variants = []
    base_observation_schema = confirm_properties["observation"]
    for family, definition in sorted(typed_observations.items()):
        if question_candidate:
            requirements = [
                item
                for item in (observed_candidate.get("request_contract") or {}).get(
                    "requirements", []
                )
                if isinstance(item, dict)
                and str(item.get("family") or "").strip().lower() == family
            ]
            boolean_fields = set(definition["boolean_fields"])
            for field in (*definition["fields"], *definition["boolean_fields"]):
                field_requirements = [
                    item for item in requirements if item.get("field") == field
                ]
                operators = {
                    str(item["operator"])
                    for item in field_requirements
                    if item.get("kind") == "predicate" and item.get("operator")
                }
                if any(
                    item.get("kind") == "observed_value" for item in field_requirements
                ):
                    operators.update(
                        "contains" if isinstance(value, list) else "equals"
                        for row in (observed_candidate.get("evidence") or [])
                        if isinstance(row, dict)
                        and routed_family(str(row.get("evidence_id") or "")) == family
                        and row.get("_source") == canonical_record_table(family)
                        and _has_observed_value(row.get(field))
                        and (value := normalize_value(row.get(field))) is not None
                    )
                for operator in sorted(operators):
                    variant = copy.deepcopy(base_observation_schema)
                    variant["properties"]["family"]["enum"] = [family]
                    variant["properties"]["capability"]["enum"] = definition[
                        "capabilities"
                    ]
                    variant["properties"]["field"]["enum"] = [field]
                    variant["properties"]["operator"]["enum"] = [operator]
                    variant["properties"]["value"] = (
                        {"type": "boolean"}
                        if field in boolean_fields
                        else {
                            "anyOf": [
                                {"type": "string", "minLength": 1},
                                {"type": "number"},
                            ]
                        }
                    )
                    observation_variants.append(variant)
            continue
        if definition["fields"]:
            variant = copy.deepcopy(base_observation_schema)
            variant["properties"]["family"]["enum"] = [family]
            variant["properties"]["capability"]["enum"] = definition["capabilities"]
            variant["properties"]["field"]["enum"] = definition["fields"]
            variant["properties"]["value"] = {
                "anyOf": [
                    {"type": "string", "minLength": 1},
                    {"type": "number"},
                ]
            }
            observation_variants.append(variant)
        if definition["boolean_fields"]:
            variant = copy.deepcopy(base_observation_schema)
            variant["properties"]["family"]["enum"] = [family]
            variant["properties"]["capability"]["enum"] = definition["capabilities"]
            variant["properties"]["field"]["enum"] = definition["boolean_fields"]
            variant["properties"]["operator"]["enum"] = ["equals"]
            variant["properties"]["value"] = {"type": "boolean"}
            observation_variants.append(variant)
    if observation_variants:
        confirm_properties["observation"] = {"anyOf": observation_variants}
    else:
        confirm_properties.pop("observation", None)
        schema["properties"]["hypothesis"]["properties"]["confirm_when"]["required"] = [
            key
            for key in schema["properties"]["hypothesis"]["properties"][
                "confirm_when"
            ].get("required", [])
            if key != "observation"
        ]
    eligible_event_contexts: list[dict[str, Any]] = []
    observed_event_ids: set[int] = set()
    candidate_event_contexts: set[tuple[int, str, str]] = set()
    if observed_candidate:
        for row in observed_candidate.get("evidence") or []:
            if not isinstance(row, dict):
                continue
            raw_event_id = row.get("event_id")
            try:
                event_id = int(raw_event_id)
            except TypeError, ValueError:
                continue
            if isinstance(raw_event_id, bool):
                continue
            observed_event_ids.add(event_id)
            channel = str(row.get("channel") or "").strip()
            provider = str(row.get("provider") or "").strip()
            if channel and provider:
                candidate_event_contexts.add((event_id, channel, provider))
    if candidate_family == "evtx" and observed_event_ids and db is not None:
        eligible_event_contexts = [
            item
            for item in observed_event_contexts(db, observed_event_ids)
            if (item["event_id"], item["channel"], item["provider"])
            in candidate_event_contexts
        ]
    elif (
        not observed_candidate
        and case_profile is not None
        and case_profile.event_ids is not None
        and db is not None
    ):
        eligible_event_contexts = observed_event_contexts(db, case_profile.event_ids)
    allowed_event_ids = sorted({item["event_id"] for item in eligible_event_contexts})
    confirm_schema_properties = schema["properties"]["hypothesis"]["properties"][
        "confirm_when"
    ]["properties"]
    if "co_observed_event_ids" in confirm_schema_properties:
        ids_schema = confirm_schema_properties["co_observed_event_ids"]
        if observed_candidate or case_profile is not None:
            if allowed_event_ids:
                ids_schema["items"] = {"enum": allowed_event_ids}
            else:
                ids_schema["maxItems"] = 0
    event_contexts = sorted(
        eligible_event_contexts,
        key=lambda item: (
            item["event_id"] not in observed_event_ids,
            item["event_id"],
            item["channel"],
            item["provider"],
        ),
    )[:24]
    gap_words = [gap_area.get("keypoint_id", "")]
    matched_rule_ids = [
        str(rule.get("id") or rule.get("rule_id") or "")
        for rule in available_rules
        if isinstance(rule, dict) and (rule.get("id") or rule.get("rule_id"))
    ]
    observed_block = ""
    if observed_candidate:
        observations = []
        for row in (observed_candidate.get("evidence") or [])[:3]:
            if not isinstance(row, dict):
                continue
            family = routed_family(str(row.get("evidence_id") or ""))
            canonical_record = family is not None and row.get(
                "_source"
            ) == canonical_record_table(family)
            canonical_fields = typed_catalog.get(family or "", {}).get("fields", [])
            displayed_fields = {
                key: prompt_value_projection(row[key])
                for key in evidence_fields
                if row.get(key) is not None
                and (
                    not canonical_record
                    or key in canonical_fields
                    or key in {"evidence_id", "_source", "source_file"}
                )
            }
            raw = row.get("raw")
            winlog = raw.get("winlog") if isinstance(raw, dict) else None
            provider = winlog.get("provider") if isinstance(winlog, dict) else None
            provider_name = provider.get("name") if isinstance(provider, dict) else None
            if provider_name is not None:
                displayed_fields["provider"] = provider_name
            observations.append(displayed_fields)
        projection = {
            "candidate_ref": observed_candidate.get("candidate_ref"),
            "title": observed_candidate.get("title"),
            "summary": observed_candidate.get("summary"),
            "scope": observed_candidate.get("scope"),
            "match_count": observed_candidate.get("match_count"),
            "evidence_count": observed_candidate.get("evidence_count"),
            "evidence_ids": observed_candidate.get("evidence_ids", [])[:3],
            "request_contract": observed_candidate.get("request_contract"),
            "observations": observations,
        }
        observed_block = (
            "<OBSERVED_CANDIDATE>\n"
            + json.dumps(projection, ensure_ascii=False, default=str)
            + "\n</OBSERVED_CANDIDATE>\n"
        )
        for value in (
            observed_candidate.get("title"),
            observed_candidate.get("summary"),
        ):
            if isinstance(value, str) and value.strip():
                gap_words.append(value.strip()[:160])
        gap_words.extend(matched_rule_ids)
        for rule in available_rules:
            if not isinstance(rule, dict):
                continue
            title = rule.get("title")
            if isinstance(title, str) and title.strip():
                gap_words.append(title.strip()[:120])
            tags = rule.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            if isinstance(tags, list):
                gap_words.extend(
                    tag.strip()[:80]
                    for tag in tags[:10]
                    if isinstance(tag, str) and tag.strip()
                )
    typed_observations_block = (
        "<AVAILABLE_TYPED_OBSERVATIONS>\n"
        + json.dumps(typed_observation_entries, ensure_ascii=False)
        + "\nUse only the listed family, capability, and field combinations. Choose values "
        + (
            "from that field in OBSERVED_CANDIDATE. "
            if observed_candidate is not None
            else "from the supplied gap's explicit search criteria. These are proposed search conditions, not observed facts; do not invent unknown values or evidence IDs. A narrow observation does not answer the entire question. "
        )
        + "`contains` requires a string value; "
        "For array fields, use a string element with `contains`, not the serialized JSON array or its sample wrapper. "
        "`greater_than` requires a number or ISO datetime. Boolean fields require a "
        "JSON boolean and support only `equals`.\n"
        + (
            "Valid condition examples (from the listed evidence):\n"
            + json.dumps(typed_condition_examples, ensure_ascii=False)
            + "\n"
            if typed_condition_examples
            else ""
        )
        + (
            'For a typed search, default min_count to 1 and use this exact description format: At least 1 <family> observation has <field> <operator> <JSON value>. Render greater_than as "greater than".\n'
            if observed_candidate is None
            else ""
        )
        + "</AVAILABLE_TYPED_OBSERVATIONS>\n"
        if typed_observation_entries
        else ""
    )
    observation_schema_hint = (
        '"observation": {"family": "listed family", "capability": "listed capability", '
        '"field": "listed field", "operator": "equals|contains|greater_than", '
        '"value": str|number|bool}, '
        if typed_observation_entries
        else ""
    )
    if observation_only:
        confirm_when_schema_hint = (
            '    "confirm_when": {'
            + observation_schema_hint.removesuffix(", ")
            + ', "min_count": optional positive int},\n'
        )
    else:
        confirm_when_schema_hint = (
            '    "confirm_when": {'
            + observation_schema_hint
            + '"min_count": optional positive int, "co_observed_event_ids": [listed IDs], '
            + '"event_contexts": [{"event_id": int, "channel": str, "provider": str}], '
            + '"same_host": bool, "within_minutes": int, '
            + '"same_entities": [listed evidence columns]},\n'
        )
    family_scope_block = ""
    if candidate_family and canonical_table and db is not None:
        family_id_column = (
            "artifact_id" if candidate_family == "registry" else "evidence_id"
        )
        family_population = int(
            db.execute(
                f"SELECT COUNT(DISTINCT {family_id_column}) FROM {canonical_table}"
            ).fetchone()[0]
            or 0
        )
        family_scope_block = (
            "<OBSERVATION_SCOPE>\n"
            f"family={candidate_family}; canonical_table={canonical_table}; "
            f"canonical_columns={json.dumps(allowed_entities or [], ensure_ascii=False)}; "
            f"distinct_evidence_ids_in_case={family_population}; "
            f"candidate_distinct_evidence_ids={int((observed_candidate or {}).get('evidence_count') or 0)}.\n"
            "The candidate sample is not the family population. min_count means distinct matching canonical evidence IDs; "
            "it is not an execution count such as Prefetch exec_count.\n"
            "</OBSERVATION_SCOPE>\n"
        )
    system = (
        (f"{case_policy_block(case_policy)}" if case_policy is not None else "")
        + "<TASK>You are a hypothesis_drafter. Draft ONE falsifiable, SQL-testable hypothesis from the supplied observation or existing gap.</TASK>\n"
        f"{_case_profile_guidance(case_profile.summary if case_profile else None)}"
        f"{_org_knowledge_block(extra_words=gap_words, db=db, session_id=session_id, phase='plan_broad_draft')}"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "hypothesis": {\n'
        + (
            ""
            if observation_only
            else '    "description": "str (one investigative claim tested by these conditions)",\n'
        )
        + '    "required_entities": '
        + json.dumps((allowed_entities or [])[:12], ensure_ascii=False)
        + ",\n"
        '    "source_rule_ids": ["an id from the host-supplied matched_rule_ids, or empty list"],\n'
        + confirm_when_schema_hint
        + '    "refute_when": {"zero_rows": true}\n'
        "  }\n"
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        + (
            "<AVAILABLE_EVENT_CONTEXTS>\n"
            + json.dumps(event_contexts, ensure_ascii=False)
            + "\nUse only listed event_id/channel/provider combinations. If none are listed, "
            "do not use event IDs; use available non-EVTX evidence instead.\n"
            "</AVAILABLE_EVENT_CONTEXTS>\n"
            if (
                not observation_only
                and case_profile is not None
                and case_profile.event_ids is not None
            )
            else ""
        )
        + family_scope_block
        + typed_observations_block
        + "<RULES>\n"
        "Treat supplied observations as leads, not proof. For an observed candidate, test that candidate using only fields/ref IDs shown there. Do not infer facts from match counts, severity, titles, or rule names.\n"
        "Use source_rule_ids only from the host-supplied matched_rule_ids. They identify observed matches and are not evidence support.\n"
        "For a gap without an observed candidate, stay within its stated objective, gap, keypoint, and available evidence. Do not invent an event, entity, or source.\n"
        "For an explicit question candidate, the request_contract is authoritative: use a requested family/field and, for predicate requirements, the exact operator/value. Do not substitute a related field or weaken a predicate. For observed_value requirements, use equals with the exact scalar value from that field in the same canonical evidence row; for an array field, use contains with one exact array element from that field. Never use a range or substring search to stand in for an unknown value.\n"
        "required_entities must be valid snake_case evidence column names. Keep verification conditions explicit and use only event ID/context combinations supplied by the host.\n"
        "Typed observations use fields from canonical evidence records, not derived timeline projections such as prefetch_timeline.exec_time or mft_timeline.timestamp.\n"
        "Preserve the supplied subject. For an observed candidate, the host binds a typed observation to that candidate's canonical evidence IDs; matching a different record will not confirm it. Keep each timestamp paired with its named field. Consider what additional observation could distinguish an alternative explanation; do not turn uncertainty about intent into a claim of malicious intent.\n"
        + (
            "This candidate uses one canonical artifact family. Use only its listed columns and capability. confirm_when is observation-only in this mode; the schema rejects event/correlation mixes. Return conditions only, without description. The host renders the precise observation from the validated conditions. This observation does not resolve a broader causal question.\n"
            if observation_only
            else "If confirm_when uses observation, do not mix it with event or correlation conditions. Use only the listed family, capability, and fields. A typed observation description must state only the observation; broader interpretations are rejected at admission. Preserve the original question for review instead of claiming that a narrow observation resolves it. min_count defaults to 1 and counts distinct canonical evidence IDs.\n"
        )
        + "confirm_when and refute_when must be JSON objects. Output JSON only.\n"
        "</RULES>\n"
    )
    # Only rules that actually matched this candidate may be disclosed.
    slim_rules: list[dict[str, Any]] = []
    for rule in available_rules:
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
                "hypotheses": slim_hypotheses,
            }
        )
    user = (
        f"gap_area: {json.dumps(gap_area, ensure_ascii=False, default=str)}\n"
        f"draft_feedback: {json.dumps(gap_area.get('draft_feedback') or {}, ensure_ascii=False, default=str)}\n"
        f"matched_rule_ids: {json.dumps(matched_rule_ids, ensure_ascii=False)}\n"
        f"{observed_block}"
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
