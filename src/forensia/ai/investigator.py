from __future__ import annotations

import hashlib
import json
import signal
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.checker import check_query_result, summarize_query_result
from forensia.ai.lmstudio import chat_completion
from forensia.ai.planner import BroadPlanResult, broad_plan_investigation, plan_hypothesis_query
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import HistoryEntry, Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.writer import (
    collect_gaps,
    fetch_report_sections,
    fill_section,
    finalize_section,
    load_report_sections_map,
    mark_report_sections_ai_exhausted,
    prepare_section_request,
    render_written_report,
    write_report_brief,
)
from forensia.rules.engine import generate_findings, run_rule, save_findings
from forensia.rules.loader import load_rules_from_dir

def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _save_step(
    db: CaseDB,
    session_id: str,
    iteration: int,
    phase: str,
    input_json: Any,
    output_json: Any,
    suffix: str | None = None,
) -> None:
    step_id = f"{session_id}-{iteration:02d}-{phase}"
    if suffix:
        step_id = f"{step_id}-{suffix}"
    db.execute(
        """
        INSERT INTO investigation_steps (
            step_id, session_id, iteration, phase, input_json, output_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            step_id,
            session_id,
            iteration,
            phase,
            _to_json(input_json),
            _to_json(output_json),
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )


def _reasoning_entry_id(
    hypothesis_id: str,
    iteration: int,
    phase: str,
    query_id: str | None,
) -> str:
    body = f"{hypothesis_id}-{iteration}-{phase}-{query_id or '-'}"
    return hashlib.sha1(body.encode("utf-8")).hexdigest()[:16]


def _append_hypothesis_reasoning(
    db: CaseDB,
    hypothesis_id: str,
    session_id: str,
    iteration: int,
    phase: str,
    body: str,
    verdict: str | None = None,
    query_id: str | None = None,
) -> str | None:
    text = str(body).strip()
    if not hypothesis_id or not text:
        return None
    entry_id = _reasoning_entry_id(hypothesis_id, iteration, phase, query_id)
    db.execute(
        """
        INSERT INTO hypothesis_reasoning (
            entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (entry_id) DO NOTHING
        """,
        (
            entry_id,
            hypothesis_id,
            session_id,
            iteration,
            phase,
            verdict,
            query_id,
            text,
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )
    return entry_id


def _seed_findings(case: Case, db: CaseDB, profile: str) -> int:
    existing = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    if existing:
        return int(existing)

    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    rules_dir = Path(__file__).parent.parent / "rulepacks"
    rules = load_rules_from_dir(rules_dir, profile_path)
    total = 0
    for rule in rules:
        findings = generate_findings(rule, run_rule(db, rule))
        save_findings(case, db, findings)
        total += len(findings)
    return total


def _initialize_overview(memory: MemoryManager, case: Case) -> None:
    if memory.has_overview():
        return
    output_language = str(get_llm_settings()["output_language"]).lower()
    open_question_seed = {
        "ja": "初回調査待ち",
        "en": "Awaiting initial investigation",
    }.get(output_language, "Awaiting initial investigation")
    memory.update_overview(
        (
            f"# Investigation Overview\n\n"
            f"Case: {case.path.name}\n\n"
            "## Confirmed Hosts\n- none\n\n"
            "## Confirmed Timeline\n- none\n\n"
            "## Active Hypotheses\n- none\n\n"
            f"## Open Questions\n- {open_question_seed}\n"
        )
    )


def _recent_reasoning_rows(db: CaseDB, hypothesis_id: str, limit: int = 10) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT phase, verdict, query_id, body, created_at
        FROM hypothesis_reasoning
        WHERE hypothesis_id = ?
        ORDER BY created_at DESC, entry_id DESC
        LIMIT ?
        """,
        (hypothesis_id, limit),
    )


def _render_hypothesis_memory(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    lines = [
        f"# Hypothesis {hypothesis.id}",
        "",
        "## Status",
        f"- {hypothesis.status}",
        "",
        "## Verdict",
        f"- {hypothesis.verdict or 'pending'}",
        "",
        "## Description",
        hypothesis.description,
        "",
        "## Summary",
        hypothesis.summary or "-",
    ]
    if db is not None:
        reasoning_rows = _recent_reasoning_rows(db, hypothesis.id)
        if reasoning_rows:
            lines.extend(["", "## Reasoning"])
            for row in reasoning_rows:
                phase = str(row.get("phase") or "")
                verdict = str(row.get("verdict") or "-")
                query_id = str(row.get("query_id") or "-")
                body = " ".join(str(row.get("body") or "").split())[:240]
                lines.append(f"- [{phase}] verdict={verdict} query={query_id} :: {body}")
    return "\n".join(lines) + "\n"


def _finding_snapshot(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT finding_id, title, summary, severity, confidence, status
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )


def _matching_findings(snapshot: list[dict[str, Any]], hypothesis: Hypothesis | None) -> list[dict[str, Any]]:
    if hypothesis is None:
        return snapshot[:5]
    words = {token.lower() for token in hypothesis.description.split() if len(token) >= 3}
    if not words:
        return snapshot[:5]
    matched = []
    for finding in snapshot:
        haystack = " ".join(
            str(finding.get(key, "") or "")
            for key in ("title", "summary", "severity", "status")
        ).lower()
        if any(word in haystack for word in words):
            matched.append(finding)
    return matched[:5] if matched else snapshot[:5]


def _row_to_hypothesis(row: dict[str, Any]) -> Hypothesis:
    verdict = row.get("verdict")
    return Hypothesis(
        id=str(row.get("hypothesis_id") or ""),
        description=str(row.get("description") or ""),
        status=str(row.get("status") or "active"),
        verdict=str(verdict) if verdict else None,
        summary=str(row.get("summary") or ""),
    )


def _load_persisted_hypotheses(db: CaseDB) -> tuple[list[Hypothesis], list[Hypothesis]]:
    rows = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary
        FROM hypotheses
        ORDER BY created_at, hypothesis_id
        """,
    )
    active: list[Hypothesis] = []
    resolved: list[Hypothesis] = []
    for row in rows:
        hypothesis = _row_to_hypothesis(row)
        if hypothesis.status == "active":
            active.append(hypothesis)
        else:
            resolved.append(hypothesis)
    return active, resolved


def _upsert_hypothesis(
    db: CaseDB,
    hypothesis: Hypothesis,
    origin: str,
    session_id: str,
    resolved_session: str | None = None,
) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        """
        SELECT origin, created_session, created_at, resolved_session
        FROM hypotheses
        WHERE hypothesis_id = ?
        """,
        (hypothesis.id,),
    ).fetchone()
    created_origin = origin
    created_session = session_id
    created_at = now
    prior_resolved_session = resolved_session
    if existing is not None:
        created_origin = str(existing[0] or origin)
        created_session = str(existing[1] or session_id)
        created_at = existing[2] or now
        if prior_resolved_session is None:
            prior_resolved_session = existing[3]

    db.execute(
        """
        INSERT INTO hypotheses (
            hypothesis_id, description, status, verdict, summary, origin,
            created_session, resolved_session, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (hypothesis_id) DO UPDATE SET
            description = excluded.description,
            status = excluded.status,
            verdict = excluded.verdict,
            summary = excluded.summary,
            origin = excluded.origin,
            created_session = excluded.created_session,
            resolved_session = excluded.resolved_session,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at
        """,
        (
            hypothesis.id,
            hypothesis.description,
            hypothesis.status,
            hypothesis.verdict,
            hypothesis.summary,
            created_origin,
            created_session,
            prior_resolved_session,
            created_at,
            now,
        ),
    )


def _merge_active_hypotheses(
    db: CaseDB,
    current: list[Hypothesis],
    updates: list[Hypothesis],
    resolved: list[Hypothesis],
    session_id: str,
    origin: str,
) -> list[Hypothesis]:
    resolved_ids = {item.id for item in resolved}
    by_id = {item.id: item for item in current if item.id not in resolved_ids}
    for item in updates:
        if item.id in resolved_ids or item.status in {"confirmed", "refuted"}:
            continue
        hypothesis = Hypothesis(
            id=item.id,
            description=item.description,
            status="active",
            verdict=None,
            summary=item.summary,
        )
        by_id[item.id] = hypothesis
        _upsert_hypothesis(db, hypothesis, origin=origin, session_id=session_id)
    return list(by_id.values())


def _resolve_hypothesis(
    db: CaseDB,
    state: SessionState,
    hypothesis_id: str,
    verdict: str,
    summary: str,
    session_id: str,
) -> None:
    remaining: list[Hypothesis] = []
    for item in state.active_hypotheses:
        if item.id == hypothesis_id:
            resolved = Hypothesis(
                id=item.id,
                description=item.description,
                status="confirmed" if verdict == "confirmed" else "refuted",
                verdict=verdict,
                summary=summary,
            )
            state.resolved_hypotheses.append(resolved)
            _upsert_hypothesis(
                db=db,
                hypothesis=resolved,
                origin="check_new",
                session_id=session_id,
                resolved_session=session_id,
            )
        else:
            remaining.append(item)
    state.active_hypotheses = remaining


def _history_entry(
    iteration: int,
    query_id: str,
    hypothesis_id: str | None,
    verdict: str,
    report_text: str,
    evidence_ids: list[str],
) -> HistoryEntry:
    return HistoryEntry(
        iteration=iteration,
        query_id=query_id,
        hypothesis_id=hypothesis_id,
        verdict=verdict,
        summary=report_text,
        evidence_ids=evidence_ids,
    )


def _final_summary(state: SessionState) -> str:
    if state.resolved_hypotheses:
        lines = []
        for item in state.resolved_hypotheses[-5:]:
            verdict = item.verdict or item.status
            lines.append(f"[{verdict}] {item.description}: {item.summary or 'summary unavailable'}")
        return "\n".join(lines)
    if state.history:
        return "\n".join(entry.summary for entry in state.history[-5:] if entry.summary)
    return "調査中に追加の進展はありませんでした。"


def _apply_memory_updates(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
    check_output: dict[str, Any],
    db: CaseDB | None = None,
) -> None:
    updates = check_output.get("memory_updates") or {}
    overview_append = str(updates.get("overview_append") or "").strip()
    if overview_append:
        memory.append_overview(overview_append)

    for item in updates.get("confirmed_facts") or []:
        if not isinstance(item, dict):
            continue
        memory.append_confirmed_fact(
            str(item.get("text") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )

    for item in updates.get("timeline_anchors") or []:
        if not isinstance(item, dict):
            continue
        memory.append_timeline_anchor(
            str(item.get("timestamp") or ""),
            str(item.get("description") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )

    for item in updates.get("open_questions") or []:
        if not isinstance(item, dict):
            continue
        memory.append_open_question(
            str(item.get("question") or ""),
            str(item.get("kind") or ""),
        )

    for item in updates.get("narrative") or []:
        memory.append_narrative(str(item))

    for item in updates.get("refuted_hypotheses") or []:
        if not isinstance(item, dict):
            continue
        memory.append_refuted_hypothesis(
            str(item.get("hypothesis_id") or ""),
            str(item.get("description") or ""),
            str(item.get("reason") or ""),
        )

    for item in updates.get("important_entities") or []:
        if not isinstance(item, dict):
            continue
        memory.append_important_entity(
            str(item.get("entity_type") or ""),
            str(item.get("name") or ""),
            str(item.get("notes") or ""),
        )

    for hostname, content in (updates.get("hosts") or {}).items():
        memory.upsert_host(str(hostname), str(content))

    for username, content in (updates.get("users") or {}).items():
        memory.upsert_user(str(username), str(content))

    for key, content in (updates.get("hypotheses") or {}).items():
        key_text = str(key)
        slug = key_text.split("-", 1)[-1] if "-" in key_text else key_text
        memory.upsert_hypothesis(key_text, slug, str(content))

    memory.append_suspicious(check_output.get("suspicious_evidence") or [])

    for hypothesis in [*active_hypotheses, *resolved_hypotheses]:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(db, hypothesis)
        memory.upsert_hypothesis(hypothesis.id, slug, content)


def _all_hypotheses(state: SessionState) -> list[Hypothesis]:
    return [*state.active_hypotheses, *state.resolved_hypotheses]


def _normalize_text(value: str) -> str:
    return " ".join(value.lower().split())


def _guess_related_sections(text: str) -> list[str]:
    lowered = text.lower()
    section_map = {
        "1_overview": ["overview", "first evidence", "summary", "fec", "initial"],
        "2_timeline": ["timeline", "time", "log clear", "reboot", "shutdown", "when"],
        "3_hosts": ["host", "computer", "server", "workstation"],
        "4_accounts": ["account", "user", "credential", "password", "logon", "rdp", "admin"],
        "5_persistence": ["service", "task", "powershell", "defender", "persistence", "execution"],
        "6_ioc": ["ioc", "ip", "process", "file", "path", "indicator"],
        "7_gaps": ["gap", "unknown", "不足", "unresolved"],
        "8_recommendations": ["mitigation", "recommendation", "対策"],
    }
    matches = [section for section, keywords in section_map.items() if any(keyword in lowered for keyword in keywords)]
    return matches or ["7_gaps"]


def _build_report_status(db: CaseDB, current_section: str | None = None, focus_sections: list[str] | None = None) -> dict[str, Any]:
    sections = fetch_report_sections(db)
    items = []
    for row in sections:
        gaps = row.get("gaps") or []
        if isinstance(gaps, str):
            try:
                gaps = json.loads(gaps)
            except json.JSONDecodeError:
                gaps = []
        items.append(
            {
                "section_key": row.get("section_key"),
                "title": row.get("title"),
                "confidence": float(row.get("confidence") or 0.0),
                "status": str(row.get("status") or "draft"),
                "update_count": int(row.get("update_count") or 0),
                "gap_count": len(gaps) if isinstance(gaps, list) else 0,
                "gaps": gaps if isinstance(gaps, list) else [],
                "gap_hypothesis_ids": [_gap_hypothesis_id(str(gap)) for gap in gaps] if isinstance(gaps, list) else [],
                "body": str(row.get("body") or ""),
                "is_writing": str(row.get("section_key") or "") == str(current_section or ""),
                "is_highlighted": str(row.get("section_key") or "") in set(focus_sections or []),
            }
        )
    total_gaps = sum(int(item["gap_count"]) for item in items)
    total_body_chars = sum(len(str(item["body"])) for item in items)
    return {
        "current_section": current_section,
        "focus_sections": focus_sections or [],
        "items": items,
        "total_gaps": total_gaps,
        "total_body_chars": total_body_chars,
    }


def _overlay_report_status(
    base_status: dict[str, Any],
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
    focus = set(focus_sections or [])
    items = []
    for row in base_status.get("items", []):
        item = dict(row)
        item["is_writing"] = str(item.get("section_key") or "") == str(current_section or "")
        item["is_highlighted"] = str(item.get("section_key") or "") in focus
        items.append(item)
    return {
        **base_status,
        "current_section": current_section,
        "focus_sections": list(focus_sections or []),
        "items": items,
    }


def _report_cycle_progress(previous: dict[str, int], current: dict[str, int]) -> bool:
    return (
        current.get("total_gaps", 0) < previous.get("total_gaps", 0)
        or current.get("total_body_chars", 0) > previous.get("total_body_chars", 0)
    )


def _gap_hypothesis_id(description: str) -> str:
    digest = hashlib.sha1(description.encode("utf-8")).hexdigest()[:10]
    return f"gap-{digest}"


def _classify_gap_kind(description: str) -> str:
    lowered = description.lower()
    if any(token in lowered for token in ("whois", "osint", "外部", "所有組織", "threat intel", "reputation")):
        return "external_lookup"
    if any(token in lowered for token in ("ヒアリング", "担当者", "利用者", "承認", "human", "業務", "user confirmation")):
        return "human_decision"
    return "internal_db_check"


def _inject_gap_hypotheses(
    db: CaseDB,
    state: SessionState,
    gaps: list[str],
    session_id: str,
    memory: MemoryManager | None = None,
) -> int:
    known_by_description = {_normalize_text(item.description) for item in _all_hypotheses(state)}
    resolved_by_description = {_normalize_text(item.description) for item in state.resolved_hypotheses}
    added = 0
    for gap in gaps:
        normalized_gap = _normalize_text(gap)
        if not normalized_gap or normalized_gap in known_by_description or normalized_gap in resolved_by_description:
            continue
        gap_kind = _classify_gap_kind(gap)
        if gap_kind != "internal_db_check":
            if memory is not None:
                memory.append_open_question(gap, gap_kind)
            known_by_description.add(normalized_gap)
            continue
        hypothesis = Hypothesis(
            id=_gap_hypothesis_id(gap),
            description=gap,
            status="active",
            verdict=None,
            summary="",
        )
        state.active_hypotheses.append(hypothesis)
        _upsert_hypothesis(db, hypothesis, origin="report_gap", session_id=session_id)
        known_by_description.add(normalized_gap)
        added += 1
    return added


def _refresh_report_sections(
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    template_root: Path,
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    focus_sections: list[str] | None = None,
    max_workers: int = 1,
) -> dict[str, Any]:
    """Re-fill report sections for this cycle.

    When ``max_workers > 1``, dispatches LLM calls in a ThreadPoolExecutor.
    Workers only perform the HTTP call against LM Studio; DuckDB reads
    (evidence query summarisation) happen serially upfront and writes happen
    on the main thread after each future completes, so the single DuckDB
    connection is never touched concurrently.
    """
    template_paths = sorted(template_root.glob("[0-9]*_*.md"))
    if max_workers <= 1:
        return _refresh_report_sections_sequential(
            case=case,
            db=db,
            session_id=session_id,
            iteration=iteration,
            base_url=base_url,
            model=model,
            template_paths=template_paths,
            llm_logger=llm_logger,
            progress_callback=progress_callback,
            focus_sections=focus_sections,
        )
    return _refresh_report_sections_parallel(
        case=case,
        db=db,
        session_id=session_id,
        iteration=iteration,
        base_url=base_url,
        model=model,
        template_paths=template_paths,
        llm_logger=llm_logger,
        progress_callback=progress_callback,
        focus_sections=focus_sections,
        max_workers=max_workers,
    )


def _refresh_report_sections_sequential(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    template_paths: list[Path],
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str] | None,
) -> dict[str, Any]:
    filled_sections: dict[str, str] = {}
    updated = 0
    report_brief = write_report_brief(case, db)
    for template_path in template_paths:
        section_key = template_path.stem
        if progress_callback:
            progress_callback(
                {
                    "stage": "investigate/report-section",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} writing...",
                    "current_report_section": section_key,
                    "report_sections": _build_report_status(
                        db,
                        current_section=section_key,
                        focus_sections=focus_sections,
                    ),
                }
            )
        context_sections = dict(filled_sections)
        filled_sections[section_key] = fill_section(
            case=case,
            db=db,
            template_path=template_path,
            context_sections=context_sections,
            report_brief=report_brief,
            base_url=base_url,
            model=model,
            session_id=session_id,
            audit_callback=lambda messages, body, section=section_key: llm_logger.write(
                iteration=iteration,
                phase="report-section",
                input_messages=messages,
                output=body,
                model=model,
                base_url=base_url,
                suffix=section,
            ),
        )
        status = _build_report_status(db, focus_sections=focus_sections)
        updated += 1
        current_row = next((item for item in status["items"] if item["section_key"] == section_key), None)
        gap_count = int(current_row["gap_count"]) if current_row else 0
        confidence = float(current_row["confidence"]) if current_row else 0.0
        if progress_callback:
            progress_callback(
                {
                    "stage": "investigate/report-section-done",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} done (gaps={gap_count}, confidence={confidence:.2f})",
                    "report_sections": status,
                }
            )
    all_gaps = collect_gaps(filled_sections)
    report_status = _build_report_status(db, focus_sections=focus_sections)
    if progress_callback:
        progress_callback(
            {
                "stage": "investigate/report-cycle-done",
                "status": "running",
                "iteration": iteration,
                "summary": f"[report] cycle done (sections={updated}, gaps={len(all_gaps)})",
                "report_sections": report_status,
            }
        )
    return {
        "filled_sections": filled_sections,
        "gaps": all_gaps,
        "report_status": report_status,
        "updated_sections": updated,
    }


def _refresh_report_sections_parallel(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    template_paths: list[Path],
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str] | None,
    max_workers: int,
) -> dict[str, Any]:
    # Sections are independent within a cycle when parallel: each one sees
    # the previous-cycle bodies as context (loaded once, serially, here).
    prior_filled = load_report_sections_map(db)
    report_brief = write_report_brief(case, db)
    requests: list[dict[str, Any]] = []
    for template_path in template_paths:
        request = prepare_section_request(db, template_path, prior_filled, report_brief=report_brief)
        request["template_path"] = str(template_path)
        requests.append(request)

    progress_lock = threading.Lock()

    def emit(payload: dict[str, Any]) -> None:
        if not progress_callback:
            return
        with progress_lock:
            progress_callback(payload)

    def worker(request: dict[str, Any]) -> tuple[dict[str, Any], str]:
        emit(
            {
                "stage": "investigate/report-section",
                "status": "running",
                "iteration": iteration,
                "summary": f"[report] {request['section_key']} writing... (parallel)",
                "current_report_section": request["section_key"],
            }
        )
        body = chat_completion(
            messages=request["messages"],
            model=model,
            base_url=base_url,
        ).strip()
        llm_logger.write(
            iteration=iteration,
            phase="report-section",
            input_messages=request["messages"],
            output=body,
            model=model,
            base_url=base_url,
            suffix=str(request["section_key"]),
        )
        return request, body

    filled_sections: dict[str, str] = {}
    updated = 0
    workers = max(1, min(max_workers, len(requests)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, request) for request in requests]
        for future in as_completed(futures):
            try:
                request, body = future.result()
            except Exception as exc:  # pragma: no cover - propagated as inline message
                emit(
                    {
                        "stage": "investigate/report-section-done",
                        "status": "running",
                        "iteration": iteration,
                        "summary": f"[report] section failed: {exc}",
                    }
                )
                continue
            section_key = request["section_key"]
            finalize_section(
                db=db,
                section_key=section_key,
                title=request["title"],
                body=body,
                evidence_results=request.get("evidence_results") or [],
                session_id=session_id,
            )
            filled_sections[section_key] = body
            updated += 1
            status = _build_report_status(db, focus_sections=focus_sections)
            current_row = next((item for item in status["items"] if item["section_key"] == section_key), None)
            gap_count = int(current_row["gap_count"]) if current_row else 0
            confidence = float(current_row["confidence"]) if current_row else 0.0
            emit(
                {
                    "stage": "investigate/report-section-done",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} done (gaps={gap_count}, confidence={confidence:.2f})",
                    "report_sections": status,
                }
            )

    all_gaps = collect_gaps(filled_sections)
    report_status = _build_report_status(db, focus_sections=focus_sections)
    if progress_callback:
        progress_callback(
            {
                "stage": "investigate/report-cycle-done",
                "status": "running",
                "iteration": iteration,
                "summary": (
                    f"[report] cycle done (sections={updated}, gaps={len(all_gaps)}, "
                    f"parallel={workers})"
                ),
                "report_sections": report_status,
            }
        )
    return {
        "filled_sections": filled_sections,
        "gaps": all_gaps,
        "report_status": report_status,
        "updated_sections": updated,
    }


def investigate(
    case: Case,
    db: CaseDB,
    base_url: str,
    model: str,
    max_iter: int = 20,
    no_progress_limit: int = 3,
    profile: str = "windows-basic",
    max_queries_per_hypothesis: int = 5,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    report_every_n_cycles: int = 1,
    report_only: bool = False,
    template_root: Path | None = None,
    report_parallelism: int = 1,
) -> dict[str, Any]:
    session_id = f"session-{uuid4().hex[:12]}"
    started_at = datetime.now(UTC).replace(tzinfo=None)
    status = "running"
    interrupted = False
    no_progress_count = 0
    memory = MemoryManager(case)
    template_root = template_root or (
        case.report_template_dir if case.report_template_dir.exists() else (Path(__file__).parent.parent / "report_template")
    )

    _seed_findings(case, db, profile)
    _initialize_overview(memory, case)
    llm_logger = LLMCallLogger(case, session_id)
    active_hypotheses, resolved_hypotheses = _load_persisted_hypotheses(db)
    state = SessionState(
        session_id=session_id,
        iteration=0,
        findings_snapshot=_finding_snapshot(db),
        active_hypotheses=active_hypotheses,
        resolved_hypotheses=resolved_hypotheses,
    )
    report_status_cache = _build_report_status(db)

    def get_report_status(
        *,
        current_section: str | None = None,
        focus_sections: list[str] | None = None,
        refresh: bool = False,
    ) -> dict[str, Any]:
        nonlocal report_status_cache
        if refresh:
            report_status_cache = _build_report_status(db)
        return _overlay_report_status(
            report_status_cache,
            current_section=current_section,
            focus_sections=focus_sections,
        )

    memory_overview_cache = memory.load_overview()
    memory_plan_context_cache = memory.load_compact_context(
        ["confirmed_facts.md", "open_questions.md"],
        max_bytes=max(1024, memory.max_bytes // 3),
    )
    memory_check_context_cache = memory.load_compact_context(
        ["confirmed_facts.md", "timeline_anchors.md", "open_questions.md"],
        max_bytes=max(1024, memory.max_bytes // 2),
    )

    def refresh_memory_caches() -> None:
        nonlocal memory_overview_cache, memory_plan_context_cache, memory_check_context_cache
        memory_overview_cache = memory.load_overview()
        memory_plan_context_cache = memory.load_compact_context(
            ["confirmed_facts.md", "open_questions.md"],
            max_bytes=max(1024, memory.max_bytes // 3),
        )
        memory_check_context_cache = memory.load_compact_context(
            ["confirmed_facts.md", "timeline_anchors.md", "open_questions.md"],
            max_bytes=max(1024, memory.max_bytes // 2),
        )
    db.execute(
        """
        INSERT INTO investigation_sessions (
            session_id, started_at, finished_at, iterations, status
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (session_id, started_at, None, 0, status),
    )

    previous_sigint = signal.getsignal(signal.SIGINT)

    def llm_status(message: str) -> None:
        print(f"[yellow]{message}[/yellow]")
        if progress_callback:
            progress_callback(
                {
                    "stage": "investigate/llm",
                    "status": "running",
                    "iteration": state.iteration,
                    "summary": message,
                    "focus_hypothesis_id": state.focus_hypothesis_id,
                    "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                    "report_sections": get_report_status(),
                }
            )

    def _handle_sigint(signum, frame) -> None:
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGINT, _handle_sigint)
    try:
        for plan_cycle in range(1, max_iter + 1):
            state.iteration = plan_cycle
            state.findings_snapshot = _finding_snapshot(db)
            if progress_callback:
                progress_callback(
                    {
                        "stage": "investigate",
                        "status": "running",
                        "iteration": plan_cycle,
                        "summary": f"Hypothesis cycle {plan_cycle}/{max_iter}",
                        "focus_hypothesis_id": state.focus_hypothesis_id,
                        "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                        "report_sections": get_report_status(),
                    }
                )
            if interrupted:
                status = "stopped"
                break

            broad_plan_hypotheses = 0
            broad_plan_stop = False
            cycle_progress = False
            focus_sections: list[str] = []
            report_before = get_report_status()

            if not report_only:
                plan_input = state.model_dump()
                broad_plan: BroadPlanResult = broad_plan_investigation(
                    state=state,
                    memory=memory,
                    base_url=base_url,
                    model=model,
                    overview_md=memory_overview_cache,
                    default_context_md=memory_plan_context_cache,
                    status_callback=llm_status,
                    audit_callback=lambda messages, output, parsed: llm_logger.write(
                        iteration=plan_cycle,
                        phase="plan-broad",
                        input_messages=messages,
                        output=parsed,
                        model=model,
                        base_url=base_url,
                    ),
                )
                state.active_hypotheses = _merge_active_hypotheses(
                    db=db,
                    current=state.active_hypotheses,
                    updates=broad_plan.hypotheses,
                    resolved=state.resolved_hypotheses,
                    session_id=session_id,
                    origin="broad_plan",
                )
                broad_plan_hypotheses = len(broad_plan.hypotheses)
                broad_plan_stop = broad_plan.stop
                _save_step(
                    db=db,
                    session_id=session_id,
                    iteration=plan_cycle,
                    phase="plan-broad",
                    input_json=plan_input,
                    output_json=broad_plan.raw_response,
                )
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "investigate/plan",
                            "status": "running",
                            "iteration": plan_cycle,
                            "summary": (
                                f"[plan] new_hypotheses={len(broad_plan.hypotheses)} "
                                f"active={len(state.active_hypotheses)}"
                            ),
                            "focus_hypothesis_id": state.focus_hypothesis_id,
                            "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                            "report_sections": get_report_status(),
                        }
                    )

                for hypothesis in list(state.active_hypotheses):
                    if interrupted:
                        status = "stopped"
                        break
                    state.focus_hypothesis_id = hypothesis.id
                    state.focus_depth = 0
                    focus_sections = _guess_related_sections(hypothesis.description)
                    if progress_callback:
                        progress_callback(
                            {
                                "stage": "investigate/hypothesis",
                                "status": "running",
                                "iteration": plan_cycle,
                                "summary": f"[hypothesis] {hypothesis.id}: {hypothesis.description}",
                                "focus_hypothesis_id": state.focus_hypothesis_id,
                                "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                                "report_sections": get_report_status(focus_sections=focus_sections),
                            }
                        )

                    candidates = _matching_findings(state.findings_snapshot, hypothesis)
                    for query_index in range(1, max_queries_per_hypothesis + 1):
                        state.focus_depth = query_index
                        hypothesis_plan = plan_hypothesis_query(
                            state=state,
                            hypothesis=hypothesis,
                            finding_candidates=candidates,
                            memory=memory,
                            base_url=base_url,
                            model=model,
                            overview_md=memory_overview_cache,
                            default_context_md=memory_plan_context_cache,
                            status_callback=llm_status,
                            audit_callback=lambda messages, output, parsed, hyp_id=hypothesis.id, query_idx=query_index: llm_logger.write(
                                iteration=plan_cycle,
                                phase="plan-hypothesis",
                                input_messages=messages,
                                output=parsed,
                                model=model,
                                base_url=base_url,
                                suffix=f"{hyp_id}-{query_idx:02d}",
                            ),
                        )
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="plan-hypothesis",
                            input_json={"hypothesis": hypothesis.model_dump(), "query_index": query_index},
                            output_json=hypothesis_plan.raw_response,
                            suffix=f"{hypothesis.id}-{query_index:02d}",
                        )
                        if hypothesis_plan.hypothesis is not None:
                            hypothesis = hypothesis_plan.hypothesis
                            _upsert_hypothesis(db, hypothesis, origin="broad_plan", session_id=session_id)
                        if not hypothesis_plan.query:
                            if not hypothesis_plan.needs_more:
                                break
                            continue

                        planned_query = hypothesis_plan.query
                        reasoning_entry_id = _append_hypothesis_reasoning(
                            db=db,
                            hypothesis_id=hypothesis.id,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="plan",
                            body=planned_query.purpose,
                            query_id=planned_query.query_id,
                        )
                        if progress_callback:
                            progress_callback(
                                {
                                    "stage": "investigate/do",
                                    "status": "running",
                                    "iteration": plan_cycle,
                                    "current_query": planned_query.query_id,
                                    "summary": f"[do] {planned_query.query_id}: {planned_query.purpose}",
                                    "hypothesis_id": hypothesis.id,
                                    "reasoning_entry_id": reasoning_entry_id,
                                    "focus_hypothesis_id": state.focus_hypothesis_id,
                                    "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                                    "report_sections": get_report_status(focus_sections=focus_sections),
                                }
                            )

                        rows = fetch_records(db, planned_query.sql)
                        result_summary = summarize_query_result(rows)
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="do",
                            input_json={"planned_query": planned_query.model_dump(), "query_index": query_index},
                            output_json=result_summary,
                            suffix=f"{planned_query.query_id}-{query_index:02d}",
                        )
                        check_result = check_query_result(
                            case=case,
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            planned_query=planned_query,
                            hypothesis=hypothesis,
                            finding_candidates=candidates,
                            result_summary=result_summary,
                            memory=memory,
                            base_url=base_url,
                            model=model,
                            overview_md=memory_overview_cache,
                            memory_context_md=memory_check_context_cache,
                            status_callback=llm_status,
                            audit_callback=lambda messages, output, parsed, query_id=planned_query.query_id, query_idx=query_index: llm_logger.write(
                                iteration=plan_cycle,
                                phase="check",
                                input_messages=messages,
                                output=parsed,
                                model=model,
                                base_url=base_url,
                                suffix=f"{query_id}-{query_idx:02d}",
                            ),
                        )
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="check",
                            input_json={
                                "planned_query": planned_query.model_dump(),
                                "hypothesis": hypothesis.model_dump(),
                                "result_summary": result_summary,
                            },
                            output_json=check_result.raw_response,
                            suffix=f"{planned_query.query_id}-{query_index:02d}",
                        )
                        reasoning_entry_id = _append_hypothesis_reasoning(
                            db=db,
                            hypothesis_id=hypothesis.id,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="check",
                            body=check_result.report_text,
                            verdict=check_result.verdict,
                            query_id=planned_query.query_id,
                        )
                        if progress_callback:
                            progress_callback(
                                {
                                    "stage": "investigate/check",
                                    "status": "running",
                                    "iteration": plan_cycle,
                                    "current_query": planned_query.query_id,
                                    "summary": (
                                        f"[check] {hypothesis.id}: verdict={check_result.verdict} "
                                        f"query={planned_query.query_id}"
                                    ),
                                    "hypothesis_id": hypothesis.id,
                                    "reasoning_entry_id": reasoning_entry_id,
                                    "focus_hypothesis_id": state.focus_hypothesis_id,
                                    "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                                    "report_sections": get_report_status(focus_sections=focus_sections),
                                }
                            )

                        state.history.append(
                            _history_entry(
                                iteration=plan_cycle,
                                query_id=planned_query.query_id,
                                hypothesis_id=hypothesis.id,
                                verdict=check_result.verdict,
                                report_text=check_result.report_text,
                                evidence_ids=result_summary.get("evidence_ids", []),
                            )
                        )
                        if check_result.new_hypotheses:
                            state.active_hypotheses = _merge_active_hypotheses(
                                db=db,
                                current=state.active_hypotheses,
                                updates=check_result.new_hypotheses,
                                resolved=state.resolved_hypotheses,
                                session_id=session_id,
                                origin="check_new",
                            )
                        if check_result.verdict in {"confirmed", "refuted"}:
                            _resolve_hypothesis(
                                db=db,
                                state=state,
                                hypothesis_id=hypothesis.id,
                                verdict=check_result.verdict,
                                summary=check_result.report_text,
                                session_id=session_id,
                            )
                            cycle_progress = True
                        elif check_result.verdict == "newlead" or check_result.progress:
                            cycle_progress = True
                            _upsert_hypothesis(
                                db=db,
                                hypothesis=Hypothesis(
                                    id=hypothesis.id,
                                    description=hypothesis.description,
                                    status="active",
                                    verdict=None,
                                    summary=check_result.report_text,
                                ),
                                origin="check_new",
                                session_id=session_id,
                            )
                        _apply_memory_updates(
                            memory=memory,
                            active_hypotheses=state.active_hypotheses,
                            resolved_hypotheses=state.resolved_hypotheses,
                            check_output=check_result.raw_response,
                            db=db,
                        )
                        refresh_memory_caches()
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="act",
                            input_json={"hypothesis_id": hypothesis.id, "query_id": planned_query.query_id},
                            output_json={
                                "verdict": check_result.verdict,
                                "active_hypotheses": [item.model_dump() for item in state.active_hypotheses],
                                "resolved_hypotheses": [item.model_dump() for item in state.resolved_hypotheses],
                            },
                            suffix=f"{planned_query.query_id}-{query_index:02d}",
                        )
                        if progress_callback:
                            progress_callback(
                                {
                                    "stage": "investigate/act",
                                    "status": "running",
                                    "iteration": plan_cycle,
                                    "summary": (
                                        f"[act] {hypothesis.id}: verdict={check_result.verdict} "
                                        f"resolved={len(state.resolved_hypotheses)}"
                                    ),
                                    "focus_hypothesis_id": state.focus_hypothesis_id,
                                    "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
                                    "report_sections": get_report_status(focus_sections=focus_sections),
                                }
                            )

                        if check_result.verdict in {"confirmed", "refuted"} or query_index >= max_queries_per_hypothesis:
                            break

                    if interrupted:
                        status = "stopped"
                        break

            if interrupted:
                break

            report_result: dict[str, Any] | None = None
            if plan_cycle % max(1, report_every_n_cycles) == 0:
                report_result = _refresh_report_sections(
                    case=case,
                    db=db,
                    session_id=session_id,
                    iteration=plan_cycle,
                    base_url=base_url,
                    model=model,
                    template_root=template_root,
                    llm_logger=llm_logger,
                    progress_callback=progress_callback,
                    focus_sections=focus_sections,
                    max_workers=report_parallelism,
                )
                report_after = report_result["report_status"]
                report_status_cache = report_after
                gap_new_hypotheses = _inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=report_result["gaps"],
                    session_id=session_id,
                    memory=memory,
                )
                if gap_new_hypotheses:
                    cycle_progress = True
                if _report_cycle_progress(report_before, report_after):
                    cycle_progress = True
                render_written_report(case, db)
            else:
                report_after = report_before

            if report_only:
                status = "completed"
                break

            unresolved_gap_count = int(report_after.get("total_gaps", 0))
            if broad_plan_stop or (
                not state.active_hypotheses and unresolved_gap_count == 0 and broad_plan_hypotheses == 0
            ):
                mark_report_sections_ai_exhausted(db)
                status = "completed"
                break
            if cycle_progress or broad_plan_hypotheses:
                no_progress_count = 0
            else:
                no_progress_count += 1
            if no_progress_count >= no_progress_limit:
                status = "completed"
                break
        else:
            status = "completed"
    finally:
        signal.signal(signal.SIGINT, previous_sigint)

    finished_at = datetime.now(UTC).replace(tzinfo=None)
    summary = _final_summary(state)
    db.execute(
        """
        UPDATE investigation_sessions
        SET finished_at = ?, iterations = ?, status = ?
        WHERE session_id = ?
        """,
        (finished_at, state.iteration, status, session_id),
    )
    return {
        "session_id": session_id,
        "status": status,
        "iteration": state.iteration,
        "depth": state.focus_depth,
        "focus_hypothesis_id": state.focus_hypothesis_id,
        "summary": summary,
        "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
        "report_sections": get_report_status(refresh=True),
    }
