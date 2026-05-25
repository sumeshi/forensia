from __future__ import annotations

import hashlib
import json
import signal
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from re import sub
from typing import Any
from uuid import uuid4

import yaml
from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.checker import check_query_result, summarize_query_result
from forensia.ai.hypothesis_manager import (
    _all_hypotheses,
    _load_persisted_hypotheses,
    _merge_active_hypotheses,
    _render_hypothesis_memory,
    _resolve_hypothesis,
    _upsert_hypothesis,
)
from forensia.ai.planner import BroadPlanResult, broad_plan_investigation, plan_hypothesis_query
from forensia.ai.report_gap import (
    _build_report_status,
    _guess_related_sections,
    _inject_gap_hypotheses,
    _overlay_report_status,
    _report_cycle_progress,
)
from forensia.ai.section_refresher import _refresh_report_sections
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import ENTITY_ROLES, HistoryEntry, Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.writer import (
    mark_report_sections_ai_exhausted,
    render_written_report,
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
    hypothesis_id: str | None,
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
            step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (step_id) DO UPDATE SET
            output_json = excluded.output_json,
            created_at = excluded.created_at
        """,
        (
            step_id,
            session_id,
            hypothesis_id,
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


def _load_profile_config(profile: str) -> dict[str, Any]:
    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    if not profile_path.exists():
        return {}
    return yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}


def _initialize_overview(memory: MemoryManager, case: Case, profile_config: dict[str, Any] | None = None) -> None:
    objective = str((profile_config or {}).get("objective") or "").strip()
    if memory.has_overview():
        return
    output_language = str(get_llm_settings()["output_language"]).lower()
    open_question_seed = {
        "ja": "初回調査待ち",
        "en": "Awaiting initial investigation",
    }.get(output_language, "Awaiting initial investigation")
    objective_line = objective or {
        "ja": "証拠に基づいて事実関係を整理する",
        "en": "Establish the evidence-backed incident narrative.",
    }.get(output_language, "Establish the evidence-backed incident narrative.")
    memory.update_overview(
        (
            f"# Investigation Overview\n\n"
            f"Case: {case.path.name}\n\n"
            f"## Investigation Objective\n- {objective_line}\n\n"
            "## Memory Details\n"
            "- Detailed fact records can be stored under memory/details/fact-NNN.md and loaded on demand.\n\n"
            "## Case Scope\n- none\n\n"
            "## Key Findings\n- none\n\n"
            "## Investigation Policy\n- preserve evidence fidelity\n\n"
            f"## Active Tasks\n- {open_question_seed}\n"
        )
    )


def _ensure_profile_objective(memory: MemoryManager, profile_config: dict[str, Any] | None = None) -> None:
    objective = str((profile_config or {}).get("objective") or "").strip()
    if not objective:
        return
    overview = memory.load_overview()
    if "## Investigation Objective" not in overview:
        memory.update_overview(
            overview.rstrip() + f"\n\n## Investigation Objective\n- {objective}\n"
        )
    elif objective not in overview:
        memory.update_overview(
            overview.replace("## Investigation Objective\n", f"## Investigation Objective\n- {objective}\n", 1)
            if "## Investigation Objective\n- " not in overview
            else overview
        )
    if memory.tasks_memory_path.exists():
        tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")
    else:
        tasks_text = ""
    objective_task = f"Investigation objective: {objective}"
    if objective_task not in tasks_text:
        memory.append_task(objective_task, "human_decision")


def _finding_snapshot(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT finding_id, title, summary, severity, confidence, status, evidence
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )


def _render_entity_memory(entity_type: str, name: str, notes: str, role: str = "") -> str:
    normalized_type = str(entity_type).strip().lower() or "entity"
    normalized_name = str(name).strip()
    lines = [f"# {normalized_type}: {normalized_name}", "", f"- type: {normalized_type}", f"- name: {normalized_name}"]
    normalized_role = str(role).strip().lower()
    if normalized_role in ENTITY_ROLES and normalized_role != "unknown":
        lines.append(f"- role: {normalized_role}")
    note_text = str(notes).strip()
    if note_text:
        lines.append(f"- notes: {note_text}")
    return "\n".join(lines).rstrip() + "\n"


def _keypoint_card_id(index: int) -> str:
    return f"KP-{index:04d}"


def _sync_keypoint_cards(memory: MemoryManager, findings_snapshot: list[dict[str, Any]]) -> None:
    for index, finding in enumerate(findings_snapshot, start=1):
        evidence_ids: list[str] = []
        evidence = finding.get("evidence")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except json.JSONDecodeError:
                evidence = []
        if isinstance(evidence, list):
            for row in evidence:
                if not isinstance(row, dict):
                    continue
                evidence_id = str(row.get("evidence_id") or "").strip()
                if evidence_id:
                    evidence_ids.append(evidence_id)
        lines = [
            f"# {_keypoint_card_id(index)}",
            "",
            f"- finding_id: {finding.get('finding_id')}",
            f"- title: {finding.get('title')}",
            f"- severity: {finding.get('severity')}",
            f"- confidence: {finding.get('confidence')}",
            "",
            "## Summary",
            str(finding.get("summary") or "").strip() or "-",
            "",
            "## Evidence IDs",
        ]
        lines.extend([f"- {evidence_id}" for evidence_id in evidence_ids] or ["- none"])
        memory.upsert_keypoint(_keypoint_card_id(index), "\n".join(lines).rstrip() + "\n")
    active_ids = {_keypoint_card_id(index) for index in range(1, len(findings_snapshot) + 1)}
    for path in memory.keypoints_dir.glob("KP-*.md"):
        if path.stem not in active_ids:
            path.unlink(missing_ok=True)


def _sync_hypothesis_cards(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
) -> None:
    valid_ids = {
        sub(r"[^a-zA-Z0-9._-]+", "-", str(item.id).strip()).strip("-") or "unknown"
        for item in [*active_hypotheses, *resolved_hypotheses]
    }
    for path in memory.hypotheses_dir.glob("*.md"):
        if path.stem not in valid_ids:
            path.unlink(missing_ok=True)


def _matching_findings(snapshot: list[dict[str, Any]], hypothesis: Hypothesis | None) -> list[dict[str, Any]]:
    if hypothesis is None:
        return snapshot[:10]
    words = {token.lower() for token in hypothesis.description.split() if len(token) >= 3}
    if not words:
        return snapshot[:10]
    matched = []
    for finding in snapshot:
        haystack = " ".join(
            str(finding.get(key, "") or "")
            for key in ("title", "summary", "severity", "status")
        ).lower()
        if any(word in haystack for word in words):
            matched.append(finding)
    return matched[:10] if matched else snapshot[:10]


def _final_summary(state: SessionState) -> str:
    if state.resolved_hypotheses:
        lines = []
        for item in state.resolved_hypotheses[-5:]:
            verdict = item.verdict or item.status
            lines.append(f"[{verdict}] {item.description}: {item.summary or 'summary unavailable'}")
        return "\n".join(lines)
    if state.history:
        return "\n".join(entry.summary for entry in state.history[-5:] if entry.summary)
    output_language = str(get_llm_settings()["output_language"]).lower()
    return {
        "ja": "調査中に追加の進展はありませんでした。",
        "en": "No additional progress was made during this investigation.",
    }.get(output_language, "No additional progress was made during this investigation.")


def _apply_memory_updates(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
    check_output: dict[str, Any],
    db: CaseDB | None = None,
) -> None:
    updates = check_output.get("memory_updates") or {}
    for item in updates.get("facts") or []:
        if not isinstance(item, dict):
            continue
        memory.append_confirmed_fact(
            str(item.get("text") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )

    for item in updates.get("timeline") or []:
        if not isinstance(item, dict):
            continue
        memory.append_timeline_anchor(
            str(item.get("timestamp") or ""),
            str(item.get("description") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )

    for item in updates.get("tasks") or []:
        if not isinstance(item, dict):
            continue
        memory.append_task(
            str(item.get("text") or item.get("question") or ""),
            str(item.get("kind") or ""),
        )

    for item in updates.get("overview") or []:
        memory.append_overview(str(item))

    for item in updates.get("refuted_hypotheses") or []:
        if not isinstance(item, dict):
            continue
        memory.append_refuted_hypothesis(
            str(item.get("hypothesis_id") or ""),
            str(item.get("description") or ""),
            str(item.get("reason") or ""),
        )

    for item in updates.get("resolved_gaps") or []:
        if not isinstance(item, dict):
            continue
        memory.append_resolved_gap(
            str(item.get("text") or ""),
            [str(evidence_id) for evidence_id in (item.get("evidence_ids") or [])],
        )

    for item in updates.get("entities") or []:
        if not isinstance(item, dict):
            continue
        entity_type = str(item.get("entity_type") or "")
        entity_name = str(item.get("name") or "")
        entity_role = str(item.get("role") or "")
        notes = str(item.get("notes") or "")
        content = str(item.get("content") or "").strip() or _render_entity_memory(entity_type, entity_name, notes, entity_role)
        memory.upsert_entity(
            entity_type,
            entity_name,
            content,
        )

    memory.append_suspicious(check_output.get("suspicious_evidence") or [])

    for hypothesis in active_hypotheses:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(db, hypothesis)
        memory.upsert_hypothesis(hypothesis.id, slug, content)
    for hypothesis in resolved_hypotheses:
        slug = hypothesis.description[:40]
        content = _render_hypothesis_memory(None, hypothesis)
        memory.upsert_hypothesis(hypothesis.id, slug, content)


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
    profile_config = _load_profile_config(profile)
    if template_root is None:
        case.ensure_report_templates()
        template_root = case.report_template_dir

    _seed_findings(case, db, profile)
    _initialize_overview(memory, case, profile_config)
    _ensure_profile_objective(memory, profile_config)
    llm_logger = LLMCallLogger(case, session_id)
    active_hypotheses, resolved_hypotheses = _load_persisted_hypotheses(db)
    state = SessionState(
        session_id=session_id,
        iteration=0,
        findings_snapshot=_finding_snapshot(db),
        active_hypotheses=active_hypotheses,
        resolved_hypotheses=resolved_hypotheses,
    )
    _sync_keypoint_cards(memory, state.findings_snapshot)
    _sync_hypothesis_cards(memory, state.active_hypotheses, state.resolved_hypotheses)
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

    memory.compact_overview_if_needed(base_url=base_url, model=model)
    memory_overview_cache = memory.load_compact_context(["overview.md"], max_bytes=memory.max_bytes)
    memory_plan_context_cache = memory.load_compact_context(
        ["facts.md", "tasks.md"],
        max_bytes=max(1024, memory.max_bytes // 3),
    )
    memory_check_context_cache = memory.load_compact_context(
        ["facts.md", "timeline.md", "tasks.md"],
        max_bytes=max(1024, memory.max_bytes // 2),
    )

    def refresh_memory_caches() -> None:
        nonlocal memory_overview_cache, memory_plan_context_cache, memory_check_context_cache
        memory.compact_overview_if_needed(base_url=base_url, model=model)
        memory_overview_cache = memory.load_compact_context(["overview.md"], max_bytes=memory.max_bytes)
        memory_plan_context_cache = memory.load_compact_context(
            ["facts.md", "tasks.md"],
            max_bytes=max(1024, memory.max_bytes // 3),
        )
        memory_check_context_cache = memory.load_compact_context(
            ["facts.md", "timeline.md", "tasks.md"],
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

        _emit("investigate/llm", message, iteration=state.iteration)

    def _handle_sigint(signum, frame) -> None:
        nonlocal interrupted
        interrupted = True

    def _emit(
        stage: str,
        summary: str,
        *,
        report_kw: dict[str, Any] | None = None,
        iteration: int | None = None,
        **extras: Any,
    ) -> None:
        if not progress_callback:
            return
        payload = {
            "stage": stage,
            "status": "running",
            "iteration": state.iteration if iteration is None else iteration,
            "summary": summary,
            "focus_hypothesis_id": state.focus_hypothesis_id,
            "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
            "report_sections": get_report_status(**(report_kw or {})),
        }
        payload.update(extras)
        progress_callback(payload)

    signal.signal(signal.SIGINT, _handle_sigint)
    try:
        for plan_cycle in range(1, max_iter + 1):
            state.iteration = plan_cycle
            state.findings_snapshot = _finding_snapshot(db)
            _sync_keypoint_cards(memory, state.findings_snapshot)
            _emit("investigate", f"Hypothesis cycle {plan_cycle}/{max_iter}", iteration=plan_cycle)
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
                try:
                    broad_plan: BroadPlanResult = broad_plan_investigation(
                        state=state,
                        memory=memory,
                        base_url=base_url,
                        model=model,
                        max_findings=20,
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
                        hypothesis_id=None,
                        input_json=plan_input,
                        output_json=broad_plan.raw_response,
                    )
                    _emit(
                        "investigate/plan",
                        f"[plan] new_hypotheses={len(broad_plan.hypotheses)} active={len(state.active_hypotheses)}",
                        iteration=plan_cycle,
                    )
                except Exception as exc:
                    err_msg = f"[plan-broad] LLM failed: {exc}"
                    print(f"[red]{err_msg}[/red]")
                    _emit("investigate/plan", err_msg, iteration=plan_cycle)

                for hypothesis in list(state.active_hypotheses):
                    if interrupted:
                        status = "stopped"
                        break
                    state.focus_hypothesis_id = hypothesis.id
                    state.focus_depth = 0
                    focus_sections = _guess_related_sections(hypothesis.description)
                    _emit(
                        "investigate/hypothesis",
                        f"[hypothesis] {hypothesis.id}: {hypothesis.description}",
                        iteration=plan_cycle,
                        report_kw={"focus_sections": focus_sections},
                    )

                    candidates = _matching_findings(state.findings_snapshot, hypothesis)
                    for query_index in range(1, max_queries_per_hypothesis + 1):
                        state.focus_depth = query_index
                        try:
                            hypothesis_plan = plan_hypothesis_query(
                                state=state,
                                hypothesis=hypothesis,
                                finding_candidates=candidates,
                                memory=memory,
                                base_url=base_url,
                                model=model,
                                db=db,
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
                        except Exception as exc:
                            err_msg = f"[plan-hypothesis] LLM failed for {hypothesis.id}: {exc}"
                            print(f"[red]{err_msg}[/red]")
                            _append_hypothesis_reasoning(
                                db=db,
                                hypothesis_id=hypothesis.id,
                                session_id=session_id,
                                iteration=plan_cycle,
                                phase="plan",
                                body=err_msg,
                            )
                            break
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="plan-hypothesis",
                            hypothesis_id=hypothesis.id,
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
                        _emit(
                            "investigate/do",
                            f"[do] {planned_query.query_id}: {planned_query.purpose}",
                            iteration=plan_cycle,
                            report_kw={"focus_sections": focus_sections},
                            current_query=planned_query.query_id,
                            hypothesis_id=hypothesis.id,
                            reasoning_entry_id=reasoning_entry_id,
                        )

                        try:
                            rows = fetch_records(db, planned_query.sql)
                        except Exception as exc:
                            err_msg = f"SQL execution error — {planned_query.query_id}: {exc}"
                            print(f"[red]{err_msg}[/red]")
                            _emit(
                                "investigate/do",
                                f"[do] {err_msg}",
                                iteration=plan_cycle,
                                hypothesis_id=hypothesis.id,
                            )
                            _append_hypothesis_reasoning(
                                db=db,
                                hypothesis_id=hypothesis.id,
                                session_id=session_id,
                                iteration=plan_cycle,
                                phase="do",
                                body=err_msg,
                                query_id=planned_query.query_id,
                            )
                            continue
                        result_summary = summarize_query_result(rows)
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="do",
                            hypothesis_id=hypothesis.id,
                            input_json={"planned_query": planned_query.model_dump(), "query_index": query_index},
                            output_json=result_summary,
                            suffix=f"{planned_query.query_id}-{query_index:02d}",
                        )
                        try:
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
                        except Exception as exc:
                            err_msg = f"[check] LLM failed for {hypothesis.id}/{planned_query.query_id}: {exc}"
                            print(f"[red]{err_msg}[/red]")
                            _append_hypothesis_reasoning(
                                db=db,
                                hypothesis_id=hypothesis.id,
                                session_id=session_id,
                                iteration=plan_cycle,
                                phase="check",
                                body=err_msg,
                                query_id=planned_query.query_id,
                            )
                            continue
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="check",
                            hypothesis_id=hypothesis.id,
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
                        _emit(
                            "investigate/check",
                            f"[check] {hypothesis.id}: verdict={check_result.verdict} query={planned_query.query_id}",
                            iteration=plan_cycle,
                            report_kw={"focus_sections": focus_sections},
                            current_query=planned_query.query_id,
                            hypothesis_id=hypothesis.id,
                            reasoning_entry_id=reasoning_entry_id,
                        )

                        state.history.append(
                            HistoryEntry(
                                iteration=plan_cycle,
                                query_id=planned_query.query_id,
                                hypothesis_id=hypothesis.id,
                                verdict=check_result.verdict,
                                summary=check_result.report_text,
                                evidence_ids=result_summary.get("evidence_ids", []),
                            )
                        )
                        state.history = state.history[-50:]
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
                            check_output={
                                **check_result.raw_response,
                                "memory_updates": check_result.memory_updates,
                                "suspicious_evidence": check_result.suspicious_evidence,
                            },
                            db=db,
                        )
                        try:
                            memory.compact_overview_if_needed(base_url=base_url, model=model)
                            memory.compact_oversized_with_llm(base_url=base_url, model=model)
                        except Exception as exc:
                            print(f"[yellow][memory] compaction failed: {exc}[/yellow]")
                        refresh_memory_caches()
                        _save_step(
                            db=db,
                            session_id=session_id,
                            iteration=plan_cycle,
                            phase="act",
                            hypothesis_id=hypothesis.id,
                            input_json={"hypothesis_id": hypothesis.id, "query_id": planned_query.query_id},
                            output_json={
                                "verdict": check_result.verdict,
                                "active_hypotheses": [item.model_dump() for item in state.active_hypotheses],
                                "resolved_hypotheses": [item.model_dump() for item in state.resolved_hypotheses],
                            },
                            suffix=f"{planned_query.query_id}-{query_index:02d}",
                        )
                        _emit(
                            "investigate/act",
                            f"[act] {hypothesis.id}: verdict={check_result.verdict} resolved={len(state.resolved_hypotheses)}",
                            iteration=plan_cycle,
                            report_kw={"focus_sections": focus_sections},
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
                try:
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
                except Exception as exc:
                    print(f"[red][report] section refresh failed: {exc}[/red]")
                    _emit("investigate/report-cycle-done", f"[report] refresh failed: {exc}", iteration=plan_cycle)
                if report_result is not None:
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
            else:
                report_after = report_before

            if report_only:
                status = "completed"
                break

            unresolved_gap_count = int(report_after.get("total_gaps", 0))
            if broad_plan_stop and not state.active_hypotheses and unresolved_gap_count == 0:
                mark_report_sections_ai_exhausted(db)
                status = "completed"
                break
            if cycle_progress:
                no_progress_count = 0
            else:
                no_progress_count += 1
            if no_progress_count >= no_progress_limit:
                status = "completed"
                break
        else:
            status = "completed"
    except Exception:
        status = "failed"
        raise
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        finished_at = datetime.now(UTC).replace(tzinfo=None)
        db.execute(
            """
            UPDATE investigation_sessions
            SET finished_at = ?, iterations = ?, status = ?
            WHERE session_id = ?
            """,
            (finished_at, state.iteration, status, session_id),
        )

    summary = _final_summary(state)
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
