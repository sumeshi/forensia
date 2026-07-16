"""Per-block context assembly for the section agent."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Block-support helpers live in section_answers / section_exec / section_run_store.
from forensia.ai.sections.section_exec import (
    _filter_template_catalog_by_section,
    _keypoint_catalog,
    _structured_report_brief,
    structured_digest_from_answers,
)
from forensia.ai.sections.section_run_store import (
    _audit_bridge,
    _findings_snapshot,
    _load_reusable_section_evidence,
    _store_section_question,
    load_reusable_section_facts,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.db.database import CaseDB
from forensia.knowledge.questions import (
    QuestionSpec,
    resolve_question_spec,
)


@dataclass(slots=True)
class _BlockContext:
    case: Case
    db: CaseDB
    section_key: str
    title: str
    block_heading: str
    template_body: str
    base_url: str
    model: str
    audit: Callable | None
    keypoint_catalog: list[dict]
    template_catalog: list[dict]
    reusable_facts: list[dict[str, Any]]
    reusable_evidence: list[dict[str, Any]]
    memory_context_md: str
    question_mode: bool
    max_queries: int
    findings_snapshot: list[dict[str, Any]]
    prompt_report_brief: dict[str, Any]
    question_spec: QuestionSpec | None = None
    question_confidence: float = 0.0
    evidence_keypoints: list[str] | None = None
    question_id: str = ""
    answer_id: str = ""
    answer_spec: str = ""
    question: str = ""
    structured_digest: str = ""
    review_audit: Callable | None = None
    template_tags: tuple[str, ...] = ()


def prepare_block_context(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    base_url: str,
    model: str,
    memory: MemoryManager | None,
    max_queries: int,
    evidence_keypoints: list[str] | None,
    question_mode: bool,
    question_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    section_table_digest: str = "",
    audit_callback=None,
    review_audit_callback=None,
    report_brief: dict[str, Any] | None = None,
    template_tags: tuple[str, ...] = (),
) -> _BlockContext:
    routing_text = f"{question}\n{template_body}".strip() if question else template_body
    question_spec, question_confidence = resolve_question_spec(
        block_heading=block_heading,
        template_body=routing_text,
        question=question,
        answer_spec=answer_spec,
    )
    resolved_answer_spec = answer_spec or (
        question_spec.answer_spec if question_spec is not None else ""
    )
    _store_section_question(
        db,
        section_key=section_key,
        block_heading=block_heading,
        question_text=question or block_heading or template_body[:200],
        spec=question_spec,
        confidence=question_confidence,
    )
    memory_context_md = ""
    if memory is not None:
        memory_context_md = memory.load_investigation_context(
            None,
            max_bytes=max(1024, memory.max_bytes // 2),
            include_overview=False,
            include_scratch=False,
        )
    findings_snapshot = _findings_snapshot(db)
    keypoint_catalog = _keypoint_catalog(
        section_key,
        template_body,
        block_heading=block_heading,
        evidence_keypoints=evidence_keypoints,
    )
    template_catalog = _filter_template_catalog_by_section([], section_key, [])
    reusable_facts = load_reusable_section_facts(
        db,
        section_key,
        include_case_probe=section_key == "6_appendix",
    )
    reusable_evidence = _load_reusable_section_evidence(db, section_key, block_heading=block_heading)
    if question_mode:
        reusable_facts = []
        reusable_evidence = []
    audit = _audit_bridge(audit_callback)
    review_audit = _audit_bridge(review_audit_callback)
    prompt_report_brief = (
        _structured_report_brief(report_brief)
        if question_mode
        else (report_brief or {})
    )
    structured_digest = (
        structured_digest_from_answers(case)
        if section_key in {"1_overview", "2_timeline"}
        else ""
    )
    if section_table_digest:
        # R6-05: same-section table data, rendered moments earlier, becomes
        # part of the narrative blocks' observation context.
        structured_digest = (structured_digest + "\n" + section_table_digest).strip()
    return _BlockContext(
        case=case,
        db=db,
        section_key=section_key,
        title=title,
        block_heading=block_heading,
        template_body=template_body,
        base_url=base_url,
        model=model,
        audit=audit,
        keypoint_catalog=keypoint_catalog,
        template_catalog=template_catalog,
        reusable_facts=reusable_facts,
        reusable_evidence=reusable_evidence,
        memory_context_md=memory_context_md,
        question_mode=question_mode,
        max_queries=max_queries,
        findings_snapshot=findings_snapshot,
        prompt_report_brief=prompt_report_brief,
        question_spec=question_spec,
        question_confidence=question_confidence,
        evidence_keypoints=evidence_keypoints,
        question_id=question_id,
        answer_id=answer_id,
        answer_spec=resolved_answer_spec,
        question=question,
        structured_digest=structured_digest,
        review_audit=review_audit,
        template_tags=tuple(template_tags),
    )
