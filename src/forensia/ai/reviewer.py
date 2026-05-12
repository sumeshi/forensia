from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from collections.abc import Callable

import orjson

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import build_review_messages
from forensia.core.case import Case
from forensia.db.database import CaseDB


@dataclass(slots=True)
class LLMReviewResult:
    verdict: str
    report_text: str
    missing_checks: list[str]
    confidence_adjustment: float
    notes: str
    raw_response: dict[str, Any]


def review_finding(
    case: Case,
    db: CaseDB,
    finding: dict[str, Any],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> LLMReviewResult:
    evidence = json.loads(finding.get("evidence") or "[]")
    messages = build_review_messages(finding, evidence)
    parsed = request_llm_json(messages=messages, model=model, base_url=base_url, status_callback=status_callback)
    result = LLMReviewResult(
        verdict=parsed["verdict"],
        report_text=parsed["report_text"],
        missing_checks=parsed.get("missing_checks", []),
        confidence_adjustment=float(parsed.get("confidence_adjustment", 0.0)),
        notes=parsed.get("notes", ""),
        raw_response=parsed,
    )

    db.execute(
        """
        INSERT INTO ai_reviews (
            review_id, finding_id, verdict, report_text, missing_checks,
            confidence_adjustment, notes, raw_response, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"{finding['finding_id']}-review",
            finding["finding_id"],
            result.verdict,
            result.report_text,
            json.dumps(result.missing_checks, ensure_ascii=False),
            result.confidence_adjustment,
            result.notes,
            json.dumps(result.raw_response, ensure_ascii=False),
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )
    db.execute(
        """
        UPDATE findings
        SET ai_summary = ?, missing_checks = ?, status = ?, confidence = confidence + ?
        WHERE finding_id = ?
        """,
        (
            result.report_text,
            json.dumps(result.missing_checks, ensure_ascii=False),
            result.verdict,
            result.confidence_adjustment,
            finding["finding_id"],
        ),
    )

    log_path = case.ai_logs_dir / f"{finding['finding_id']}.json"
    log_path.write_bytes(
        orjson.dumps(
            {
                "input": messages,
                "output": parsed,
                "meta": {"model": model, "base_url": base_url},
            },
            option=orjson.OPT_INDENT_2,
        )
    )
    return result
