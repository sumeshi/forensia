from __future__ import annotations

import hashlib
import json
from typing import Any

from forensia.ai.hypothesis_manager import _all_hypotheses, _upsert_hypothesis
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.report.writer import fetch_report_sections


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


def _build_report_status(
    db: CaseDB,
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
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
    if any(
        token in lowered
        for token in (
            "whois",
            "osint",
            "外部",
            "所有組織",
            "threat intel",
            "reputation",
            "ip reputation",
            "geo lookup",
            "dns lookup",
            "certificate",
            "public record",
            "external",
            "internet",
        )
    ):
        return "external_lookup"
    if any(
        token in lowered
        for token in (
            "ヒアリング",
            "担当者",
            "利用者",
            "承認",
            "human",
            "業務",
            "user confirmation",
            "manager approval",
            "business",
            "policy",
            "confirm with",
            "authorized",
            "permission",
        )
    ):
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
