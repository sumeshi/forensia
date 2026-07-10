from __future__ import annotations

from pathlib import Path
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.section_quality import _title_from_template_body
from forensia.report.template_parsing import parse_template, split_template_body

SECTION_KEYPOINT_PREFIXES: dict[str, tuple[str, ...]] = {
    "overview": ("overview_",),
    "timeline": ("timeline_",),
    "technical": ("host_", "account_", "persistence_", "ioc_", "execution_"),
    "gaps": ("gaps_",),
    "recommendations": ("recommendations_",),
    "appendix": ("appendix_",),
}

SECTION_EXTRA_KEYPOINTS: dict[str, tuple[str, ...]] = {
    "overview": ("top_keypoints", "session_activity_events"),
    "timeline": (
        "top_keypoints",
        "gaps_log_integrity_events",
        "timeline_prefetch_full_history",
    ),
    "technical": (
        "top_keypoints",
        "overview_hosts",
        "session_activity_events",
        "host_user_profile_paths",
        "timeline_prefetch_history",
        "timeline_prefetch_full_history",
        "host_execution_activity",
        "mft_prefetch_filenames",
        "mft_user_app_activity",
        "mft_recent_folder_lnk",
        "ioc_user_data_files",
    ),
    "gaps": ("top_keypoints",),
    "recommendations": (
        "top_keypoints",
        "timeline_system_events",
        "timeline_prefetch_history",
        "ioc_user_data_files",
    ),
    "appendix": ("top_keypoints",),
}


def section_family(section_key: str) -> str:
    parts = str(section_key or "").split("_", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def prepare_section_request(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read a section template and normalize block requests for section agents."""
    del db
    template_body, template_meta = parse_template(str(template_path))
    section_key = Path(template_path).stem
    title = _title_from_template_body(template_body, section_key)
    template_preamble, blocks = split_template_body(template_body)
    if not blocks:
        blocks = [
            {
                "heading": "",
                "template_body": template_body,
                "evidence_keypoints": [],
                "mode": "",
                "question_id": "",
                "answer_id": "",
                "answer_spec": "",
                "question": "",
                "builder": "",
            }
        ]
    block_requests = [
        {
            "heading": block["heading"],
            "template_body": block["template_body"],
            "evidence_keypoints": list(block.get("evidence_keypoints") or []),
            "mode": str(block.get("mode") or ""),
            "question_id": str(block.get("question_id") or ""),
            "answer_id": str(block.get("answer_id") or block.get("question_id") or ""),
            "answer_spec": str(block.get("answer_spec") or ""),
            "question": str(block.get("question") or ""),
            "builder": str(block.get("builder") or ""),
        }
        for block in blocks
    ]
    return {
        "case": case,
        "section_key": section_key,
        "title": title,
        "template_path": str(template_path),
        "template_preamble": template_preamble,
        "block_requests": block_requests,
        "context_sections": dict(context_sections),
        "report_brief": report_brief or {},
        "template_meta": template_meta,
    }


def body_starts_with_heading(body: str, heading: str) -> bool:
    text = body.lstrip()
    if text.startswith("**Status:**"):
        nl = text.find("\n")
        text = text[nl:].lstrip() if nl != -1 else ""
    return text.startswith(f"## {heading}")


def assemble_section_body(template_preamble: str, rendered_blocks: list[str]) -> str:
    """Join preamble and rendered blocks consistently across sync/async paths."""
    parts = [
        str(template_preamble or "").strip(),
        *[item.strip() for item in rendered_blocks if item.strip()],
    ]
    return "\n\n".join(part for part in parts if part).strip()
