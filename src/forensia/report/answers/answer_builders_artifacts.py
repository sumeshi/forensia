"""Structured answer builders: browser, LNK, cloud, and anti-forensics."""

from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import (
    catalog_artifact_names,
    catalog_exe_globs,
    catalog_file_patterns,
    catalog_marker_map,
    exe_glob_sql,
)
from forensia.report.answers.answer_store import (
    _catalog_path_patterns,
    _dedupe_dict_rows,
    _like_sql,
    _lower_blob,
    _structured_answer,
    _structured_rows,
    _text,
)
from forensia.report.answers.event_semantics import LOG_CLEAR_EVENT_SQL


@lru_cache(maxsize=1)
def _browser_markers() -> dict[str, tuple[str, ...]]:
    return catalog_marker_map(
        "browser_artifacts",
        "name",
        "exe_patterns",
        "paths",
        "version_sources",
    )


def _browser_name_for_row(row: dict[str, Any]) -> str:
    text = _lower_blob(row).replace("\\", "/")
    for name, markers in _browser_markers().items():
        if any(marker.replace("\\", "/") in text for marker in markers):
            return name
    return ""


def _build_browser_usage(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    browser_exe_sql = exe_glob_sql(
        "executable_name", catalog_exe_globs("browser_artifacts")
    )
    browser_file_sql = exe_glob_sql("file_name", catalog_exe_globs("browser_artifacts"))
    browser_path_sql = _like_sql(
        "file_path", _catalog_path_patterns("browser_artifacts")
    )
    prefetch_rows = _structured_rows(
        db,
        f"""
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE {browser_exe_sql}
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        """,
    )
    mft_rows = _structured_rows(
        db,
        f"""
        SELECT
            file_name,
            file_path,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE {browser_file_sql}
           OR {browser_path_sql}
        ORDER BY si_modified DESC NULLS LAST, file_name
        LIMIT 100
        """,
    )
    grouped: dict[str, dict[str, Any]] = {}

    def group_for(browser_name: str) -> dict[str, Any]:
        return grouped.setdefault(
            browser_name,
            {
                "browser_name": browser_name,
                "prefetch_records": 0,
                "total_exec_count": 0,
                "last_exec_time": "",
                "mft_artifacts": 0,
                "first_artifact_time": "",
                "last_artifact_time": "",
                "sample_paths": [],
                "evidence_ids": [],
            },
        )

    def append_unique(values: list[Any], value: Any, limit: int) -> None:
        text = _text(value)
        if text and text not in values and len(values) < limit:
            values.append(text)

    def max_text_time(left: Any, right: Any) -> str:
        left_text = _text(left)
        right_text = _text(right)
        return (
            max(left_text, right_text)
            if left_text and right_text
            else (left_text or right_text)
        )

    def min_text_time(left: Any, right: Any) -> str:
        left_text = _text(left)
        right_text = _text(right)
        return (
            min(left_text, right_text)
            if left_text and right_text
            else (left_text or right_text)
        )

    for row in prefetch_rows:
        browser_name = _browser_name_for_row(row)
        if not browser_name:
            continue
        item = group_for(browser_name)
        item["prefetch_records"] = int(item.get("prefetch_records") or 0) + 1
        try:
            item["total_exec_count"] = int(item.get("total_exec_count") or 0) + int(
                row.get("exec_count") or 0
            )
        except TypeError, ValueError:
            pass
        item["last_exec_time"] = max_text_time(
            item.get("last_exec_time"), row.get("last_exec_time")
        )
        append_unique(
            item["sample_paths"],
            row.get("source_file") or row.get("executable_name"),
            10,
        )
        append_unique(item["evidence_ids"], row.get("evidence_id"), 20)
    for row in mft_rows:
        browser_name = _browser_name_for_row(row)
        if not browser_name:
            continue
        item = group_for(browser_name)
        item["mft_artifacts"] = int(item.get("mft_artifacts") or 0) + 1
        item["first_artifact_time"] = min_text_time(
            item.get("first_artifact_time"), row.get("artifact_time")
        )
        item["last_artifact_time"] = max_text_time(
            item.get("last_artifact_time"), row.get("artifact_time")
        )
        append_unique(
            item["sample_paths"], row.get("file_path") or row.get("file_name"), 10
        )
        append_unique(item["evidence_ids"], row.get("evidence_id"), 20)
    rows = sorted(
        grouped.values(), key=lambda item: str(item.get("browser_name") or "")
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "browser_name",
            "prefetch_records",
            "total_exec_count",
            "last_exec_time",
            "mft_artifacts",
            "first_artifact_time",
            "last_artifact_time",
            "sample_paths",
            "evidence_ids",
        ],
        queries_run=[
            "structured:browser_usage:browser_prefetch",
            "structured:browser_usage:browser_mft_artifacts",
        ],
    )


def _recent_lnk_base_name(file_name: Any) -> str:
    text = _text(file_name)
    if text.lower().endswith(".lnk"):
        text = text[:-4]
    return text.strip()


def _recent_lnk_tokens(file_name: Any) -> set[str]:
    base = _recent_lnk_base_name(file_name).lower()
    base = re.sub(r"\.[a-z0-9]{1,8}$", "", base)
    tokens = {token for token in re.split(r"[^a-z0-9]+", base) if len(token) >= 3}
    return tokens - {"lnk", "desktop", "templates", "drive"}


def _row_time_text(row: dict[str, Any]) -> str:
    for key in ("fn_created", "si_created", "fn_modified", "si_modified"):
        value = _text(row.get(key))
        if value:
            return value
    return ""


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _infer_recent_lnk_rename_candidates(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for left_index, left in enumerate(rows):
        left_tokens = _recent_lnk_tokens(left.get("file_name"))
        left_time = _parse_iso_datetime(_row_time_text(left))
        if not left_tokens or left_time is None:
            continue
        for right in rows[left_index + 1 :]:
            right_tokens = _recent_lnk_tokens(right.get("file_name"))
            right_time = _parse_iso_datetime(_row_time_text(right))
            if not right_tokens or right_time is None:
                continue
            delta_s = abs((right_time - left_time).total_seconds())
            if delta_s > 120:
                continue
            # Recent-file aliases do not necessarily retain a common token or
            # preserve the source filename's length. Temporal proximity alone
            # is sufficient to retain a candidate; the result remains
            # candidate_only and is never presented as authoritative.
            shorter, longer = left, right
            candidates.append(
                {
                    "original_name": _recent_lnk_base_name(shorter.get("file_name")),
                    "new_name": _recent_lnk_base_name(longer.get("file_name")),
                    "timestamp": max(_row_time_text(left), _row_time_text(right)),
                    "basis": "Windows Recent LNK files created/modified within 120 seconds with overlapping filename tokens",
                    "source_paths": [
                        _text(shorter.get("file_path")),
                        _text(longer.get("file_path")),
                    ],
                    "evidence_ids": [
                        _text(shorter.get("evidence_id")),
                        _text(longer.get("evidence_id")),
                    ],
                }
            )
    deduped = _dedupe_dict_rows(candidates, ("original_name", "new_name", "timestamp"))
    return sorted(
        deduped, key=lambda row: str(row.get("timestamp") or ""), reverse=True
    )[:50]


def _build_desktop_rename_candidates(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            json_extract_string(raw_json, '$.fn_filename') AS original_name,
            file_name AS new_name,
            file_path,
            si_modified,
            fn_modified,
            evidence_id
        FROM mft_entries
        WHERE (
            LOWER(COALESCE(file_path, '')) LIKE '%/desktop/%'
            OR LOWER(COALESCE(file_path, '')) LIKE '%\\desktop\\%'
        )
          AND json_extract_string(raw_json, '$.fn_filename') IS NOT NULL
          AND json_extract_string(raw_json, '$.fn_filename') != file_name
        ORDER BY COALESCE(fn_modified, si_modified) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    queries_run = ["structured:desktop_rename_candidates:mft_filename_pairs"]
    if not rows:
        recent_rows = _structured_rows(
            db,
            """
            SELECT
                file_name,
                file_path,
                si_created,
                si_modified,
                fn_created,
                fn_modified,
                evidence_id
            FROM mft_entries
            WHERE (
                LOWER(COALESCE(file_path, '')) LIKE '%/windows/recent/%'
                OR LOWER(COALESCE(file_path, '')) LIKE '%\\windows\\recent\\%'
            )
              AND LOWER(COALESCE(file_name, '')) LIKE '%.lnk'
            ORDER BY COALESCE(fn_created, si_created, fn_modified, si_modified) DESC NULLS LAST, file_name
            LIMIT 500
            """,
        )
        rows = _infer_recent_lnk_rename_candidates(recent_rows)
        queries_run.append(
            "structured:desktop_rename_candidates:recent_lnk_temporal_alias_pairs"
        )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "original_name",
            "new_name",
            "timestamp",
            "basis",
            "source_paths",
            "evidence_ids",
        ],
        queries_run=queries_run,
        # R7-07: Recent LNK temporal proximity is not actual rename evidence.
        # Mark as candidate_only to distinguish from confirmed renames.
        status="candidate_only"
        if rows
        and "structured:desktop_rename_candidates:recent_lnk_temporal_alias_pairs"
        in queries_run
        else ("partial" if rows else "not_found"),
        missing_reason=[]
        if not rows
        else [
            "MFT filename-pair evidence was not available; returned Recent LNK temporal alias candidates. "
            "These are candidate associations based on temporal proximity, not confirmed renames."
        ],
    )


@lru_cache(maxsize=1)
def _cloud_markers() -> dict[str, tuple[str, ...]]:
    return catalog_marker_map(
        "cloud_sync_artifacts",
        "service",
        "exe_patterns",
        "paths",
        "registry",
    )


def _build_cloud_service_traces(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    cloud_path_sql = _like_sql(
        "file_path", _catalog_path_patterns("cloud_sync_artifacts")
    )
    cloud_file_sql = _like_sql(
        "file_name",
        [
            *catalog_file_patterns(
                "cloud_sync_artifacts", "exe_patterns", "paths", "prefetch_names"
            )
        ],
    )
    cloud_prefetch_sql = exe_glob_sql(
        "executable_name", catalog_exe_globs("cloud_sync_artifacts")
    )
    mft_rows = _structured_rows(
        db,
        f"""
        SELECT
            file_name,
            file_path,
            is_deleted,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE {cloud_path_sql}
           OR {cloud_file_sql}
        ORDER BY si_modified DESC NULLS LAST, file_path
        LIMIT 200
        """,
    )
    prefetch_rows = _structured_rows(
        db,
        f"""
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE {cloud_prefetch_sql}
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        """,
    )
    rows: list[dict[str, Any]] = []
    for service_name, markers in _cloud_markers().items():
        service_mft = [
            row
            for row in mft_rows
            if any(marker in _lower_blob(row).replace("\\", "/") for marker in markers)
        ]
        service_prefetch = [
            row
            for row in prefetch_rows
            if any(marker in _lower_blob(row).replace("\\", "/") for marker in markers)
        ]
        if not service_mft and not service_prefetch:
            continue
        paths = [
            _text(row.get("file_path"))
            for row in service_mft
            if _text(row.get("file_path"))
        ]
        paths.extend(
            _text(row.get("source_file"))
            for row in service_prefetch
            if _text(row.get("source_file"))
        )
        evidence_ids = [
            _text(row.get("evidence_id"))
            for row in [*service_mft, *service_prefetch]
            if _text(row.get("evidence_id"))
        ]
        rows.append(
            {
                "service_name": service_name,
                "exe_found": "yes"
                if service_prefetch
                or any(
                    ".exe" in _lower_blob(row) or ".pf" in _lower_blob(row)
                    for row in service_mft
                )
                else "no",
                "paths_found": paths[:20],
                "config_found": "yes"
                if any(
                    marker in _lower_blob(row)
                    for row in service_mft
                    for marker in ("config", ".db", "snapshot")
                )
                else "no",
                "evidence_ids": evidence_ids[:20],
            }
        )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "service_name",
            "exe_found",
            "paths_found",
            "config_found",
            "evidence_ids",
        ],
        queries_run=[
            "structured:cloud_service_traces:mft_artifacts",
            "structured:cloud_service_traces:prefetch",
        ],
    )


def _build_antiforensic_activity(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    tool_globs = catalog_exe_globs("antiforensic_tools")
    tool_exe_sql = exe_glob_sql("executable_name", tool_globs)
    tool_file_sql = exe_glob_sql("file_name", tool_globs)
    artifact_name_sql = _like_sql(
        "file_name", catalog_artifact_names("antiforensic_tools")
    )
    prefetch_name_sql = _like_sql(
        "file_name", catalog_file_patterns("antiforensic_tools", "prefetch_names")
    )
    tool_markers = [
        markers[0]
        for markers in catalog_marker_map(
            "antiforensic_tools", "name", "exe_patterns", "artifact_names"
        ).values()
        if markers
    ]
    prefetch_path_sql = _like_sql(
        "file_path", [f"%prefetch%{marker}%" for marker in tool_markers]
    )
    event_rows = _structured_rows(
        db,
        f"""
        SELECT
            'log_integrity_event' AS evidence_type,
            timestamp,
            event_id,
            channel,
            computer,
            target_user,
            evidence_id,
            message
        FROM evtx_events
        WHERE {LOG_CLEAR_EVENT_SQL}
        ORDER BY timestamp DESC NULLS LAST
        LIMIT 100
        """,
    )
    prefetch_rows = _structured_rows(
        db,
        f"""
        SELECT
            'tool_execution' AS evidence_type,
            last_exec_time AS timestamp,
            executable_name AS file_name,
            source_file AS file_path,
            evidence_id
        FROM prefetch_executions
        WHERE {tool_exe_sql}
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        LIMIT 50
        """,
    )
    tool_rows = _structured_rows(
        db,
        f"""
        SELECT
            'tool_or_cleanup_artifact' AS evidence_type,
            file_name,
            file_path,
            is_deleted,
            si_created,
            si_modified,
            evidence_id
        FROM mft_entries
        WHERE (
              {artifact_name_sql}
           OR {prefetch_name_sql}
           OR {prefetch_path_sql}
           OR (
                ({tool_file_sql})
                AND (
                    LOWER(COALESCE(file_path, '')) LIKE '%/download/%'
                    OR LOWER(COALESCE(file_path, '')) LIKE '%\\download\\%'
                    OR LOWER(COALESCE(file_path, '')) LIKE '%/desktop/%'
                    OR LOWER(COALESCE(file_path, '')) LIKE '%\\desktop\\%'
                )
              )
        )
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'windows/system32/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'windows/syswow64/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'program files/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'program files (x86)/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%/lang/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%\\lang\\%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%/logs/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%\\logs\\%'
        ORDER BY COALESCE(si_modified, si_created) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    rows = event_rows + prefetch_rows + tool_rows
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "evidence_type",
            "timestamp",
            "event_id",
            "channel",
            "computer",
            "target_user",
            "file_name",
            "file_path",
            "is_deleted",
            "si_created",
            "si_modified",
            "evidence_id",
            "message",
        ],
        queries_run=[
            "structured:antiforensic_activity:event_log_clear_events",
            "structured:antiforensic_activity:prefetch_tool_execution",
            "structured:antiforensic_activity:tool_artifacts",
        ],
    )
