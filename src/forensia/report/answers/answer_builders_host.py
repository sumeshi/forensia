"""Structured answer builders: host identity, logon, session activity."""

from __future__ import annotations

import logging
from typing import Any

from forensia.core.case import Case, detect_epochs
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.catalog import (
    load_event_class_definitions as _load_event_class_definitions,
)
from forensia.knowledge.questions import (
    extract_time_qualifiers,
)
from forensia.report.answers.answer_store import (
    _dedupe_dict_rows,
    _human_user_predicate,
    _is_local_ingest_path,
    _prefetch_executable_from_filename,
    _sanitize_prefetch_path,
    _strip_path_basename,
    _structured_answer,
    _structured_rows,
    _text,
)
from forensia.report.render.markdown import (
    _build_host_note,
)

logger = logging.getLogger(__name__)

# ── Builder functions for deterministic structured answers ──────────────────


def _build_host_identity(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        WITH raw AS (
          SELECT
              computer,
              COUNT(*) AS evidence_count,
              MIN(timestamp) AS first_seen,
              MAX(timestamp) AS last_seen
          FROM evtx_events
          WHERE computer IS NOT NULL AND TRIM(computer) <> ''
          GROUP BY computer
        )
        SELECT
            ARG_MAX(computer, evidence_count) AS host_id,
            SUM(evidence_count) AS evidence_count,
            MIN(first_seen) AS first_seen,
            MAX(last_seen) AS last_seen
        FROM raw
        GROUP BY UPPER(TRIM(computer))
        ORDER BY evidence_count DESC, host_id
        """,
    )
    rows = _dedupe_dict_rows(rows, ("host_id",))
    try:
        epochs = detect_epochs(db)
        for row in rows:
            host_key = str(row.get("host_id") or "").strip().upper()
            host_epochs = epochs.get(host_key) or []
            if host_epochs:
                row["note"] = _build_host_note(host_epochs)
    except Exception:
        logger.debug("Failed to attach epoch notes to host rows", exc_info=True)
    columns = (
        ["host_id", "note", "evidence_count", "first_seen", "last_seen"]
        if any("note" in r for r in rows)
        else ["host_id", "evidence_count", "first_seen", "last_seen"]
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=columns,
        queries_run=["structured:host_identity:evtx_distinct_hosts"],
    )


def _build_last_human_logon(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    interactive_rows = _structured_rows(
        db,
        f"""
        SELECT
            timestamp AS logon_time,
            computer,
            target_user AS user_name,
            logon_type,
            process_name,
            src_ip,
            evidence_id
        FROM evtx_events
        WHERE event_id = 4624
          AND {_human_user_predicate("target_user")}
          AND CAST(COALESCE(logon_type, '') AS VARCHAR) IN ('2', '7', '10', '11')
        ORDER BY timestamp DESC
        LIMIT 1
        """,
    )
    if interactive_rows:
        rows = interactive_rows
        status = "answered"
        missing: list[str] = []
        label = "structured:last_human_logon:last_interactive_user_logon"
    else:
        rows = _structured_rows(
            db,
            f"""
            SELECT
                timestamp AS logon_time,
                computer,
                target_user AS user_name,
                logon_type,
                process_name,
                src_ip,
                evidence_id
            FROM evtx_events
            WHERE event_id = 4624
              AND {_human_user_predicate("target_user")}
            ORDER BY timestamp DESC
            LIMIT 1
            """,
        )
        status = "partial" if rows else "not_found"
        missing = [] if rows else ["No human-user 4624 logon events were found."]
        if rows:
            missing = [
                "No interactive logon type was found; returned the latest human-user 4624 logon event."
            ]
        label = "structured:last_human_logon:last_human_user_logon_fallback"
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "logon_time",
            "computer",
            "user_name",
            "logon_type",
            "process_name",
            "src_ip",
            "evidence_id",
        ],
        queries_run=[label],
        status=status,
        missing_reason=missing,
    )


def _build_last_shutdown_event(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            timestamp AS shutdown_time,
            event_id,
            computer,
            evidence_id,
            message
        FROM evtx_events
        WHERE (event_id = 1074)
           OR (event_id IN (6006, 6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
        ORDER BY timestamp DESC
        LIMIT 1
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["shutdown_time", "event_id", "computer", "evidence_id", "message"],
        queries_run=["structured:last_shutdown_event:1074_6006_6008"],
    )


def _build_application_execution_history(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            executable_name,
            SUM(exec_count) AS exec_count,
            MAX(last_exec_time) AS last_exec_time,
            COUNT(*) AS prefetch_records,
            MIN(COALESCE(
              (SELECT MIN(x.executable_path)
               FROM (SELECT UNNEST(TRY_CAST(filenames AS VARCHAR[])) AS executable_path) x
               WHERE x.executable_path LIKE '%' || UPPER(executable_name)),
              NULL
            )) AS executable_path,
            MIN(source_file) AS prefetch_file
        FROM prefetch_executions
        WHERE executable_name IS NOT NULL AND TRIM(executable_name) <> ''
        GROUP BY executable_name
        ORDER BY last_exec_time DESC NULLS LAST
        LIMIT 200
        """,
    )
    if rows:
        # Sanitise paths so raw local ingest artefact paths never leak into output
        for row in rows:
            row["executable_path"] = _sanitize_prefetch_path(row.get("executable_path"))
            row["prefetch_file"] = _strip_path_basename(row.get("prefetch_file"))
        return _structured_answer(
            case,
            answer_id=answer_id,
            section_key=section_key,
            block_heading=block_heading,
            rows=rows,
            columns=[
                "executable_name",
                "exec_count",
                "last_exec_time",
                "prefetch_records",
                "executable_path",
                "prefetch_file",
            ],
            queries_run=[
                "structured:application_execution_history:prefetch_executions"
            ],
        )

    mft_rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(extension, '')) = 'pf'
           OR LOWER(COALESCE(file_name, '')) LIKE '%.pf'
        ORDER BY si_modified DESC NULLS LAST, file_name
        LIMIT 200
        """,
    )
    rows = [
        {
            "executable_name": _prefetch_executable_from_filename(row.get("file_name")),
            "exec_count": "",
            "last_exec_time": "",
            "prefetch_records": "",
            "executable_path": (
                ""
                if _is_local_ingest_path(row.get("file_path"))
                else _text(row.get("file_path"))
            ),
            "prefetch_file": _strip_path_basename(row.get("file_name")),
            "artifact_time": row.get("artifact_time"),
            "artifact_path": row.get("file_path"),
            "evidence_id": row.get("evidence_id"),
        }
        for row in mft_rows
    ]
    rows = [row for row in rows if _text(row.get("executable_name"))]
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "executable_name",
            "exec_count",
            "last_exec_time",
            "prefetch_records",
            "executable_path",
            "prefetch_file",
            "artifact_time",
            "artifact_path",
            "evidence_id",
        ],
        queries_run=[
            "structured:application_execution_history:mft_prefetch_file_fallback"
        ],
        status="partial" if rows else "not_found",
        missing_reason=[]
        if not rows
        else [
            "prefetch_executions was empty; returned MFT Prefetch files without execution counts."
        ],
    )


def _build_daily_session_activity(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
            SUM(CASE WHEN event_id IN (6005, 4608) THEN 1 ELSE 0 END) AS startup,
            SUM(CASE WHEN event_id = 4624 THEN 1 ELSE 0 END) AS logons,
            SUM(CASE WHEN event_id IN (4634, 4647) THEN 1 ELSE 0 END) AS logoff,
            SUM(CASE WHEN event_id IN (1074, 6006, 6008) THEN 1 ELSE 0 END) AS shutdown
        FROM evtx_events
        WHERE timestamp IS NOT NULL
          AND (
            event_id IN (4608, 4624, 4634, 4647, 1074)
            OR (event_id IN (6005, 6006, 6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
          )
        GROUP BY CAST(timestamp AS DATE)
        ORDER BY CAST(timestamp AS DATE)
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["date", "startup", "logons", "logoff", "shutdown"],
        queries_run=["structured:daily_session_activity:startup_logon_logoff_shutdown"],
    )


def _build_daily_session_timeline_rows(
    db: CaseDB,
    qualifiers: dict[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    classes = _load_event_class_definitions()
    startup_ids = tuple(classes.get("startup", {}).get("event_ids", [6005, 12]))
    shutdown_ids = tuple(classes.get("shutdown", {}).get("event_ids", [6006, 13, 1074]))
    logon_ids = tuple(classes.get("logon", {}).get("event_ids", [4624]))
    logon_types = tuple(classes.get("logon", {}).get("logon_types", [2, 10, 11]))
    logoff_ids = tuple(classes.get("logoff", {}).get("event_ids", [4634, 4647]))

    all_event_ids = sorted(set(startup_ids + shutdown_ids + logon_ids + logoff_ids))
    if not all_event_ids:
        return []

    id_list = ", ".join(str(eid) for eid in all_event_ids)
    startup_list = ", ".join(str(e) for e in startup_ids)
    shutdown_list = ", ".join(str(e) for e in shutdown_ids)
    logon_id_list = ", ".join(str(eid) for eid in logon_ids)
    logon_type_list = ", ".join(str(lt) for lt in logon_types)
    logoff_list = ", ".join(str(e) for e in logoff_ids)

    hour_filter = ""
    qual = qualifiers or {}
    hour_from = qual.get("hour_from")
    hour_to = qual.get("hour_to")
    if hour_from and hour_to:
        hour_filter = (
            f"  AND CAST(STRFTIME(timestamp, '%H:%M') AS VARCHAR) >= '{hour_from}'\n"
            f"  AND CAST(STRFTIME(timestamp, '%H:%M') AS VARCHAR) <= '{hour_to}'\n"
        )

    sql = f"""
    WITH sessions AS (
        SELECT
            CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
            timestamp,
            event_id,
            logon_type,
            target_user,
            evidence_id
        FROM evtx_events
        WHERE event_id IN ({id_list})
          AND timestamp IS NOT NULL
{hour_filter}
    ),
    daily_agg AS (
        SELECT
            date,
            MIN(CASE WHEN event_id IN ({startup_list}) THEN timestamp END) AS first_startup,
            MIN(CASE WHEN event_id IN ({logon_id_list}) AND logon_type IN ({logon_type_list}) THEN timestamp END) AS first_logon,
            MAX(CASE WHEN event_id IN ({logoff_list}) THEN timestamp END) AS last_logoff,
            MAX(CASE WHEN event_id IN ({shutdown_list}) THEN timestamp END) AS last_shutdown,
            LIST(DISTINCT evidence_id) FILTER (WHERE evidence_id IS NOT NULL) AS evidence_ids,
            LIST(
                CAST(timestamp AS VARCHAR) || ' event_id=' || CAST(event_id AS VARCHAR)
                || ' user=' || COALESCE(target_user, '')
                || ' evidence_id=' || COALESCE(evidence_id, '')
                ORDER BY timestamp
            ) AS event_trace
        FROM sessions
        GROUP BY date
    ),
    daily_logon_users AS (
        SELECT
            date,
            LIST(DISTINCT target_user) FILTER (WHERE target_user IS NOT NULL AND TRIM(target_user) <> '') AS logon_users_raw,
            COUNT(*) FILTER (WHERE target_user IS NOT NULL AND TRIM(target_user) <> '') AS interactive_logon_count
        FROM sessions
        WHERE event_id IN ({logon_id_list})
          AND logon_type IN ({logon_type_list})
        GROUP BY date
    )
    SELECT
        d.date,
        d.first_startup,
        d.first_logon,
        d.last_logoff,
        d.last_shutdown,
        CASE
            WHEN LEN(u.logon_users_raw) > 5
            THEN u.logon_users_raw[1:5]
            ELSE u.logon_users_raw
        END AS logon_users,
        u.interactive_logon_count
    FROM daily_agg d
    LEFT JOIN daily_logon_users u ON d.date = u.date
    ORDER BY d.date

    """

    try:
        rows = fetch_records(db, sql)
    except Exception:
        return []

    result: list[dict[str, Any]] = []
    for row in rows:
        entry: dict[str, Any] = {
            "date": str(row.get("date") or ""),
            "first_startup": str(row.get("first_startup") or ""),
            "first_logon": str(row.get("first_logon") or ""),
            "last_logoff": str(row.get("last_logoff") or ""),
            "last_shutdown": str(row.get("last_shutdown") or ""),
            "logon_users": "",
            "interactive_logon_count": int(row.get("interactive_logon_count") or 0),
            "evidence_ids": [
                str(item) for item in (row.get("evidence_ids") or []) if item
            ],
            "event_trace": [str(item) for item in (row.get("event_trace") or [])],
        }
        raw_users = row.get("logon_users")
        if isinstance(raw_users, list):
            entry["logon_users"] = ", ".join(str(u) for u in raw_users if u)
        result.append(entry)
    return result


def _build_daily_session_timeline(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    # Evidence timestamps are normalized to naive UTC at ingest. The rendered
    # answer carries the case timezone, but SQL filtering must use UTC values.
    qualifiers = extract_time_qualifiers(block_heading, "UTC")
    rows = _build_daily_session_timeline_rows(db, qualifiers)
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "date",
            "first_startup",
            "first_logon",
            "last_logoff",
            "last_shutdown",
            "logon_users",
            "interactive_logon_count",
            "event_trace",
            "evidence_ids",
        ],
        queries_run=["structured:daily_session_timeline:per_day_session_timeline"],
    )
