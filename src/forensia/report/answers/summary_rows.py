"""Row sources for report summary tables: scope, timeline, execution."""

from __future__ import annotations

from typing import Any

from forensia.core.case import detect_epochs
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.catalog import (
    catalog_artifact_names,
    catalog_exe_globs,
    catalog_names,
    catalog_path_terms,
    exe_glob_sql,
    matches_exe_globs,
)
from forensia.report.answers.answer_store import (
    _dedupe_dict_rows,
)
from forensia.report.answers.event_semantics import LOG_CLEAR_EVENT_SQL
from forensia.report.evidence_refs import (
    _sql_like_any,
)
from forensia.report.render.markdown import (
    _build_host_note,
)
from forensia.report.report_brief import (
    _query_evtx_time_range,
    _short_path_context,
)


def _count_table(db: CaseDB) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT
          (SELECT COUNT(*) FROM evtx_events) AS evtx_events,
          (SELECT COUNT(*) FROM mft_entries) AS mft_entries,
          (SELECT COUNT(*) FROM prefetch_executions) AS prefetch_executions,
          (SELECT COUNT(DISTINCT UPPER(TRIM(computer))) FROM evtx_events WHERE COALESCE(computer, '') != '') AS hosts,
          (SELECT COUNT(DISTINCT channel) FROM evtx_events WHERE COALESCE(channel, '') != '') AS channels
        """,
    )
    if not rows:
        return []
    row = rows[0]
    time_range = _query_evtx_time_range(db)
    return [
        {
            "metric": "EVTX events",
            "value": row.get("evtx_events"),
            "scope": f"{time_range.get('first_event', 'unknown')} to {time_range.get('last_event', 'unknown')}",
        },
        {
            "metric": "MFT entries",
            "value": row.get("mft_entries"),
            "scope": "Filesystem metadata",
        },
        {
            "metric": "Prefetch executions",
            "value": row.get("prefetch_executions"),
            "scope": "Application execution artifacts",
        },
        {
            "metric": "Hosts",
            "value": row.get("hosts"),
            "scope": "Distinct EVTX computer names",
        },
        {
            "metric": "EVTX channels",
            "value": row.get("channels"),
            "scope": "Distinct channels",
        },
    ]


def _host_summary_rows(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        WITH raw AS (
          SELECT computer, COUNT(*) AS cnt, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
          FROM evtx_events
          WHERE COALESCE(computer, '') != ''
          GROUP BY computer
        )
        SELECT
          ARG_MAX(computer, cnt) AS host,
          SUM(cnt) AS events,
          MIN(first_seen) AS first_seen,
          MAX(last_seen) AS last_seen
        FROM raw
        GROUP BY UPPER(TRIM(computer))
        ORDER BY events DESC
        LIMIT ?
        """,
        (limit,),
    )
    # Annotate each row with pre-deployment note when applicable
    try:
        epochs = detect_epochs(db)
        for row in rows:
            host_key = str(row.get("host") or "").strip().upper()
            host_epochs = epochs.get(host_key) or []
            if host_epochs:
                row["note"] = _build_host_note(host_epochs)
        # Only keep note when at least one host is pre-deployment
        if not any(
            r.get("note") == "pre-deployment"
            or "pre-deployment" in (r.get("note") or "")
            for r in rows
        ):
            for row in rows:
                row.pop("note", None)
    except Exception:
        pass
    return rows


def _account_summary_rows(db: CaseDB, limit: int = 10) -> list[dict[str, Any]]:
    """Per-account/host authentication summary.

    RPT-09: 4625 (failed logon) rows commonly have a NULL actor (the target
    account could not be resolved); these are kept as account='-' instead of
    being dropped, so failed-logon totals are visible. Hosts are grouped
    case-insensitively (UPPER(TRIM(computer))) since the same host can appear
    with mixed case across event sources.
    """
    return fetch_records(
        db,
        """
        SELECT
          COALESCE(NULLIF(target_user, ''), NULLIF(user_name, ''), NULLIF(subject_user, ''), '-') AS account,
          ANY_VALUE(computer) AS computer,
          COUNT(*) FILTER (WHERE event_id = 4624) AS logons,
          COUNT(*) FILTER (WHERE event_id = 4625) AS failed_logons,
          COUNT(*) FILTER (WHERE event_id = 4648) AS explicit_credential_events,
          MIN(timestamp) AS first_seen,
          MAX(timestamp) AS last_seen
        FROM evtx_events
        WHERE event_id IN (4624, 4625, 4648)
        GROUP BY account, UPPER(TRIM(COALESCE(computer, '')))
        ORDER BY explicit_credential_events DESC, failed_logons DESC, logons DESC
        LIMIT ?
        """,
        (limit,),
    )


def _event_interpretation(event_id: Any) -> str:
    try:
        event = int(event_id)
    except TypeError, ValueError:
        return "Event"
    return {
        4624: "Successful logon",
        4625: "Failed logon",
        4648: "Explicit credentials",
        1100: "Event log service stopped",
        104: "Event log cleared",
        1074: "Shutdown/restart initiated",
        6006: "Event log service stopped",
    }.get(event, f"Event {event}")


def _timeline_rows(db: CaseDB, limit: int = 18) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    evtx_rows = fetch_records(
        db,
        """
        SELECT timestamp, computer, event_id,
               COALESCE(NULLIF(target_user, ''), NULLIF(user_name, ''), NULLIF(subject_user, ''), '-') AS actor,
               COALESCE(NULLIF(process_name, ''), NULLIF(service_name, ''), '-') AS object,
               evidence_id
        FROM evtx_events
        WHERE (
            (event_id IN (1074))
            OR (event_id = 1100 AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
            OR (event_id = 6006 AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            OR (event_id IN (4648, 4625) AND LOWER(COALESCE(channel, '')) LIKE '%security%')
            OR (event_id = 104 AND LOWER(COALESCE(channel, '')) LIKE '%eventlog%')
        )
        ORDER BY timestamp
        LIMIT 80
        """,
    )
    for row in evtx_rows:
        rows.append(
            {
                "time": row.get("timestamp"),
                "host": row.get("computer"),
                "activity": _event_interpretation(row.get("event_id")),
                "subject": row.get("actor"),
                "artifact": row.get("object"),
                "evidence_id": row.get("evidence_id"),
            }
        )
    notable_exe_sql = exe_glob_sql(
        "executable_name",
        catalog_exe_globs(
            "antiforensic_tools",
            "cloud_sync_artifacts",
            "browser_artifacts",
            "email_artifacts",
        ),
    )
    prefetch_rows = fetch_records(
        db,
        f"""
        SELECT last_exec_time AS timestamp, executable_name, exec_count, evidence_id
        FROM prefetch_executions
        WHERE {notable_exe_sql}
        ORDER BY last_exec_time DESC
        LIMIT 12
        """,
    )
    for row in prefetch_rows:
        rows.append(
            {
                "time": row.get("timestamp"),
                "host": "-",
                "activity": "Application execution",
                "subject": row.get("executable_name"),
                "artifact": f"exec_count={row.get('exec_count')}",
                "evidence_id": row.get("evidence_id"),
            }
        )
    rows = sorted(rows, key=lambda item: str(item.get("time") or ""))
    if len(rows) > limit:
        early_count = max(4, limit // 3)
        late_count = max(limit - early_count, 0)
        rows = sorted(
            [*rows[:early_count], *rows[-late_count:]],
            key=lambda item: str(item.get("time") or ""),
        )
    return rows


def _execution_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT executable_name, exec_count, last_exec_time, evidence_id, source_file
        FROM prefetch_executions
        WHERE UPPER(executable_name) NOT IN (
          'DLLHOST.EXE', 'CONHOST.EXE', 'AUDIODG.EXE', 'SEARCHFILTERHOST.EXE',
          'SEARCHPROTOCOLHOST.EXE', 'WMIPRVSE.EXE'
        )
        ORDER BY last_exec_time DESC
        LIMIT ?
        """,
        (max(limit * 4, 48),),
    )
    # One row per executable name: prefetch keeps one record per .pf file,
    # which rendered duplicates (e.g. IEXPLORE.EXE twice).
    aggregated: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = str(row.get("executable_name") or "")
        existing = aggregated.get(name)
        if existing is None:
            aggregated[name] = dict(row)
            continue
        existing["exec_count"] = int(existing.get("exec_count") or 0) + int(
            row.get("exec_count") or 0
        )
        if str(row.get("last_exec_time") or "") > str(
            existing.get("last_exec_time") or ""
        ):
            existing["last_exec_time"] = row.get("last_exec_time")
    rows = list(aggregated.values())

    antiforensic_globs = catalog_exe_globs("antiforensic_tools")
    user_app_globs = catalog_exe_globs(
        "cloud_sync_artifacts", "browser_artifacts", "email_artifacts"
    )

    def _rank(row: dict[str, Any]) -> int:
        name = str(row.get("executable_name") or "")
        if matches_exe_globs(name, antiforensic_globs):
            return 0
        if matches_exe_globs(name, user_app_globs):
            return 1
        return 2

    # Rank ascending; within a rank keep most-recent first (stable sorts).
    rows.sort(key=lambda row: str(row.get("last_exec_time") or ""), reverse=True)
    rows.sort(key=_rank)
    # Map DB column names to schema column keys for table rendering.
    return [
        {
            "executable": r.get("executable_name"),
            "execution_count": r.get("exec_count"),
            "last_execution": r.get("last_exec_time"),
            "evidence_id": r.get("evidence_id"),
        }
        for r in rows[:limit]
    ]


def _file_artifact_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    """Notable user-data file artifacts: mail data, cloud sync state, cleanup tools.

    Path families come from the IOC catalog and the user's Recent folder —
    no case-specific filename keywords (Rule 16).
    """
    path_terms = catalog_path_terms(
        "email_artifacts", "cloud_sync_artifacts", "antiforensic_tools"
    )
    tool_globs = catalog_exe_globs("antiforensic_tools")
    path_sql = (
        _sql_like_any("file_path", *[f"%{term}%" for term in path_terms])
        if path_terms
        else "FALSE"
    )
    tool_name_sql = exe_glob_sql("file_name", tool_globs)
    recent_lnk_sql = "(LOWER(COALESCE(file_path, '')) LIKE '%/recent/%' AND LOWER(COALESCE(file_name, '')) LIKE '%.lnk')"
    return fetch_records(
        db,
        f"""
        SELECT file_name, file_path,
               COALESCE(si_modified, si_created, fn_modified, fn_created) AS timestamp,
               evidence_id
        FROM mft_entries
        WHERE ({path_sql} OR {tool_name_sql} OR {recent_lnk_sql})
          AND COALESCE(is_directory, FALSE) = FALSE
          AND LENGTH(COALESCE(file_name, '')) > 3
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    )


def _antiforensic_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    tool_globs = catalog_exe_globs("antiforensic_tools")
    tool_exe_sql = exe_glob_sql("executable_name", tool_globs)
    tool_file_sql = exe_glob_sql("file_name", tool_globs)
    artifact_names = catalog_artifact_names("antiforensic_tools")
    artifact_name_sql = (
        _sql_like_any("file_name", *artifact_names) if artifact_names else "FALSE"
    )
    tool_name_terms = [name.lower() for name in catalog_names("antiforensic_tools")]
    prefetch_path_sql = (
        _sql_like_any("file_path", *[f"%prefetch%{term}%" for term in tool_name_terms])
        if tool_name_terms
        else "FALSE"
    )
    rows: list[dict[str, Any]] = []
    for row in fetch_records(
        db,
        f"""
        SELECT last_exec_time AS timestamp, executable_name AS artifact, exec_count, evidence_id, source_file
        FROM prefetch_executions
        WHERE {tool_exe_sql}
        ORDER BY last_exec_time DESC
        LIMIT 6
        """,
    ):
        rows.append(
            {
                "type": "tool execution",
                "context": _short_path_context(row.get("source_file")),
                **row,
            }
        )
    for row in fetch_records(
        db,
        f"""
        SELECT timestamp, CAST(event_id AS VARCHAR) AS artifact, computer, evidence_id
        FROM evtx_events
        WHERE {LOG_CLEAR_EVENT_SQL}
        ORDER BY timestamp DESC
        LIMIT 6
        """,
    ):
        rows.append(
            {
                "type": "log integrity event",
                "context": str(row.get("computer") or ""),
                **row,
            }
        )
    artifact_rows: list[dict[str, Any]] = []
    for row in fetch_records(
        db,
        f"""
        SELECT COALESCE(si_modified, si_created, fn_modified, fn_created) AS timestamp,
               file_name AS artifact, file_path, evidence_id
        FROM mft_entries
        WHERE ({tool_file_sql} OR {artifact_name_sql} OR {prefetch_path_sql})
          AND LOWER(COALESCE(file_name, '')) NOT IN ('lang', 'logs')
        ORDER BY timestamp DESC
        LIMIT 6
        """,
    ):
        artifact_rows.append(
            {
                "type": "tool artifact",
                "context": _short_path_context(row.get("file_path")),
                **row,
            }
        )
    # The MFT commonly carries multiple records for one file (e.g. 8.3 short
    # name or duplicate attribute records); one on-disk artifact should appear
    # as one row, not inflate the count.
    rows.extend(_dedupe_dict_rows(artifact_rows, ("artifact", "file_path")))
    return sorted(
        rows, key=lambda item: str(item.get("timestamp") or ""), reverse=True
    )[:limit]


def _network_summary_rows(db: CaseDB) -> list[dict[str, Any]]:
    row = db.execute(
        """
        SELECT
          COUNT(*) FILTER (WHERE COALESCE(src_ip, '') NOT IN ('', '-', '127.0.0.1', '::1')) AS external_src_ip_rows,
          COUNT(*) FILTER (WHERE COALESCE(dst_ip, '') NOT IN ('', '-', '127.0.0.1', '::1')) AS external_dst_ip_rows,
          COUNT(*) FILTER (WHERE COALESCE(src_ip, '') != '' OR COALESCE(dst_ip, '') != '') AS rows_with_ip
        FROM evtx_events
        """
    ).fetchone()
    if not row:
        return []
    return [
        {
            "area": "Network indicators in normalized EVTX",
            "ip_address": "aggregate",
            "outbound_rows": int(row[0] or 0),
            "inbound_rows": int(row[1] or 0),
            "interpretation": "No strong external network row was normalized"
            if not (row[0] or row[1])
            else "Review rows with non-loopback IP values",
        }
    ]


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except TypeError, ValueError:
        return 0


def _timeline_phase_rows(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    evtx_rows = fetch_records(
        db,
        f"""
        SELECT
          CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
          COUNT(*) FILTER (WHERE event_id = 4648) AS explicit_credentials,
          COUNT(*) FILTER (WHERE {LOG_CLEAR_EVENT_SQL}) AS log_integrity_events,
          COUNT(*) FILTER (WHERE event_id IN (1074, 6006, 6008)
            AND NOT (event_id = 6006 AND channel NOT ILIKE '%System%')
            AND NOT (event_id = 6008 AND channel NOT ILIKE '%System%')
          ) AS shutdown_events,
          MIN(timestamp) AS first_seen,
          MAX(timestamp) AS last_seen
        FROM evtx_events
        WHERE timestamp IS NOT NULL
          AND event_id IN (4648, 104, 1102, 1074, 6006, 6008)
          AND NOT (event_id = 6006 AND channel NOT ILIKE '%System%')
          AND NOT (event_id = 6008 AND channel NOT ILIKE '%System%')
        GROUP BY CAST(timestamp AS DATE)
        ORDER BY CAST(timestamp AS DATE)
        """,
    )
    notable_exe_sql = exe_glob_sql(
        "executable_name",
        catalog_exe_globs(
            "antiforensic_tools",
            "cloud_sync_artifacts",
            "browser_artifacts",
            "email_artifacts",
        ),
    )
    exec_rows = fetch_records(
        db,
        f"""
        SELECT
          CAST(CAST(last_exec_time AS DATE) AS VARCHAR) AS date,
          COUNT(*) AS executions,
          string_agg(DISTINCT executable_name, ', ' ORDER BY executable_name) AS executables
        FROM prefetch_executions
        WHERE last_exec_time IS NOT NULL
          AND {notable_exe_sql}
        GROUP BY CAST(last_exec_time AS DATE)
        ORDER BY CAST(last_exec_time AS DATE)
        """,
    )
    by_date: dict[str, dict[str, Any]] = {}
    for row in evtx_rows:
        date = str(row.get("date") or "")
        if date:
            by_date.setdefault(date, {"date": date}).update(row)
    for row in exec_rows:
        date = str(row.get("date") or "")
        if date:
            by_date.setdefault(date, {"date": date}).update(row)

    phases: list[dict[str, Any]] = []
    for date in sorted(by_date):
        row = by_date[date]
        points: list[str] = []
        if _as_int(row.get("explicit_credentials")):
            points.append(
                f"{_as_int(row.get('explicit_credentials'))} explicit-credential logon events (4648)"
            )
        if _as_int(row.get("log_integrity_events")):
            points.append(
                f"{_as_int(row.get('log_integrity_events'))} log integrity events"
            )
        if _as_int(row.get("shutdown_events")):
            points.append(
                f"{_as_int(row.get('shutdown_events'))} shutdown/log-stop events"
            )
        if _as_int(row.get("executions")):
            executables = str(row.get("executables") or "").strip()
            points.append(
                f"Notable application executions: {executables}"
                if executables
                else "Notable application executions detected"
            )
        if not points:
            continue
        phases.append(
            {
                "date": date,
                "phase": " / ".join(points),
                "interpretation": _phase_interpretation(row),
                "window": f"{row.get('first_seen') or '-'} to {row.get('last_seen') or '-'}",
            }
        )
    return phases[:limit]


def _phase_interpretation(row: dict[str, Any]) -> str:
    executables = [
        item.strip()
        for item in str(row.get("executables") or "").split(",")
        if item.strip()
    ]
    tool_globs = catalog_exe_globs("antiforensic_tools")
    cloud_globs = catalog_exe_globs("cloud_sync_artifacts")
    has_tools = any(matches_exe_globs(name, tool_globs) for name in executables)
    has_cloud = any(matches_exe_globs(name, cloud_globs) for name in executables)
    if has_tools and _as_int(row.get("log_integrity_events")):
        return "Cleaning tools and log integrity events on the same day; prioritize anti-forensic hypothesis"
    if has_cloud and has_tools:
        return "Cloud sync traces and cleaning tools on the same day; check for post-exfiltration wiping"
    if _as_int(row.get("explicit_credentials")):
        return "Explicit credential usage detected; check relationship with standard logons per user"
    if _as_int(row.get("log_integrity_events")):
        return "Log stop/clear candidates detected; check the actor and surrounding events at the same time"
    return "Notable events clustered on this day; correlate with surrounding file and execution traces"


antiforensic_rows = _antiforensic_rows
execution_rows = _execution_rows
host_summary_rows = _host_summary_rows
