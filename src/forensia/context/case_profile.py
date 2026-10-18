"""Session-owned projection of currently available case evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensia.knowledge.catalog import event_context_eligible, event_context_from_row


@dataclass(frozen=True)
class CaseEvidenceProfile:
    """Session-owned projection of the case's evidence availability.

    ``event_ids=None`` means "availability not computed" (unknown); an empty
    set means "availability computed and the case has zero EVTX event IDs"
    (e.g. an MFT-only case). Callers such as the drafter event-ID filter and
    the untestable detector rely on that distinction.
    """

    event_ids: frozenset[int] | None = None
    summary: str = ""


def observed_event_ids(db) -> set[int]:
    """Read current availability from this case, including the empty-case result."""
    return {
        int(row[0])
        for row in db.execute(
            "SELECT DISTINCT event_id FROM evtx_events WHERE event_id IS NOT NULL"
        ).fetchall()
    }


def observed_event_contexts(db, event_ids: frozenset[int]) -> list[dict[str, Any]]:
    """Project distinct observed event contexts eligible under the event catalog."""
    if not event_ids:
        return []
    rows = db.execute(
        "SELECT DISTINCT event_id, "
        "COALESCE(channel, json_extract_string(raw_json, '$.winlog.channel')) AS channel, "
        "COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), "
        "json_extract_string(raw_json, '$.winlog.provider')) AS provider "
        "FROM evtx_events "
        "WHERE event_id IN (SELECT UNNEST(?))",
        [sorted(event_ids)],
    ).fetchall()
    available: set[tuple[int, str, str]] = set()
    for event_id, channel, provider in rows:
        channel, provider = event_context_from_row(
            {"channel": channel, "provider": provider}
        )
        if (
            channel
            and provider
            and event_context_eligible(event_id, channel=channel, provider=provider)
        ):
            available.add((int(event_id), channel, provider))
    return [
        {"event_id": event_id, "channel": channel, "provider": provider}
        for event_id, channel, provider in sorted(available)
    ]


def _build_profile_queries(conn) -> dict[str, Any]:
    evtx_event_ids: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT event_id, COUNT(*) AS cnt FROM evtx_events GROUP BY event_id ORDER BY cnt DESC"
    ).fetchall()
    evtx_event_ids = [
        {"event_id": r[0], "count": r[1]} for r in rows if r[0] is not None
    ]
    channels: list[dict[str, Any]] = []
    rows = conn.execute(
        "SELECT channel, COUNT(*) AS cnt FROM evtx_events GROUP BY channel ORDER BY cnt DESC"
    ).fetchall()
    channels = [{"channel": r[0], "count": r[1]} for r in rows if r[0] is not None]
    table_row_counts: dict[str, int] = {}
    for tbl in (
        "evtx_events",
        "mft_entries",
        "mft_timeline",
        "prefetch_executions",
        "prefetch_timeline",
        "registry_artifacts",
    ):
        row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
        table_row_counts[tbl] = row[0] if row and row[0] is not None else 0
    top_users: list[str] = []
    rows = conn.execute(
        "SELECT COALESCE(target_user, user_name) AS u, COUNT(*) AS cnt FROM evtx_events WHERE COALESCE(target_user, user_name) IS NOT NULL GROUP BY u ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    top_users = [str(r[0]) for r in rows]
    top_hosts: list[str] = []
    rows = conn.execute(
        "WITH raw AS (  SELECT computer, COUNT(*) AS cnt FROM evtx_events   WHERE computer IS NOT NULL GROUP BY computer) SELECT ARG_MAX(computer, cnt) AS computer, SUM(cnt) AS cnt FROM raw GROUP BY UPPER(TRIM(computer)) ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    top_hosts = [str(r[0]) for r in rows]
    top_executables: list[str] = []
    rows = conn.execute(
        "SELECT COALESCE(process_name, child_process) AS exe, COUNT(*) AS cnt FROM evtx_events WHERE COALESCE(process_name, child_process) IS NOT NULL GROUP BY exe ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    top_executables = [str(r[0]) for r in rows]
    time_range: dict[str, str] = {}
    row = conn.execute(
        "SELECT MIN(timestamp) AS earliest, MAX(timestamp) AS latest FROM evtx_events"
    ).fetchone()
    if row:
        time_range["earliest"] = str(row[0] or "") if row[0] is not None else ""
        time_range["latest"] = str(row[1] or "") if row[1] is not None else ""
    return {
        "event_ids": evtx_event_ids,
        "channels": channels,
        "table_row_counts": table_row_counts,
        "top_users": top_users,
        "top_hosts": top_hosts,
        "top_executables": top_executables,
        "time_range": time_range,
    }


def build_case_profile(db) -> dict[str, Any]:
    """Build a case evidence-availability profile using pure SQL queries.

    Uses the already-open CaseDB connection (opening a second connection to the
    same DuckDB file risks lock conflicts). Rebuild from current data so a
    later ingest or rerun cannot reuse a stale process-wide profile.
    """
    return _build_profile_queries(db)


def _format_case_profile(profile: dict[str, Any]) -> str:
    """Format the profile dict as a compact string of <=1200 characters.

    Designed for injection into LLM system prompts to guide hypothesis
    drafting and query planning.
    """
    parts: list[str] = []

    event_ids = profile.get("event_ids", [])
    if event_ids:
        id_list = ", ".join(str(e["event_id"]) for e in event_ids[:30])
        parts.append(f"Available event_ids ({len(event_ids)}): [{id_list}]")

    channels = profile.get("channels", [])
    if channels:
        ch_list = ", ".join(f"{c['channel']}({c['count']})" for c in channels[:5])
        parts.append(f"Channels: {ch_list}")

    table_counts = profile.get("table_row_counts", {})
    tbl_parts = [f"{k}={v}" for k, v in sorted(table_counts.items()) if v > 0]
    if tbl_parts:
        parts.append(f"Rows: {'; '.join(tbl_parts)}")

    users = profile.get("top_users", [])
    if users:
        parts.append(f"Top users ({len(users)}): {', '.join(users[:5])}")

    hosts = profile.get("top_hosts", [])
    if hosts:
        parts.append(f"Top hosts ({len(hosts)}): {', '.join(hosts[:5])}")

    exes = profile.get("top_executables", [])
    if exes:
        parts.append(f"Top executables ({len(exes)}): {', '.join(exes[:5])}")

    tr = profile.get("time_range", {})
    if tr.get("earliest") and tr.get("latest"):
        parts.append(f"Time range: {tr['earliest']} to {tr['latest']}")

    result = "\n".join(parts)
    if len(result) > 1200:
        result = result[:1197] + "..."
    return result
