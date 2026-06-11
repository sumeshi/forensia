from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_PROFILE_CACHE: dict[str, dict[str, Any]] = {}


@dataclass
class CaseEvidenceProfile:
    """Explicit profile context object replacing module globals.

    ``event_ids=None`` means "no profile computed" (unknown); an empty set
    means "profile computed and the case has zero EVTX event IDs" (e.g. an
    MFT-only case). Callers such as the drafter event-ID filter and the
    untestable detector rely on that distinction.
    """
    profile_name: str = ""
    event_ids: set[int] | None = None


# Legacy module-global state — deprecated, will be removed in R5
_profile: CaseEvidenceProfile = CaseEvidenceProfile()


def set_case_profile(profile_name: str | None, event_ids: set[int] | None) -> None:
    """Set the case profile globally (deprecated: use CaseEvidenceProfile directly)."""
    global _profile
    _profile = CaseEvidenceProfile(profile_name=profile_name or "", event_ids=event_ids)


def get_case_profile() -> str | None:
    return _profile.profile_name or None


def get_profile_event_ids() -> set[int] | None:
    # Return a copy: several prompt builders extend the result with
    # hypothesis/row-derived IDs, and mutating the module-global set would
    # corrupt "which event IDs exist in this case" semantics used by the
    # drafter filter and untestable detection.
    # None (no profile) and empty set (profile with no event IDs) are distinct.
    return set(_profile.event_ids) if _profile.event_ids is not None else None


def _build_profile_queries(conn) -> dict[str, Any]:
    evtx_event_ids: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT event_id, COUNT(*) AS cnt FROM evtx_events GROUP BY event_id ORDER BY cnt DESC"
        ).fetchall()
        evtx_event_ids = [{"event_id": r[0], "count": r[1]} for r in rows if r[0] is not None]
    except Exception:
        pass

    channels: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT channel, COUNT(*) AS cnt FROM evtx_events GROUP BY channel ORDER BY cnt DESC"
        ).fetchall()
        channels = [{"channel": r[0], "count": r[1]} for r in rows if r[0] is not None]
    except Exception:
        pass

    table_row_counts: dict[str, int] = {}
    for tbl in ("evtx_events", "mft_entries", "mft_timeline", "prefetch_executions", "prefetch_timeline"):
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
            table_row_counts[tbl] = row[0] if row and row[0] is not None else 0
        except Exception:
            table_row_counts[tbl] = 0

    top_users: list[str] = []
    try:
        rows = conn.execute(
            "SELECT COALESCE(target_user, user_name) AS u, COUNT(*) AS cnt "
            "FROM evtx_events WHERE COALESCE(target_user, user_name) IS NOT NULL "
            "GROUP BY u ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_users = [str(r[0]) for r in rows]
    except Exception:
        pass

    top_hosts: list[str] = []
    try:
        rows = conn.execute(
            "WITH raw AS ("
            "  SELECT computer, COUNT(*) AS cnt FROM evtx_events "
            "  WHERE computer IS NOT NULL GROUP BY computer"
            ") "
            "SELECT ARG_MAX(computer, cnt) AS computer, SUM(cnt) AS cnt "
            "FROM raw GROUP BY UPPER(TRIM(computer)) "
            "ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_hosts = [str(r[0]) for r in rows]
    except Exception:
        pass

    top_executables: list[str] = []
    try:
        rows = conn.execute(
            "SELECT COALESCE(process_name, child_process) AS exe, COUNT(*) AS cnt "
            "FROM evtx_events WHERE COALESCE(process_name, child_process) IS NOT NULL "
            "GROUP BY exe ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_executables = [str(r[0]) for r in rows]
    except Exception:
        pass

    time_range: dict[str, str] = {}
    try:
        row = conn.execute(
            "SELECT MIN(timestamp) AS earliest, MAX(timestamp) AS latest FROM evtx_events"
        ).fetchone()
        if row:
            time_range["earliest"] = str(row[0] or "") if row[0] is not None else ""
            time_range["latest"] = str(row[1] or "") if row[1] is not None else ""
    except Exception:
        pass

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
    same DuckDB file risks lock conflicts). Results are cached per database
    path so repeated calls within the same process return the same profile.
    """
    cache_key = str(db.case.database_path)
    cached = _PROFILE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    profile = _build_profile_queries(db)
    _PROFILE_CACHE[cache_key] = profile
    return profile


def profile_advisor(profile_name: str, db) -> str:
    """Check which rulepacks are not covered by the active profile and return recommendations.

    Works purely deterministically:
    - Enumerates rulepack directories under rulepacks/ (excluding _schema/).
    - Loads the active profile YAML to identify enabled packs.
    - Queries the case DB for evidence of uncovered artifact families (cloud sync
      executables in prefetch, .ost/.pst in MFT) and maps them to profiles that
      include the matching rulepacks.
    """
    import yaml
    from pathlib import Path

    rulepacks_dir = Path(__file__).parent.parent / "rulepacks"
    all_packs = sorted(
        d.name for d in rulepacks_dir.iterdir()
        if d.is_dir() and d.name != "_schema"
    )
    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile_name}.yaml"
    if not profile_path.exists():
        return ""
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
    enabled_packs = {str(p) for p in (profile.get("rulepacks") or [])}
    uncovered = [p for p in all_packs if p not in enabled_packs]
    if not uncovered:
        return ""

    hints: list[str] = []

    # Detect cloud-sync executables in prefetch
    try:
        rows = db.execute(
            """
            SELECT DISTINCT executable_name FROM prefetch_executions
            WHERE LOWER(executable_name) IN (
                'googledrivesync.exe', 'onedrive.exe', 'dropbox.exe', 'icloudsetup.exe',
                'googledrivesync', 'onedrive', 'dropbox', 'icloudsetup'
            )
            """
        ).fetchall()
        detected = [str(r[0]) for r in rows if r[0]]
        if detected:
            hints.append(f"Cloud sync executables detected in prefetch: {', '.join(detected[:3])}")
    except Exception:
        pass

    # Detect email cache files in MFT
    try:
        row = db.execute("SELECT COUNT(*) FROM mft_entries WHERE extension IN ('ost', 'pst')").fetchone()
        count = int(row[0]) if row else 0
        if count > 0:
            hints.append(f"Email cache files (.ost/.pst) found in MFT ({count} entries)")
    except Exception:
        pass

    # Map uncovered packs to available profiles
    profile_pack_map: dict[str, set[str]] = {}
    for pf_path in sorted((Path(__file__).parent.parent / "profiles").glob("*.yaml")):
        try:
            pf_data = yaml.safe_load(pf_path.read_text(encoding="utf-8")) or {}
            pf_name = str(pf_data.get("name") or pf_path.stem)
            pf_packs = {str(p) for p in (pf_data.get("rulepacks") or [])}
            profile_pack_map[pf_name] = pf_packs
        except Exception:
            continue

    covering = sorted(
        pf_name for pf_name, pf_packs in profile_pack_map.items()
        if pf_name != profile_name and any(p in pf_packs for p in uncovered)
    )

    lines: list[str] = []
    lines.append(
        f"[RULES] profile '{profile_name}' enables packs [{', '.join(sorted(enabled_packs))}]; "
        f"packs not enabled: [{', '.join(uncovered)}]."
    )
    if hints:
        lines.extend(f"[RULES] Indicator hint: {h}." for h in hints)
    if covering:
        lines.append(
            f"[RULES] Use --profile {' or '.join(covering[:3])} "
            f"to include rulepacks covering these artifacts."
        )
    return "\n".join(lines)


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
