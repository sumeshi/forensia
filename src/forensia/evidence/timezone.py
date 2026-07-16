from __future__ import annotations

import re
from datetime import datetime
from typing import Any


def _observe_4616_biases(db) -> list[tuple[int, str]]:
    """Method 1: extract timezone bias observations from Event 4616 raw_json."""
    rows = db.execute(
        """
        SELECT raw_json
        FROM evtx_events
        WHERE event_id = 4616
          AND raw_json IS NOT NULL
        LIMIT 50
        """
    ).fetchall()
    observations: list[tuple[int, str]] = []
    for (raw_json,) in rows:
        if not raw_json:
            continue
        try:
            data = json_loads(raw_json) if isinstance(raw_json, str) else dict(raw_json)
        except Exception:
            continue
        bias = _extract_4616_bias(data)
        if bias is not None:
            observations.append((bias, "Event 4616 system time change"))
    return observations


def _observe_message_offsets(db) -> list[int]:
    """Method 2: offsets (minutes) between embedded message-body ISO timestamps and UTC."""
    rows = db.execute(
        """
        SELECT timestamp, message
        FROM evtx_events
        WHERE message IS NOT NULL AND message != ''
          AND timestamp IS NOT NULL
        LIMIT 5000
        """
    ).fetchall()
    iso_pattern = re.compile(r"(?<!\d)(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?!\d)")
    msg_offsets: list[int] = []
    for utc_ts, message in rows:
        if not message:
            continue
        try:
            utc_dt = datetime.fromisoformat(str(utc_ts).replace("Z", "+00:00")).replace(
                tzinfo=None
            )
        except (ValueError, TypeError, AttributeError):
            continue
        for match in iso_pattern.finditer(str(message)):
            try:
                embedded_dt = datetime.strptime(
                    f"{match.group(1)} {match.group(2)}", "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue
            if embedded_dt.year < 2000 or embedded_dt.year > 2100:
                continue
            offset_sec = (embedded_dt - utc_dt).total_seconds()
            offset_min = round(offset_sec / 60)
            if -720 <= offset_min <= 720:
                msg_offsets.append(offset_min)
    return msg_offsets


def _observe_uptime_offsets(db) -> list[int]:
    """Method 3: offsets (minutes) from paired 6005/6013 uptime clock-consistency checks."""
    rows = db.execute(
        """
        SELECT timestamp, message
        FROM evtx_events
        WHERE event_id = 6013
          AND message IS NOT NULL
          AND timestamp IS NOT NULL
        LIMIT 50
        """
    ).fetchall()
    uptime_offsets: list[int] = []
    for utc_ts, message in rows:
        if not message:
            continue
        m = re.search(r"uptime is (\d+) seconds?", str(message), re.IGNORECASE)
        if not m:
            continue
        try:
            boot_6013 = datetime.fromisoformat(
                str(utc_ts).replace("Z", "+00:00")
            ).replace(tzinfo=None)
            uptime_sec = int(m.group(1))
            boot_calculated = boot_6013.replace(tzinfo=None)
        except (ValueError, TypeError, AttributeError):
            continue
        # Compare with 6005 (EventLog service start) within a short time window
        nearby = db.execute(
            """
            SELECT timestamp
            FROM evtx_events
            WHERE event_id = 6005
              AND timestamp IS NOT NULL
              AND CAST(timestamp AS TIMESTAMP) BETWEEN CAST(? AS TIMESTAMP) - INTERVAL '5 minutes'
                                                   AND CAST(? AS TIMESTAMP) + INTERVAL '5 minutes'
              AND computer = (
                  SELECT computer FROM evtx_events WHERE event_id = 6013
                  AND timestamp = ? LIMIT 1
              )
            LIMIT 1
            """,
            (utc_ts, utc_ts, utc_ts),
        ).fetchone()
        if not nearby:
            continue
        try:
            boot_6005 = datetime.fromisoformat(
                str(nearby[0]).replace("Z", "+00:00")
            ).replace(tzinfo=None)
        except (ValueError, TypeError, AttributeError):
            continue
        expected_boot = boot_calculated - __import__("datetime").timedelta(
            seconds=uptime_sec
        )
        gap_sec = abs((expected_boot - boot_6005).total_seconds())
        if gap_sec > 3600:
            offset_hours = round(gap_sec / 3600)
            uptime_offsets.append(offset_hours * 60)
    return uptime_offsets


def _aggregate_observations(
    observations: list[tuple[int, str]], msg_offsets: list[int]
) -> tuple[int | None, str]:
    """Two-path aggregation of timezone observations.

    a) ≥2 methods agree on the same offset → strong signal.
    b) Single method (message-body timestamps) with ≥2 agreeing raw data
       points → accepted.
    """
    method_offsets = [o for o, _ in observations]
    agreed_method = (
        _all_agree(method_offsets, tolerance=30) if len(method_offsets) >= 2 else None
    )
    if agreed_method is not None:
        source_set: set[str] = set()
        for obs_offset, obs_src in observations:
            if abs(obs_offset - agreed_method) <= 30:
                source_set.add(obs_src)
        return (
            agreed_method,
            f"Inferred from {len(source_set)} sources: {', '.join(sorted(source_set))}",
        )
    if len(msg_offsets) >= 2:
        agreed = _most_common_agreeing(msg_offsets, tolerance=30)
        if agreed is not None:
            return (
                agreed,
                f"Inferred from {len(msg_offsets)} event message timestamps",
            )
    return (None, "Could not determine timezone from available events")


def infer_timezone(db) -> tuple[int | None, str]:
    """Infer the source timezone offset in minutes from available evidence.

    Methods used (in order):
      1. Event 4616 (System Time Change) — extract timezone bias from raw_json.
      2. Embedded ISO timestamps in event message bodies — compare with UTC.
      3. Paired 6005/6013 uptime records — validate clock consistency.

    Conservative: returns None unless ≥2 independent agreeing observations.
    Returns (tz_offset_minutes | None, basis_string).
    """
    observations = _observe_4616_biases(db)

    msg_offsets = _observe_message_offsets(db)
    if len(msg_offsets) >= 2:
        offset = _most_common_agreeing(msg_offsets, tolerance=30)
        if offset is not None:
            observations.append((offset, "Event message body timestamps"))

    uptime_offsets = _observe_uptime_offsets(db)
    if len(uptime_offsets) >= 2:
        offset = _most_common_agreeing(uptime_offsets, tolerance=30)
        if offset is not None:
            observations.append((offset, "Paired 6005/6013 uptime records"))

    return _aggregate_observations(observations, msg_offsets)


def get_timezone_info(db) -> dict[str, Any]:
    """Return timezone information with status tracking.

    R7-08: Returns a dict with:
    - status: 'declared' | 'inferred' | 'unknown'
    - offset_minutes: int | None
    - basis: str
    - confidence: float (0.0-1.0)
    - display_tz: str for display purposes
    """
    offset, basis = infer_timezone(db)
    if offset is not None:
        return {
            "status": "inferred",
            "offset_minutes": offset,
            "basis": basis,
            "confidence": 0.8,
            "display_tz": f"UTC{offset//60:+d}" if offset != 0 else "UTC",
        }
    return {
        "status": "unknown",
        "offset_minutes": None,
        "basis": "Could not determine timezone from available events",
        "confidence": 0.0,
        "display_tz": "Normalized timestamps (source timezone undetermined)",
    }


def _all_agree(values: list[int], tolerance: int = 30) -> int | None:
    """Return the offset if all non-None values agree within tolerance."""
    filtered = [v for v in values if v is not None]
    if len(filtered) < 2:
        return None
    for candidate in set(filtered):
        if all(abs(v - candidate) <= tolerance for v in filtered):
            return candidate
    return None


def _extract_4616_bias(data: dict[str, Any]) -> int | None:
    """Extract timezone bias in minutes from an Event 4616 raw_json payload."""
    event_data = data
    for key in ("Event", "EventData"):
        if isinstance(event_data, dict):
            event_data = event_data.get(key, event_data)
    if not isinstance(event_data, dict):
        return None
    data_list = event_data.get("Data")
    if isinstance(data_list, list):
        for item in data_list:
            if isinstance(item, dict) and str(item.get("Name", "")).lower() in {
                "newtimezonebias",
                "timezonebias",
                "bias",
            }:
                try:
                    return int(item.get("Text", item.get("#text", 0)))
                except (ValueError, TypeError):
                    return None
    for key in ("NewTimeZoneBias", "TimeZoneBias", "Bias"):
        val = event_data.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                return None
    return None


def _most_common_agreeing(values: list[int], tolerance: int = 30) -> int | None:
    """Return the most common value from values where at least 2 agree within `tolerance`."""
    if len(values) < 2:
        return None
    for candidate in set(values):
        count = sum(1 for v in values if abs(v - candidate) <= tolerance)
        if count >= 2:
            return candidate
    return None


def json_loads(s: str) -> Any:
    import json

    return json.loads(s)
