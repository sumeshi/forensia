"""Finding theme classification and theme-driven summary tables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge import catalog_names
from forensia.report.report_brief import (
    _has_benign_context_tag,
    _query_top_findings,
)

_FINDING_THEME_FILTER_SQL = """
    SELECT finding_id, rule_id, title, summary, tags
    FROM findings
    WHERE COALESCE(status, 'accepted') != 'suppressed'
      AND severity IN ('critical','high','medium')
      AND confidence >= 0.5
      AND COALESCE(title, '') != ''
      AND title NOT LIKE '%:  @%'
"""


def _finding_theme_counts(db: CaseDB) -> dict[str, int]:
    """Single-source theme counts over the same finding population as `_query_top_findings`.

    Excludes benign-context tagged findings, matching `_signal_finding_rows`'s
    existing exclusion (R3-04). Both the Key Findings table and the Action Plan
    table read from this function so theme `(N)` counts stay consistent.
    """
    counts: dict[str, int] = {}
    for row in fetch_records(db, _FINDING_THEME_FILTER_SQL):
        if _has_benign_context_tag(row):
            continue
        theme = _finding_theme(row)
        counts[theme] = counts.get(theme, 0) + 1
    return counts


def _signal_finding_rows(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    theme_counts = _finding_theme_counts(db)
    grouped: dict[str, dict[str, Any]] = {}
    for item in _query_top_findings(db, max(limit * 4, limit)):
        # R3-04: Exclude benign-context tagged findings from top findings
        if _has_benign_context_tag(item):
            continue
        theme = _finding_theme(item)
        target = grouped.setdefault(
            theme,
            {
                "theme": theme,
                "count": 0,
                "severity": "low",
                "confidence": 0.0,
                "evidence_ids": [],
                "finding_ids": [],
            },
        )
        target["count"] = int(target["count"]) + 1
        target["severity"] = _max_severity(
            str(target.get("severity") or "low"), str(item.get("severity") or "low")
        )
        try:
            target["confidence"] = max(
                float(target.get("confidence") or 0), float(item.get("confidence") or 0)
            )
        except TypeError, ValueError:
            pass
        for evidence_id in item.get("evidence_ids") or []:
            text = str(evidence_id or "").strip()
            if text and text not in target["evidence_ids"]:
                target["evidence_ids"].append(text)
        finding_id = str(item.get("finding_id") or "").strip()
        if finding_id and finding_id not in target["finding_ids"]:
            target["finding_ids"].append(finding_id)

    candidates = [
        item for item in grouped.values() if str(item.get("theme") or "") != "other"
    ] or list(grouped.values())
    rows: list[dict[str, Any]] = []
    for item in sorted(
        candidates,
        key=lambda row: (
            _finding_theme_rank(str(row.get("theme") or "")),
            _severity_rank(str(row.get("severity") or "")),
            -float(row.get("confidence") or 0),
        ),
    )[:limit]:
        confidence = item.get("confidence")
        try:
            confidence = f"{float(confidence):.2f}"
        except TypeError, ValueError:
            confidence = str(confidence or "-")
        theme = str(item.get("theme") or "")
        rows.append(
            {
                "finding": _finding_theme_title(
                    theme, theme_counts.get(theme, int(item.get("count") or 0))
                ),
                "severity": item.get("severity"),
                "confidence": confidence,
                "why_it_matters": _finding_theme_summary(str(item.get("theme") or "")),
                "reference": "; ".join((item.get("evidence_ids") or [])[:3])
                or "; ".join((item.get("finding_ids") or [])[:2]),
            }
        )
    return rows


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity.lower(), 4)


def _max_severity(left: str, right: str) -> str:
    return left if _severity_rank(left) <= _severity_rank(right) else right


def _finding_theme(item: dict[str, Any]) -> str:
    blob = " ".join(
        str(item.get(key) or "").lower()
        for key in ("finding_id", "rule_id", "title", "summary")
    )
    if "4648" in blob or "explicit credential" in blob:
        return "explicit_credentials"
    if (
        "4722" in blob
        or "4724" in blob
        or "account lifecycle" in blob
        or "account" in blob
        and "user" in blob
    ):
        return "account_lifecycle"
    if "4616" in blob or "system time" in blob:
        return "time_change"
    if (
        "event log service stopped" in blob
        or " log clear" in blob
        or "1100" in blob
        or "1102" in blob
    ):
        return "log_integrity"
    if (
        "anti-forensic" in blob
        or "antiforensic" in blob
        or any(name.lower() in blob for name in catalog_names("antiforensic_tools"))
    ):
        return "antiforensic_tools"
    if (
        "ost" in blob
        or "outlook" in blob
        or "browser" in blob
        or "cloud" in blob
        or "drive" in blob
    ):
        return "data_access"
    return "other"


def _finding_theme_rank(theme: str) -> int:
    return {
        "explicit_credentials": 0,
        "account_lifecycle": 1,
        "time_change": 2,
        "log_integrity": 3,
        "antiforensic_tools": 4,
        "data_access": 5,
        "other": 9,
    }.get(theme, 9)


def _finding_theme_title(theme: str, count: int) -> str:
    suffix = f" ({count})" if count > 1 else ""
    return {
        "explicit_credentials": f"Explicit credential usage observed{suffix}",
        "account_lifecycle": f"User account change events{suffix}",
        "time_change": f"System time change observed{suffix}",
        "log_integrity": f"Log stop / clear candidate events{suffix}",
        "antiforensic_tools": f"Wiping / cleaning tool traces{suffix}",
        "data_access": f"Mail / browser / cloud-related traces{suffix}",
        "other": f"Other priority findings{suffix}",
    }.get(theme, f"Priority findings{suffix}")


def _finding_theme_summary(theme: str) -> str:
    return {
        "explicit_credentials": "Credentials were used explicitly (not standard logon); correlate target user, host, and time.",
        "account_lifecycle": "Account creation, activation, or password changes may enable privilege use or trace manipulation.",
        "time_change": "Time changes affect timeline interpretation; correlate with surrounding auth and file events.",
        "log_integrity": "Log stop/clear candidates alone do not confirm wiping; check proximity to cleaning tools and shutdown.",
        "antiforensic_tools": "Cleaning tool traces do not reveal what was deleted, but are central supporting evidence for a wiping hypothesis.",
        "data_access": "Mail/browser/cloud traces show information access and sync environment; confirm destinations and target files.",
        "other": "Detailed conclusions require correlating individual evidence with surrounding events.",
    }.get(
        theme,
        "Detailed conclusions require correlating individual evidence with surrounding events.",
    )


@lru_cache(maxsize=1)
def _load_finding_theme_specs() -> dict[str, dict[str, str]]:
    import yaml

    path = (
        Path(__file__).resolve().parent.parent
        / "rulepacks"
        / "_schema"
        / "finding_themes.yaml"
    )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    themes = data.get("themes") if isinstance(data, dict) else None
    if not isinstance(themes, dict):
        return {}
    return {
        str(name): {str(k): str(v) for k, v in spec.items() if isinstance(v, str)}
        for name, spec in themes.items()
        if isinstance(spec, dict)
    }


def _finding_theme_recommended_action(theme: str, count: int) -> str:
    declared = (
        _load_finding_theme_specs().get(theme, {}).get("recommended_action") or ""
    ).strip()
    if declared:
        return declared
    return (
        f"Correlate {_finding_theme_title(theme, count)} by user, host, and time"
    )


def _build_key_findings_table(db: CaseDB) -> list[dict[str, Any]]:
    return _signal_finding_rows(db, 8)


def _build_recommendations_table(db: CaseDB) -> list[dict[str, Any]]:
    """Action plan rows derived from the case's own findings.

    No fixed scenario actions: every row is conditional on data present in
    this case (Rule 16). Top finding themes drive correlation actions.

    Only evidence-driven forensic recommendations belong here. Tool-side
    investigation bookkeeping (triaging open hypotheses, reviewing automatic
    benign downgrades) is not client-facing advice; open hypotheses are
    already surfaced in the Gap Assessment tables.
    """
    rows: list[dict[str, Any]] = []
    # Correlation actions for the top finding themes actually observed.
    # RPT-03: counts come from the same single-source `_finding_theme_counts`
    # used by the Key Findings table, so `(N)` matches across sections.
    theme_counts = _finding_theme_counts(db)
    ranked_themes = sorted(
        (theme for theme in theme_counts if theme != "other"),
        key=lambda theme: (_finding_theme_rank(theme), -theme_counts[theme]),
    )
    for theme in ranked_themes[:3]:
        rows.append(
            {
                "priority": "High" if _finding_theme_rank(theme) <= 2 else "Medium",
                "action": _finding_theme_recommended_action(
                    theme, theme_counts[theme]
                ),
                "rationale": _finding_theme_summary(theme),
                "evidence_or_gap": theme,
            }
        )

    return rows

