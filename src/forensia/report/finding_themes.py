"""Finding theme classification and theme-driven summary tables."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.catalog import catalog_names
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


@dataclass(frozen=True)
class FindingThemeSpec:
    """Describe one externally configured finding classification and its copy."""

    key: str
    rank: int
    title: str
    summary: str
    recommended_action: str
    any_terms: tuple[str, ...] = ()
    all_term_groups: tuple[tuple[str, ...], ...] = ()
    catalogs: tuple[str, ...] = ()

    def matches(self, blob: str) -> bool:
        """Return True when the normalized finding text matches this theme."""
        if any(term in blob for term in self.any_terms):
            return True
        if any(all(term in blob for term in group) for group in self.all_term_groups):
            return True
        return any(
            name.lower() in blob
            for catalog in self.catalogs
            for name in catalog_names(catalog)
        )


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
    """Classify a finding using the ordered rules in finding_themes.yaml."""
    blob = " ".join(
        str(item.get(key) or "").lower()
        for key in ("finding_id", "rule_id", "title", "summary")
    )
    for spec in _load_finding_theme_specs().values():
        if spec.key != "other" and spec.matches(blob):
            return spec.key
    return "other"


def _finding_theme_rank(theme: str) -> int:
    spec = _load_finding_theme_specs().get(theme)
    return spec.rank if spec else 999


def _finding_theme_title(theme: str, count: int) -> str:
    suffix = f" ({count})" if count > 1 else ""
    spec = _load_finding_theme_specs().get(theme)
    title = spec.title if spec else "Priority findings"
    return f"{title}{suffix}"


def _finding_theme_summary(theme: str) -> str:
    spec = _load_finding_theme_specs().get(theme)
    fallback = _load_finding_theme_specs().get("other")
    if spec:
        return spec.summary
    return (
        fallback.summary if fallback else "Detailed evidence correlation is required."
    )


def _theme_config_path() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "rulepacks"
        / "_schema"
        / "finding_themes.yaml"
    )


def _string_tuple(value: Any, *, field: str, theme: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"finding theme {theme}.{field} must be a list of strings")
    return tuple(item.strip().lower() for item in value if item.strip())


@lru_cache(maxsize=1)
def _load_finding_theme_specs() -> dict[str, FindingThemeSpec]:
    """Load and validate report theme rules and presentation copy from YAML."""
    import yaml

    path = _theme_config_path()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"{path}: version must be 1")
    themes = data.get("themes") if isinstance(data, dict) else None
    if not isinstance(themes, dict):
        raise ValueError(f"{path}: themes must be a mapping")

    loaded: dict[str, FindingThemeSpec] = {}
    for name, raw in themes.items():
        key = str(name).strip()
        if not key or not isinstance(raw, dict):
            raise ValueError(f"{path}: each theme must be a named mapping")
        match = raw.get("match") or {}
        if not isinstance(match, dict):
            raise ValueError(f"finding theme {key}.match must be a mapping")
        raw_groups = match.get("all_term_groups") or []
        if not isinstance(raw_groups, list):
            raise ValueError(
                f"finding theme {key}.match.all_term_groups must be a list"
            )
        groups = tuple(
            _string_tuple(group, field="match.all_term_groups", theme=key)
            for group in raw_groups
        )
        if any(not group for group in groups):
            raise ValueError(
                f"finding theme {key}.match.all_term_groups cannot contain an empty group"
            )
        required = ("rank", "title", "summary", "recommended_action")
        missing = [field for field in required if field not in raw]
        if missing:
            raise ValueError(f"finding theme {key} is missing: {', '.join(missing)}")
        spec = FindingThemeSpec(
            key=key,
            rank=int(raw["rank"]),
            title=str(raw["title"]).strip(),
            summary=str(raw["summary"]).strip(),
            recommended_action=str(raw["recommended_action"]).strip(),
            any_terms=_string_tuple(
                match.get("any_terms"), field="match.any_terms", theme=key
            ),
            all_term_groups=groups,
            catalogs=_string_tuple(
                match.get("catalogs"), field="match.catalogs", theme=key
            ),
        )
        if not spec.title or not spec.summary or not spec.recommended_action:
            raise ValueError(f"finding theme {key} presentation fields cannot be empty")
        if key != "other" and not (
            spec.any_terms or spec.all_term_groups or spec.catalogs
        ):
            raise ValueError(f"finding theme {key} must declare at least one matcher")
        unknown_catalogs = [
            catalog for catalog in spec.catalogs if not catalog_names(catalog)
        ]
        if unknown_catalogs:
            raise ValueError(
                f"finding theme {key} references empty or unknown catalogs: "
                f"{', '.join(unknown_catalogs)}"
            )
        loaded[key] = spec
    if "other" not in loaded:
        raise ValueError(f"{path}: themes.other is required")
    ranks = [spec.rank for spec in loaded.values()]
    if len(ranks) != len(set(ranks)):
        raise ValueError(f"{path}: theme ranks must be unique")
    return dict(sorted(loaded.items(), key=lambda item: item[1].rank))


def _finding_theme_recommended_action(theme: str, count: int) -> str:
    spec = _load_finding_theme_specs().get(theme)
    declared = spec.recommended_action if spec else ""
    if declared:
        return declared
    return f"Correlate {_finding_theme_title(theme, count)} by user, host, and time"


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
                "action": _finding_theme_recommended_action(theme, theme_counts[theme]),
                "rationale": _finding_theme_summary(theme),
                "evidence_or_gap": theme,
            }
        )

    return rows


build_recommendations_table = _build_recommendations_table
classify_finding_theme = _finding_theme
finding_theme_counts = _finding_theme_counts
signal_finding_rows = _signal_finding_rows
