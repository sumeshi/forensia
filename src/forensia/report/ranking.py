"""Report ranking policy, supplied by the report's Markdown templates (not core).

The order in which findings lead the report (``top_findings`` in
``report_brief.json``, which seeds the leading thesis) is a *presentation policy*
of the section that renders the overview/executive summary, not a property of the
report engine. Different cases want different orders: a data-exfiltration
narrative may want findings grouped by attack stage, while a generic incident is
most honestly ordered by severity.

So the policy is written in the section template's YAML frontmatter — read the
template and you see how that section wants its findings ordered:

    ---
    behaviors:
      - canonical_evidence_scope
    brief:
      top_findings:
        ranking:
          policy: priority_keywords        # or "severity" (the built-in default)
          priority_keywords:               # ordered groups; earlier groups rank higher
            - ["4648", "explicit credential"]
            - ["4625", "brute"]
            - ["outlook", "ost", "browser", "cloud"]
            - ["ccleaner", "eraser", "anti-forensic"]
    ---
    # Investigation Overview
    ...

Core keeps only the *mechanism*: the ``priority_keywords`` and ``severity``
operators and a stable sort. The case-specific vocabulary ("4648", "ccleaner", …)
lives in the template. When no template declares a policy (e.g. the packaged
generic templates), core falls back to its case-agnostic default: severity, then
ATT&CK mapping, then confidence. Swapping the template set therefore swaps the
ranking policy without touching core code.

Malformed policies are not silently ignored: at runtime they raise a warning and
fall back to the default, and ``audit_packaged_report_templates`` (wired into
``forensia doctor``) hard-fails if a packaged generic template is malformed or
smuggles in case-specific ranking vocabulary.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import yaml

SECTION_TEMPLATE_GLOB = "[0-9]*_*.md"


class RankingPolicyError(ValueError):
    """A template declares a malformed ``brief.top_findings.ranking`` policy."""


def _parse_frontmatter(text: str) -> dict:
    """Return the YAML frontmatter mapping, or {} when there is none.

    Raises RankingPolicyError on frontmatter that is present but not valid YAML.
    """
    if not text.startswith("---\n"):
        return {}
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        return {}
    try:
        meta = yaml.safe_load(parts[1])
    except yaml.YAMLError as exc:
        raise RankingPolicyError(f"invalid YAML frontmatter: {exc}") from exc
    return meta if isinstance(meta, dict) else {}


def _ranking_block(meta: dict):
    """Pull ``brief.top_findings.ranking`` out of a frontmatter mapping."""
    brief = meta.get("brief")
    if not isinstance(brief, dict):
        return None
    top_findings = brief.get("top_findings")
    if not isinstance(top_findings, dict):
        return None
    return top_findings.get("ranking")


def parse_priority_keywords(ranking) -> list[list[str]] | None:
    """Validate a ranking block into ordered keyword groups.

    Returns ``None`` for the severity default (no policy / ``policy: severity``).
    Raises :class:`RankingPolicyError` for any malformed declaration so callers
    and the doctor check can surface it instead of silently degrading.
    """
    if ranking is None:
        return None
    if not isinstance(ranking, dict):
        raise RankingPolicyError("brief.top_findings.ranking must be a mapping")
    policy = str(ranking.get("policy") or "").strip()
    if policy in ("", "severity", "default"):
        return None
    if policy != "priority_keywords":
        raise RankingPolicyError(f"unknown top_findings ranking policy: {policy!r}")
    raw_groups = ranking.get("priority_keywords")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise RankingPolicyError(
            "policy 'priority_keywords' requires a non-empty priority_keywords list"
        )
    groups: list[list[str]] = []
    for group in raw_groups:
        if isinstance(group, str):
            terms = [group]
        elif isinstance(group, list):
            terms = [str(term) for term in group]
        else:
            raise RankingPolicyError(
                "priority_keywords entries must be a string or a list of strings"
            )
        terms = [term.lower() for term in terms if str(term).strip()]
        if not terms:
            raise RankingPolicyError("priority_keywords groups must be non-empty")
        groups.append(terms)
    return groups


def _iter_section_templates(template_dir: Path | str):
    for path in sorted(Path(template_dir).glob(SECTION_TEMPLATE_GLOB)):
        try:
            yield path, path.read_text(encoding="utf-8")
        except OSError:
            continue


def load_top_findings_priority_keywords(
    template_dir: Path | str | None,
) -> list[list[str]] | None:
    """Resolve the active template set's top_findings ranking into keyword groups.

    Scans the section templates' frontmatter for a ``brief.top_findings.ranking``
    policy. Returns ordered keyword groups, or ``None`` for the case-agnostic
    severity default. A malformed policy emits a warning and is skipped (the
    doctor-level :func:`audit_packaged_report_templates` is the hard gate).
    """
    if not template_dir:
        return None
    resolved: list[list[str]] | None = None
    resolved_from: Path | None = None
    for path, text in _iter_section_templates(template_dir):
        try:
            groups = parse_priority_keywords(_ranking_block(_parse_frontmatter(text)))
        except RankingPolicyError as exc:
            warnings.warn(
                f"{path.name}: {exc}; falling back to default ranking",
                stacklevel=2,
            )
            continue
        if groups is None:
            continue
        if resolved is not None:
            warnings.warn(
                f"top_findings ranking declared in multiple templates "
                f"({resolved_from.name}, {path.name}); using {resolved_from.name}",
                stacklevel=2,
            )
            continue
        resolved, resolved_from = groups, path
    return resolved


def _packaged_report_template_dir() -> Path:
    # ranking.py lives at src/forensia/report/ranking.py; the packaged section
    # templates live in the sibling directory src/forensia/report/templates/.
    return Path(__file__).resolve().parent / "templates"


def audit_packaged_report_templates() -> list[str]:
    """Doctor gate: packaged generic templates must parse and stay case-agnostic.

    Returns a list of human-readable problems (empty when healthy). A packaged
    template is a problem if its frontmatter is invalid, its ranking policy is
    malformed, or it declares a ``priority_keywords`` policy — case-specific
    ranking vocabulary belongs in an external template set, never in the bundled
    generic templates.
    """
    problems: list[str] = []
    template_dir = _packaged_report_template_dir()
    if not template_dir.exists():
        return [f"packaged report_template directory not found: {template_dir}"]
    for path, text in _iter_section_templates(template_dir):
        try:
            groups = parse_priority_keywords(_ranking_block(_parse_frontmatter(text)))
        except RankingPolicyError as exc:
            problems.append(f"{path.name}: {exc}")
            continue
        if groups is not None:
            problems.append(
                f"{path.name}: packaged generic template must not declare a "
                f"case-specific top_findings 'priority_keywords' policy"
            )
    return problems


def priority_rank(text: str, keyword_groups: list[list[str]]) -> int:
    """Index of the first keyword group matched by *text*; ``len`` if none match.

    Lower is higher priority. Ties keep the caller's existing (generic) order.
    """
    blob = text.lower()
    for index, group in enumerate(keyword_groups):
        if any(term in blob for term in group):
            return index
    return len(keyword_groups)
