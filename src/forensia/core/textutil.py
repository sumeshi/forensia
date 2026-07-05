from __future__ import annotations

import re


def slugify(value: str) -> str:
    """Convert a string to a lowercase, dash-separated filesystem-safe slug.

    Preserves dots, underscores, and hyphens for paths/IPs/versions.
    Uses regex to collapse runs of disallowed characters into a single dash.
    Unicode-aware via re.UNICODE flag.
    """
    if not value:
        return "unknown"
    cleaned = re.sub(r"[^\w.\-]+", "-", value.strip(), flags=re.UNICODE)
    return cleaned.strip("-").lower() or "unknown"


def strict_slugify(value: str) -> str:
    """Strict slug: only alphanumeric preserved, individual char replacement.

    Each non-alnum character is replaced with a dash (no collapsing).
    No dot/underscore/hyphen preservation. Use for evidence IDs.
    """
    if not value:
        return "unknown"
    result = "".join(c.lower() if c.isalnum() else "-" for c in value.strip())
    return result.strip("-") or "unknown"


def normalize_text(text: str) -> str:
    """Normalize text: lowercase, keep only alphanumeric tokens, collapse whitespace."""
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def token_set_similarity(a: str, b: str) -> float:
    """Compute token-set overlap ratio between two strings.

    Returns len(a_tokens & b_tokens) / max(len(a_tokens), len(b_tokens)).
    Used for overview dedup in investigator's _apply_memory_updates.
    """
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / max(len(tokens_a), len(tokens_b))


def jaccard_similarity(a: str, b: str) -> float:
    """Jaccard token-set similarity between two pre-normalized strings.

    Returns len(intersection) / len(union).
    """
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def is_local_ingest_path(path: object) -> bool:
    """Return True if *path* looks like a local ingest artefact path rather
    than a real on-disk Windows path.

    The distinction is purely structural: evidence extracted from the image
    carries Windows-style paths (drive letter, UNC, or ``\\Device\\`` prefix,
    backslash separators), while paths pointing at the analyst's local ingest
    tree use forward slashes without a Windows root. No directory names are
    matched, so the check is independent of any particular case layout.
    """
    p = str(path).strip() if path is not None else ""
    if not p:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", p):
        return False
    if p.startswith("\\\\") or p.startswith("\\Device\\"):
        return False
    return "/" in p


def path_basename(path: object) -> str:
    """Return just the final filename component from a path string."""
    p = str(path).strip() if path is not None else ""
    if not p:
        return ""
    for sep in ("/", "\\"):
        if sep in p:
            p = p.rsplit(sep, 1)[-1]
    return p


def sanitize_ingest_path(path: object) -> str:
    """Reduce a local ingest artefact path to its basename.

    Real Windows evidence paths are returned unchanged; only paths that
    point at the analyst's local ingest tree are shortened, so case output
    never records the local filesystem layout.
    """
    p = str(path).strip() if path is not None else ""
    if not p:
        return ""
    if is_local_ingest_path(p):
        return path_basename(p)
    return p


_JP_DATE_TIME_RE = re.compile(
    r"(?P<year>\d{4})年(?P<month>\d{1,2})月(?P<day>\d{1,2})日"
    r"(?:\s*(?P<hour>\d{1,2})時(?P<minute>\d{1,2})分"
    r"(?:(?P<second>\d{1,2})秒)?)?"
)


def normalize_localized_dates(text: str) -> str:
    """Normalize Japanese numeric date/time strings to ISO-like report format.

    The LLM may ignore DATE FORMAT instructions and emit strings such as
    ``2015年3月22日14時38分16秒``. This deterministic pass converts only that
    narrow numeric pattern; it does not translate prose or month names.
    """
    if not text:
        return ""

    def _replace(match: re.Match[str]) -> str:
        year = int(match.group("year"))
        month = int(match.group("month"))
        day = int(match.group("day"))
        hour = match.group("hour")
        minute = match.group("minute")
        second = match.group("second")
        date_part = f"{year:04d}-{month:02d}-{day:02d}"
        if hour is None or minute is None:
            return date_part
        return (
            f"{date_part} {int(hour):02d}:{int(minute):02d}:"
            f"{int(second or 0):02d} UTC"
        )

    return _JP_DATE_TIME_RE.sub(_replace, str(text))
