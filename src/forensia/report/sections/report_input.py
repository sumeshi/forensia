"""Single normalization entry for report section inputs.

Every report section template — the packaged default (seeded under
``case/report_template/``), an explicit ``--template-dir`` working copy, or the
user-facing ``REPORT.md`` — is normalized here into the same
:class:`SectionSource` list, so downstream section assembly sees one contract
(existing frontmatter fields, ``#`` section headings, ``##`` blocks, and the
HTML-comment hint language of ``template_parsing``).

The user-facing ``REPORT.md`` is ordinary Markdown:

- top-level ``# `` headings become sections (the file boundary equivalent of
  one template file per section);
- ``## `` headings beneath a section are that section's blocks (existing
  hint contract applies verbatim);
- the section key is ``<nn>_<slug>`` where ``nn`` is the 1-based document
  order and ``<slug>`` is derived from the heading text. It is stable for an
  unchanged input revision; reordering creates new keys while old rows remain
  stored but leave the active report projection;
- duplicate section headings are rejected explicitly instead of being merged;
- the file-level frontmatter applies to every section derived from the file.

The default report (no ``REPORT.md``) goes through the same list, just sourced
from the seeded template directory. There is deliberately no second template
format, planner, or renderer: ``REPORT.md`` and ``--template-dir`` are two
producers of one parsed structure.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.sections.template_parsing import (
    TemplateMeta,
    parse_template,
    parse_template_text,
)

REPORT_SPEC_FILENAME = "REPORT.md"
REPORT_INPUT_PHASE = "report-input"
MAX_REPORT_SECTIONS = 99

# Line-anchored level-1 heading (`# `); `##` and deeper stay inside a section
# as its blocks, matching the existing split_template_body contract.
_SECTION_HEADING = re.compile(r"^#\s+(.+)$")
_NO_SLUG_CHARS = re.compile(r"\W+")

_TEMPLATE_DIR_MATCH = "[0-9]*_*.md"


class ReportSpecError(ValueError):
    """The report input specification (explicit path or case ``REPORT.md``) is invalid.

    Raised before any investigation or report write starts; CLI adapters
    translate it into a user-facing parameter error.
    """


@dataclass(frozen=True)
class SectionSource:
    """One normalized report section template input.

    ``section_key`` is the durable ``report_sections`` identity,
    ``body`` is the same shape of text template files provide (optional
    section declamation plus ``##`` blocks), and ``meta`` carries the
    file-level frontmatter contract fields.
    """

    section_key: str
    body: str
    meta: TemplateMeta
    source: str

    @property
    def template_path(self) -> str:
        """Provenance of this section (kept for troubleshooting output)."""
        return self.source


@dataclass(frozen=True)
class ReportInputDecision:
    sections: list[SectionSource]
    record: dict[str, object]
    notice: str | None = None


def _section_payload(sections: list[SectionSource]) -> list[dict[str, object]]:
    return [asdict(section) for section in sections]


def _section_digest(sections: list[SectionSource]) -> str:
    body = json.dumps(_section_payload(sections), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _recorded_report_input(db: CaseDB) -> dict[str, object] | None:
    row = db.execute(
        "SELECT output_json FROM investigation_steps WHERE phase = ? "
        "ORDER BY created_at DESC, step_id DESC LIMIT 1",
        (REPORT_INPUT_PHASE,),
    ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(str(row[0]))
        if not isinstance(value, dict) or not isinstance(value["sections"], list):
            raise ValueError("missing sections")
        return value
    except (KeyError, TypeError, ValueError) as exc:
        raise ReportSpecError("recorded report input is invalid") from exc


def active_report_section_keys(db: CaseDB) -> list[str] | None:
    """Keys of the adopted report input; None means a pre-adoption case."""
    record = _recorded_report_input(db)
    if record is None:
        return None
    return [str(item["section_key"]) for item in record["sections"]]


def decide_report_sources(
    case: Case,
    db: CaseDB,
    template_root: str | Path | None,
    report_spec: str | Path | None = None,
) -> ReportInputDecision:
    """Pin an implicit resume to its recorded input; explicit inputs reload it."""
    recorded = _recorded_report_input(db)
    root = Path(template_root) if template_root is not None else None
    explicit = report_spec is not None or (
        root is not None and root.resolve() != case.report_template_dir.resolve()
    )
    if recorded is not None and not explicit:
        raw_sections = recorded["sections"]
        try:
            sections = [
                SectionSource(
                    section_key=str(item["section_key"]),
                    body=str(item["body"]),
                    meta=TemplateMeta(**item["meta"]),
                    source=str(item["source"]),
                )
                for item in raw_sections
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise ReportSpecError(
                "recorded report input cannot be reconstructed"
            ) from exc
        if not sections:
            raise ReportSpecError("recorded report input has no sections")
        try:
            current = resolve_report_sources(case, root)
            changed = _section_digest(current) != str(recorded["content_sha256"])
        except OSError, UnicodeError, ReportSpecError:
            changed = True
        notice = (
            "REPORT.md/report templates changed or are unavailable; the recorded "
            "revision remains in force. Reload explicitly with --report-spec "
            "or --template-dir."
            if changed
            else None
        )
        source_path = recorded.get("source_path")
    else:
        sections = resolve_report_sources(case, root, report_spec=report_spec)
        notice = None
        source_path = str(report_spec or sections[0].source)
    record = {
        "sections": _section_payload(sections),
        "content_sha256": _section_digest(sections),
        "source": "explicit" if explicit else "default",
        "source_path": source_path,
        "notice": notice,
    }
    return ReportInputDecision(sections=sections, record=record, notice=notice)


def section_slug(heading_text: str) -> str:
    """Derive the stable slug part of a section key from a ``#`` heading.

    Pure function of the heading text: casefold, collapse runs of
    non-word characters into ``_``, trim, then cap length. Deterministic and
    re-run stable across platforms.
    """
    slug = _NO_SLUG_CHARS.sub("_", heading_text.strip().casefold())
    slug = slug.strip("_")[:60]
    return slug or "section"


def section_source_from_path(path: str | Path) -> SectionSource:
    """Normalize a single template file (one file = one section) into a SectionSource."""
    target = Path(path)
    body, meta = parse_template(str(target))
    return SectionSource(
        section_key=target.stem, body=body, meta=meta, source=str(target)
    )


def sections_from_template_dir(template_root: str | Path) -> list[SectionSource]:
    """Normalize the existing template-directory input (packaged or ``--template-dir``)."""
    root = Path(template_root)
    paths = sorted(root.glob(_TEMPLATE_DIR_MATCH))
    if not paths:
        raise ReportSpecError(
            f"no report section templates matching {_TEMPLATE_DIR_MATCH} under {root}"
        )
    return [section_source_from_path(path) for path in paths]


def split_report_spec_sections(
    text: str, source_label: str
) -> tuple[TemplateMeta, list[tuple[str, str]]]:
    """Split a ``REPORT.md`` text into (file meta, [(heading, section text), ...])."""
    body, file_meta = parse_template_text(text)
    sections: list[tuple[str, str]] = []
    heading: str | None = None
    lines: list[str] = []
    prologue: list[str] = []
    for line in body.splitlines():
        match = _SECTION_HEADING.match(line.strip())
        if match:
            if heading is not None:
                sections.append((heading, "\n".join(lines).strip()))
            heading = match.group(1).strip()
            lines = ["# " + heading]
        elif heading is None:
            prologue.append(line)
        else:
            lines.append(line)
    if heading is None:
        raise ReportSpecError(
            f"{source_label} contains no '# ' section headings; at least one "
            "top-level '# ' heading is required"
        )
    sections.append((heading, "\n".join(lines).strip()))
    prologue = [line for line in prologue if line.strip()]
    if prologue:
        raise ReportSpecError(
            f"{source_label} has prose before the first '# ' section heading "
            "(frontmatter is the only allowed prologue); move it into a section"
        )
    return file_meta, sections


def sections_from_report_spec(spec_path: str | Path) -> list[SectionSource]:
    """Normalize one ``REPORT.md`` (case default or explicit path) into sections."""
    path = Path(spec_path)
    if not path.is_file():
        raise ReportSpecError(f"report spec not found: {path}")
    text = path.read_text(encoding="utf-8")
    file_meta, raw_sections = split_report_spec_sections(text, str(path))
    if len(raw_sections) > MAX_REPORT_SECTIONS:
        raise ReportSpecError(
            f"{path} defines {len(raw_sections)} sections; the report key scheme "
            f"(two-digit order prefix) supports at most {MAX_REPORT_SECTIONS}"
        )
    seen: dict[str, str] = {}
    sources: list[SectionSource] = []
    for position, (heading, section_text) in enumerate(raw_sections, start=1):
        slug = section_slug(heading)
        previous = seen.get(slug)
        if previous is not None:
            raise ReportSpecError(
                f"{path} has duplicate section headings resolving to the same "
                f"section key slug {slug!r}: #{previous} and #{position} — "
                "merge them explicitly or rename one heading"
            )
        seen[slug] = str(position)
        sources.append(
            SectionSource(
                section_key=f"{position:02d}_{slug}",
                body=section_text,
                meta=file_meta,
                source=str(path),
            )
        )
    return sources


def resolve_report_sources(
    case: Case,
    template_root: str | Path | None,
    report_spec: str | Path | None = None,
) -> list[SectionSource]:
    """Resolve the report section inputs for one run; parsing is fixed at run start.

    Priority: explicit ``REPORT.md`` path (``--report-spec``) > explicit
    ``--template-dir`` > case-root ``REPORT.md`` > seeded packaged template
    directory. ``template_root`` that already equals the case-local seeded
    directory counts as the default policy, so a case ``REPORT.md`` takes it.
    """
    if report_spec is not None:
        return sections_from_report_spec(report_spec)
    root = Path(template_root) if template_root is not None else None
    if root is not None and root.resolve() != case.report_template_dir.resolve():
        # Explicit --template-dir outranks the case REPORT.md (evaluation and
        # benchmark runs keep their declared template policy).
        return sections_from_template_dir(root)
    default_spec = case.path / REPORT_SPEC_FILENAME
    if default_spec.is_file():
        return sections_from_report_spec(default_spec)
    if root is not None:
        return sections_from_template_dir(root)
    from forensia.report.template_export import seed_case_report_templates

    seed_case_report_templates(case)
    return sections_from_template_dir(case.report_template_dir)


def report_input_paths(case: Case, report_spec: str | Path | None = None) -> set[Path]:
    """Input paths protected from being overwritten by report writes."""
    if report_spec is not None:
        return {Path(report_spec)}
    default_spec = case.path / REPORT_SPEC_FILENAME
    if default_spec.is_file():
        return {default_spec}
    return set()


def _normalized(path: Path) -> str:
    """Resolved, case-insensitive identity used for the input/output guard."""
    return os.path.normcase(str(Path(path).expanduser().resolve())).casefold()


def ensure_report_output_paths(
    case: Case,
    outputs: Iterable[Path],
    *,
    report_spec: str | Path | None = None,
) -> None:
    """Fail before any write when a report output would replace the report input.

    Resolved paths are compared case-insensitively (Windows/macOS mates and
    explicit output flags included). Raises :class:`ReportSpecError` naming the
    offending target.
    """
    inputs = {_normalized(path) for path in report_input_paths(case, report_spec)}
    if not inputs:
        return
    for output in outputs:
        target = _normalized(Path(output))
        if target in inputs:
            raise ReportSpecError(
                f"report output would overwrite the report input "
                f"{Path(output).resolve()}; REPORT.md must stay a read-only "
                "input (generated reports live under case/reports/, or pick a "
                "different --output)"
            )
