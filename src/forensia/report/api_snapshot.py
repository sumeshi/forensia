"""Report-layer snapshot helpers for the API cache.

Building the report-sections and report-brief JSON snapshots requires
server-side Markdown/HTML rendering that lives in the reporting layer.
Keeping these helpers here avoids an upward dependency from the platform
``api`` layer into ``report``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from forensia.api.cache import (
    snapshot_dir,
    write_json,
    write_platform_snapshots,
    write_snapshot_metadata,
    write_volatile_api_snapshots,
)
from forensia.report.report_brief import write_report_brief
from forensia.report.section_views import list_report_sections_dto

if TYPE_CHECKING:
    from forensia.core.case import Case
    from forensia.db.database import CaseDB


def write_report_api_snapshots(
    case: Case, db: CaseDB, *, volatile: bool = False
) -> None:
    """Write report-related API snapshots.

    When *volatile* is ``True`` only the sections snapshot is written
    (suitable for mid-investigation refreshes).  When ``False`` both
    sections and the full report brief are written.
    """
    snap_dir = snapshot_dir(case)
    write_json(
        snap_dir / "report_sections.json",
        [item.model_dump(mode="json") for item in list_report_sections_dto(db)],
    )
    if not volatile:
        write_json(snap_dir / "report_brief.json", write_report_brief(case, db))
    write_snapshot_metadata(case, db)


def write_all_snapshots(case: Case, db: CaseDB) -> None:
    """Write all API snapshots including report data.

    Single entry point for callers — writes both platform-layer DTO snapshots
    and report-layer section/brief snapshots so callers cannot forget one half.
    """
    write_platform_snapshots(case, db)
    write_report_api_snapshots(case, db)


def write_volatile_snapshots(case: Case, db: CaseDB) -> None:
    """Write mid-investigation volatile snapshots (core + report sections)."""
    write_volatile_api_snapshots(case, db)
    write_report_api_snapshots(case, db, volatile=True)
