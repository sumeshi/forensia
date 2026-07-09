"""Facade for report keypoints, split into focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.report.keypoints.
"""

from forensia.report.evidence_refs import (  # noqa: F401
    EVIDENCE_ID_PATTERN,
    EvidenceResolver,
    _extension_in_sql,
    _extract_evidence_ids_from_value,
    _extract_needed_evidence,
    _like_any_or_false,
    _path_like_any,
    _path_like_any_or_false,
    _report_keypoint_rows,
    _row_with_evidence_ids,
    _sql_like_any,
    _summarize_rows,
)
from forensia.report.keypoint_catalog import (  # noqa: F401
    _BROWSER_EXE_SQL,
    _CLOUD_FILE_SQL,
    _CLOUD_PATH_SQL,
    _EMAIL_DATA_FILE_SQL,
    _EMAIL_EXTENSION_SQL,
    _EMAIL_PATH_SQL,
    REPORT_KEYPOINT_ALIASES,
    REPORT_KEYPOINTS,
    _default_keypoints_for_section,
    _load_keypoint_cards,
    _question_spec_keypoint_rows,
    _resolve_evidence_results,
)
