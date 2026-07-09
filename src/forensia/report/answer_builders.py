"""Facade for structured answer builders, split into focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.report.answer_builders.
"""

from forensia.report.answer_builders_artifacts import (  # noqa: F401
    _browser_markers,
    _browser_name_for_row,
    _build_antiforensic_activity,
    _build_browser_usage,
    _build_cloud_service_traces,
    _build_desktop_rename_candidates,
    _cloud_markers,
    _infer_recent_lnk_rename_candidates,
    _parse_iso_datetime,
    _recent_lnk_base_name,
    _recent_lnk_tokens,
    _row_time_text,
)
from forensia.report.answer_builders_host import (  # noqa: F401
    _build_application_execution_history,
    _build_daily_session_activity,
    _build_daily_session_timeline,
    _build_daily_session_timeline_rows,
    _build_host_identity,
    _build_last_human_logon,
    _build_last_shutdown_event,
)
from forensia.report.answer_registry import (  # noqa: F401
    _STRUCTURED_ANSWER_BUILDERS,
    UNIVERSAL_QUESTION_SPECS,
    StructuredAnswerBuilder,
    _build_generic_question_spec_answer,
    _collect_answer_evidence_ids,
    _feed_structured_to_timeline,
    build_structured_answer,
    ensure_universal_question_probes,
)
