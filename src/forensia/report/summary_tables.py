"""Facade for report summary tables, split into focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.report.summary_tables.
"""

from forensia.report.finding_themes import (  # noqa: F401
    _FINDING_THEME_FILTER_SQL,
    _build_key_findings_table,
    _build_recommendations_table,
    _finding_theme,
    _finding_theme_counts,
    _finding_theme_rank,
    _finding_theme_recommended_action,
    _finding_theme_summary,
    _finding_theme_title,
    _load_finding_theme_specs,
    _max_severity,
    _severity_rank,
    _signal_finding_rows,
)
from forensia.report.gap_tables import (  # noqa: F401
    _build_evidence_gaps_table,
    _build_gaps_confirmed_table,
    _build_gaps_unresolved_table,
    _build_gaps_untestable_table,
    _count_findings_with_tag,
    _forensic_gap_rows,
    _has_antiforensic_executions,
    _hypothesis_count,
    _hypothesis_rows,
    _section_gap_rows,
)
from forensia.report.summary_rows import (  # noqa: F401
    _account_summary_rows,
    _antiforensic_rows,
    _as_int,
    _count_table,
    _event_interpretation,
    _execution_rows,
    _file_artifact_rows,
    _first_nonempty,
    _host_summary_rows,
    _network_summary_rows,
    _phase_interpretation,
    _sample_labels,
    _sentence_list,
    _signal_executable_labels,
    _timeline_phase_rows,
    _timeline_rows,
)
from forensia.report.table_registry import (  # noqa: F401
    _TABLE_BLOCK_BUILDERS,
    _TABLE_COLUMNS,
    _build_accounts_table,
    _build_antiforensic_table,
    _build_evidence_scope_table,
    _build_execution_table,
    _build_file_artifacts_table,
    _build_network_table,
    _build_systems_observed_table,
    _build_timeline_chronological_table,
    _build_timeline_phase_table,
    _collect_flat_evidence_rows,
    _load_table_captions,
    _row_to_summary_line,
    _summarize_flat_evidence_rows,
    _table_block_columns,
    render_table_block,
)
