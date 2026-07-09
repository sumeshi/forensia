"""Benchmark-evaluation keypoint aliases.

These map benchmark-question-oriented keypoint names to the *generic* keypoint
implementations defined in :mod:`forensia.report.keypoint_catalog`. They exist only to
let the optional external CFReDS benchmark report template (see ``BENCHMARK.md``)
address report tables by question-oriented names.

They are deliberately kept out of the generic alias map in ``keypoints.py`` so
that the everyday report code carries no benchmark-question-specific names
(see CLAUDE.md Rule 16 — the benchmark is a measuring instrument, not an
optimization target). None of the report templates bundled with forensia
reference these aliases; deleting this module would not change the output of a
normal, non-benchmark report.

Each value on the right-hand side must be a real keypoint name registered in
``REPORT_KEYPOINTS`` (``keypoints.py``); the resolver validates this at runtime.
"""

from __future__ import annotations

# Benchmark keypoint alias -> generic keypoint name (registered in keypoints.py).
BENCHMARK_KEYPOINT_ALIASES: dict[str, str] = {
    "benchmark_window": "overview_event_range",
    "benchmark_hosts": "overview_hosts",
    "benchmark_logon_window": "session_activity_events",
    "benchmark_timeline_events": "timeline_system_events",
    "benchmark_timeline_files": "timeline_mft_activity",
    "benchmark_prefetch_recent": "timeline_prefetch_history",
    "benchmark_host_spans": "overview_hosts",
    "benchmark_host_logons": "session_activity_events",
    "benchmark_accounts_summary": "account_all_logon_summary",
    "benchmark_accounts_events": "account_logon_events",
    "benchmark_accounts_observed": "account_observed_users",
    "benchmark_exec_processes": "host_execution_activity",
    "benchmark_exec_related_mft": "mft_user_app_activity",
    "benchmark_artifact_processes": "mft_prefetch_filenames",
    "benchmark_artifact_paths": "ioc_user_data_files",
    "benchmark_ost_file": "ioc_email_ost_files",
    "benchmark_recent_lnk": "mft_recent_folder_lnk",
    "benchmark_reco_system_events": "timeline_system_events",
    "benchmark_reco_desktop_paths": "ioc_user_data_files",
    "benchmark_last_shutdown": "structured_last_shutdown",
    "benchmark_daily_logon_shutdown": "structured_daily_session_activity",
    "benchmark_browser_artifacts": "structured_browser_artifacts",
    "benchmark_email_ost_paths": "structured_email_artifacts",
    "benchmark_desktop_rename_candidates": "structured_desktop_rename_candidates",
    "benchmark_resignation_file": "structured_resignation_files",
    "benchmark_cloud_artifacts": "structured_cloud_artifacts",
    "benchmark_antiforensics_last_day": "structured_antiforensics",
}
