"""SQL fragments shared by keypoint definitions."""

from __future__ import annotations

from forensia.knowledge.catalog import (
    catalog_data_file_extensions,
    catalog_exe_globs,
    catalog_file_patterns,
    catalog_path_terms,
    exe_glob_sql,
)
from forensia.report.evidence_refs import (
    _extension_in_sql,
    _like_any_or_false,
    _path_like_any_or_false,
)

_BROWSER_EXE_SQL = exe_glob_sql(
    "executable_name", catalog_exe_globs("browser_artifacts")
)

_EMAIL_DATA_FILE_SQL = _like_any_or_false(
    "file_name", catalog_file_patterns("email_artifacts", "data_files")
)

_EMAIL_EXTENSION_SQL = _extension_in_sql(
    "extension", catalog_data_file_extensions("email_artifacts")
)

_EMAIL_PATH_SQL = _path_like_any_or_false(
    "file_path", catalog_path_terms("email_artifacts")
)

_CLOUD_PATH_SQL = _path_like_any_or_false(
    "file_path", catalog_path_terms("cloud_sync_artifacts")
)

_CLOUD_FILE_SQL = _like_any_or_false(
    "file_name",
    catalog_file_patterns(
        "cloud_sync_artifacts", "exe_patterns", "paths", "prefetch_names"
    ),
)
