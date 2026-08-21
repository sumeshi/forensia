"""Static SQL cookbook data kept separate from prompt assembly."""

from forensia.knowledge.catalog import expand_catalog_sql_placeholders

SQL_COOKBOOK = """
<SQL_COOKBOOK>
These are reference SQL snippets to copy and adapt. They are NOT templates — do not put their headings into the `template_id` field. To use a real template, pick a `template_id` value from `template_catalog`.

-- Enumerate occurrences of one or more event IDs --
SELECT event_id, timestamp, computer, user_name, target_user, raw_json
FROM evtx_events
WHERE event_id IN (4624, 4625)
ORDER BY timestamp
LIMIT 200;

-- Filter by time window --
SELECT event_id, timestamp, computer
FROM evtx_events
WHERE event_id = 7045
  AND timestamp BETWEEN '2024-05-14 00:00:00' AND '2024-05-17 23:59:59'
ORDER BY timestamp;

-- Per-user logon summary --
SELECT user_name, logon_type, COUNT(*) AS n, MIN(timestamp) AS first, MAX(timestamp) AS last
FROM evtx_events
WHERE event_id = 4624
GROUP BY 1, 2
ORDER BY n DESC;

-- Fall back to raw_json when a column is NULL (use json_extract_string for VARCHAR-typed cols) --
SELECT timestamp, COALESCE(user_name, json_extract_string(raw_json, '$.TargetUserName')) AS user
FROM evtx_events
WHERE event_id = 4720
ORDER BY timestamp;

-- Find file activity by path pattern (MFT) --
SELECT file_path, file_name, si_modified, is_deleted
FROM mft_entries
WHERE LOWER(file_path) LIKE '%/desktop/%'
  AND extension IN ('docx', 'xlsx', 'pptx', 'doc', 'ppt', 'xls')
ORDER BY si_modified DESC
LIMIT 100;

-- Recent application executions (Prefetch) --
SELECT executable_name, exec_count, last_exec_time
FROM prefetch_executions
WHERE {{catalog_exe_sql:antiforensic_tools:executable_name}}
ORDER BY last_exec_time DESC;
</SQL_COOKBOOK>
"""


def sql_cookbook() -> str:
    return expand_catalog_sql_placeholders(SQL_COOKBOOK)
