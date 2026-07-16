"""Shared event predicates used by report answer and keypoint queries.

Keep semantic event classifications here so report surfaces cannot silently
disagree about whether a lifecycle event is evidence of anti-forensic action.
"""

# Security 1102 and Microsoft-Windows-Eventlog 104 indicate an audit/event log
# was cleared. Event 1100 only says the Event Log service stopped and therefore
# deliberately does not belong in this predicate.
LOG_CLEAR_EVENT_SQL = """(
    (event_id = 1102 AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
    OR (
        event_id = 104
        AND LOWER(COALESCE(
            json_extract_string(raw_json, '$.winlog.provider.name'), ''
        )) = 'microsoft-windows-eventlog'
    )
)"""
