"""Shared event predicates used by report answer and keypoint queries.

Keep semantic event classifications here so report surfaces cannot silently
disagree about whether a lifecycle event is evidence of anti-forensic action.
"""

from forensia.knowledge.catalog import event_context_sql

EXECUTION_EVENT_SQL = event_context_sql([4688, 4104])
LOGON_EVENT_SQL = event_context_sql([4624, 4625, 4634, 4647, 4648])
SESSION_EVENT_SQL = event_context_sql([4624, 4634, 4647])
SERVICE_TASK_EVENT_SQL = event_context_sql([4697, 4698, 4699, 4700, 4701, 4702, 7045])
SUCCESS_LOGON_EVENT_SQL = event_context_sql([4624])
FAILED_LOGON_EVENT_SQL = event_context_sql([4625])
LOGOFF_EVENT_SQL = event_context_sql([4634, 4647])
SECURITY_SERVICE_TASK_EVENT_SQL = event_context_sql(
    [4697, 4698, 4699, 4700, 4701, 4702]
)
SCHEDULED_TASK_EVENT_SQL = event_context_sql([4698, 4699])
SYSTEM_SHUTDOWN_EVENT_SQL = event_context_sql([1074, 6006, 6008])
SYSTEM_STARTUP_EVENT_SQL = event_context_sql([6005])
SECURITY_BOOT_EVENT_SQL = event_context_sql([4608, 4609])

# Security 1102 and Microsoft-Windows-Eventlog 104 indicate an audit/event log
# was cleared. Event 1100 only says the Event Log service stopped and therefore
# deliberately does not belong in this predicate.
LOG_CLEAR_EVENT_SQL = event_context_sql([1102, 104])
