"""The assembled investigation guidance must carry its declaration-backed policy."""

from forensia.context.sql_schema import build_investigation_framework


def test_investigation_framework_contains_reference_and_read_only_policy() -> None:
    framework = build_investigation_framework()
    for required in (
        "LogonType reference",
        "RemoteInteractive",
        "Application categorization guidance",
        "evtx_events",
        "mft_entries",
        "prefetch_executions",
        "Only propose SELECT or WITH-prefixed read-only SQL",
        "never store a machine account in source_ip",
    ):
        assert required in framework
