from __future__ import annotations

from unittest.mock import patch

from forensia.core.log import format_progress_log, log, structure_progress_log


def test_progress_log_tag_is_parsed_and_level_is_producer_decided() -> None:
    assert structure_progress_log("[review] unresolved rewrite") == {
        "tag": "REVIEW",
        "level": "info",
        "message": "unresolved rewrite",
    }
    assert structure_progress_log("[final-refresh] failed", level="error")["level"] == (
        "error"
    )
    written = structure_progress_log("[report] written: report.md", level="success")
    assert format_progress_log(written) == "[REPORT] written: report.md"


def test_evidence_names_do_not_become_processing_failures() -> None:
    """The failed-logon rule id names evidence, not a processing error."""
    assert (
        structure_progress_log("[query] searching for failed logons")["level"] == "info"
    )


def test_unknown_producer_level_falls_back_to_info() -> None:
    assert structure_progress_log("[tag] message", level="critical")["level"] == "info"


def test_log_uppercases_tag_and_keeps_message_plain() -> None:
    with patch("builtins.print") as output:
        log("review", "[rewrite] needs attention", level="warning")
    rendered = output.call_args.args[0]
    assert rendered == "[REVIEW] [REWRITE] needs attention"


def test_log_normalizes_embedded_status_label() -> None:
    with patch("builtins.print") as output:
        log("validation", "[error] unsafe markup", level="error")
    rendered = output.call_args.args[0]
    assert rendered == "[VALIDATION] [ERROR] unsafe markup"
