from __future__ import annotations

from unittest.mock import patch

from forensia.core.log import log, structure_progress_log


def test_progress_log_is_structured_by_shared_policy() -> None:
    assert structure_progress_log("[review] unresolved rewrite") == {
        "tag": "REVIEW",
        "level": "warning",
        "message": "unresolved rewrite",
    }
    assert structure_progress_log("[report] written: report.md")["level"] == "success"


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
