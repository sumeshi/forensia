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


def test_log_uppercases_tag_and_uses_severity_color() -> None:
    with patch("forensia.core.log._rich_print") as output:
        log("review", "[rewrite] needs attention", level="warning")
    rendered = output.call_args.args[0]
    assert "REVIEW" in rendered
    assert "bold yellow" in rendered
    assert "REWRITE" in rendered
    assert "needs attention" in rendered


def test_log_normalizes_embedded_status_label() -> None:
    with patch("forensia.core.log._rich_print") as output:
        log("validation", "[error] unsafe markup", level="error")
    rendered = output.call_args.args[0]
    assert "bold red" in rendered
    assert "[ERROR] unsafe markup" in rendered
