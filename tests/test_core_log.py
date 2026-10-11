from __future__ import annotations

import io
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from forensia.core.log import log
from forensia.core.progress_event import progress_event


def test_event_fields_are_explicit_and_message_does_not_set_severity() -> None:
    event = progress_event(
        "search.completed",
        "completed",
        summary="Search for failed logons completed",
        refs={"query_ids": ["Q-1"]},
    )
    assert event["kind"] == "search.completed"
    assert event["status"] == "completed"
    assert event["severity"] == "info"
    assert event["refs"] == {"query_ids": ["Q-1"]}


def test_event_rejects_unknown_severity_and_status() -> None:
    with pytest.raises(ValueError, match="severity"):
        progress_event("runtime.error", "failed", severity="critical")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="status"):
        progress_event("runtime.error", "error")  # type: ignore[arg-type]


def test_log_uppercases_display_tag_and_keeps_message_plain() -> None:
    with patch("builtins.print") as output:
        log("review", "[rewrite] needs attention", level="warning")
    assert output.call_args.args[0] == "[REVIEW] [WARNING] [REWRITE] needs attention"


def test_log_keeps_unicode_on_utf8_redirected_stdout() -> None:
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="utf-8")
    with redirect_stdout(stream):
        log("investigation", "調査 — complete")
    stream.flush()

    assert (
        buffer.getvalue().decode("utf-8") == "[INVESTIGATION] [INFO] 調査 — complete\n"
    )


def test_log_escapes_only_unencodable_text_for_cp932_stdout() -> None:
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp932")
    with redirect_stdout(stream):
        log("investigation", "調査 — complete")
    stream.flush()

    output = buffer.getvalue().decode("cp932")
    assert output == r"[INVESTIGATION] [INFO] 調査 \u2014 complete" + "\n"
