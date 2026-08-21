from __future__ import annotations

import pytest

from forensia.ai.llm import llm_client
from forensia.ai.llm_telemetry import (
    LLMTelemetry,
    set_active_telemetry,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


@pytest.fixture()
def telemetry(tmp_path) -> LLMTelemetry:
    case = Case.init(tmp_path)
    db = CaseDB(case)
    return LLMTelemetry(db, session_id="S-1")


def test_deterministic_op_is_not_counted_as_llm_attempt(telemetry) -> None:
    telemetry.record_deterministic_op(
        phase="report-section-block", op_type="render", target="appendix-24",
        duration_ms=5,
    )
    agg = telemetry.session_aggregates()
    assert agg["provider_attempt_count"] == 0
    assert agg["deterministic_op_count"] == 1
    rows = telemetry.db.execute(
        "SELECT op_type, target FROM llm_deterministic_ops"
    ).fetchall()
    assert rows[0] == ("render", "appendix-24")


def test_client_creates_attempt_receipts_for_retry_then_success(
    tmp_path, monkeypatch
) -> None:
    from unittest.mock import patch

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-2")
    set_active_telemetry(tel)

    class _FakeClient:
        def __init__(self):
            self.calls = 0

        def post(self, url, json, headers):
            self.calls += 1
            if self.calls == 1:
                return httpx_500()
            return httpx_200()

    def httpx_500():
        import httpx

        req = httpx.Request("POST", "http://llama.test/v1/chat/completions")
        return httpx.Response(500, text="boom", request=req)

    def httpx_200():
        import httpx

        req = httpx.Request("POST", "http://llama.test/v1/chat/completions")
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
            request=req,
        )

    fake = _FakeClient()
    with (
        patch.object(llm_client, "_get_http_client", return_value=fake),
        patch.object(llm_client.settings, "llm_api_key", "tok"),
    ):
        result = llm_client.chat_completion(
            [{"role": "user", "content": "go"}],
            model="m",
            base_url="http://llama.test",
        )
    assert result == '{"ok": true}'
    set_active_telemetry(None)

    rows = db.execute(
        "SELECT status, http_status, retry_ordinal FROM llm_provider_attempts ORDER BY retry_ordinal"
    ).fetchall()
    # one failed 500 attempt + one success attempt
    assert rows[0][0] == "provider_error" and rows[0][1] == 500
    assert rows[1][0] == "success" and rows[1][1] == 200
    assert tel.session_aggregates()["logical_call_count"] == 1


def test_client_creates_timeout_attempt_receipt(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    import httpx

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-3")
    set_active_telemetry(tel)

    class _FakeClient:
        def post(self, url, json, headers):
            raise httpx.TimeoutException("read timeout")

    with (
        patch.object(llm_client, "_get_http_client", return_value=_FakeClient()),
        patch.object(llm_client.settings, "llm_api_key", "tok"),
    ):
        with pytest.raises(llm_client.LLMServerUnavailableError):
            llm_client.chat_completion(
                [{"role": "user", "content": "go"}],
                model="m",
                base_url="http://llama.test",
            )
    set_active_telemetry(None)

    rows = db.execute(
        "SELECT status, error_type, deadline_fired FROM llm_provider_attempts"
    ).fetchall()
    assert rows[0][0] == "timeout"
    assert rows[0][1] == "timeout"
    assert rows[0][2] == "read"
