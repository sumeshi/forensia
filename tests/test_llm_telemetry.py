from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

from forensia.ai.llm import llm_client
from forensia.ai.llm_telemetry import (
    LLMTelemetry,
    set_active_telemetry,
    telemetry_scope,
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
        phase="report-section-block",
        op_type="render",
        target="appendix-24",
        duration_ms=5,
    )
    agg = telemetry.session_aggregates()
    assert agg["provider_attempt_count"] == 0
    assert agg["deterministic_op_count"] == 1
    rows = telemetry.db.execute(
        "SELECT op_type, target FROM llm_deterministic_ops"
    ).fetchall()
    assert rows[0] == ("render", "appendix-24")


def test_logical_call_inherits_hypothesis_scope(telemetry) -> None:
    with telemetry_scope(hypothesis_id="H-CHAIN", iteration=3):
        logical_call_id = telemetry.begin_logical_call(phase="hypothesis_plan")

    row = telemetry.db.execute(
        "SELECT hypothesis_id, iteration FROM llm_logical_calls "
        "WHERE logical_call_id = ?",
        (logical_call_id,),
    ).fetchone()
    assert row == ("H-CHAIN", 3)


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
        "SELECT status, http_status, retry_ordinal, request_body, response_body "
        "FROM llm_provider_attempts ORDER BY retry_ordinal"
    ).fetchall()
    # one failed 500 attempt + one success attempt
    assert rows[0][0] == "provider_error" and rows[0][1] == 500
    assert rows[1][0] == "success" and rows[1][1] == 200
    assert json.loads(rows[0][3])["messages"] == [
        {"role": "user", "content": "go"}
    ]
    assert rows[0][4] == "boom"
    assert json.loads(rows[1][4])["choices"][0]["message"]["content"] == '{"ok": true}'
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

    messages: list[str] = []
    with (
        patch.object(llm_client, "_get_http_client", return_value=_FakeClient()),
        patch.object(llm_client.settings, "llm_api_key", "tok"),
    ):
        with pytest.raises(llm_client.LLMRequestTimeoutError):
            llm_client.chat_completion(
                [{"role": "user", "content": "go"}],
                model="m",
                base_url="http://llama.test",
                status_callback=messages.append,
            )
    set_active_telemetry(None)

    rows = db.execute(
        "SELECT status, error_type, deadline_fired FROM llm_provider_attempts"
    ).fetchall()
    assert rows[0][0] == "timeout"
    assert rows[0][1] == "timeout"
    assert rows[0][2] == "read"
    assert len(rows) == 1
    assert messages == ["LLM request timed out; not replaying it as an outage"]


def _truncated_response() -> httpx.Response:
    req = httpx.Request("POST", "http://llama.test/v1/chat/completions")
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": '{"ok":'}, "finish_reason": "length"}]
        },
        request=req,
    )


def _assert_truncation_receipt(db: CaseDB, session_id: str) -> None:
    calls = db.execute(
        "SELECT status FROM llm_logical_calls WHERE session_id = ?", (session_id,)
    ).fetchall()
    assert calls == [("failed",)]
    row = db.execute(
        """
        SELECT status, error_type, parse_status, finish_reason, truncated,
               accepted, discarded_reason, error_body_summary, response_fingerprint,
               request_body, response_body
        FROM llm_provider_attempts WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()
    assert row[:7] == (
        "parse_error",
        "truncated",
        "truncated",
        "length",
        True,
        False,
        "finish_reason=length",
    )
    assert "content_head='{" in row[7]
    assert len(row[8]) == 24
    assert json.loads(row[9])["messages"] == [{"role": "user", "content": "go"}]
    assert json.loads(row[10])["choices"][0]["message"]["content"] == '{"ok":'


def test_unusable_truncation_closes_owned_call_failed_and_marks_attempt(
    tmp_path,
) -> None:
    """Shared sync/async invariant: unusable truncation raises LLMOutputTruncatedError,
    leaves the owned logical call failed, and the attempt receipt terminal and explicit."""
    case = Case.init(tmp_path)
    db = CaseDB(case)

    # --- sync path ---
    tel = LLMTelemetry(db, session_id="S-sync")
    set_active_telemetry(tel)

    class _FakeClient:
        def post(self, url, json, headers):
            return _truncated_response()

    with (
        patch.object(llm_client, "_get_http_client", return_value=_FakeClient()),
        patch.object(llm_client.settings, "llm_api_key", "tok"),
    ):
        with pytest.raises(llm_client.LLMOutputTruncatedError):
            llm_client.chat_completion(
                [{"role": "user", "content": "go"}],
                model="m",
                base_url="http://llama.test",
            )
    set_active_telemetry(None)
    _assert_truncation_receipt(db, "S-sync")
    assert tel.session_aggregates()["provider_attempt_count"] == 1

    # --- async path ---
    tel_a = LLMTelemetry(db, session_id="S-async")
    set_active_telemetry(tel_a)

    class _FakeAsyncClient:
        async def post(self, url, json, headers):
            return _truncated_response()

    async def _fake_async_client():
        return _FakeAsyncClient()

    async def _run() -> None:
        with (
            patch.object(llm_client, "_get_async_client", new=_fake_async_client),
            patch.object(llm_client.settings, "llm_api_key", "tok"),
        ):
            with pytest.raises(llm_client.LLMOutputTruncatedError):
                await llm_client.async_chat_completion(
                    [{"role": "user", "content": "go"}],
                    model="m",
                    base_url="http://llama.test",
                )

    asyncio.run(_run())
    set_active_telemetry(None)
    _assert_truncation_receipt(db, "S-async")
    assert tel_a.session_aggregates()["provider_attempt_count"] == 1

    # JSON-level recovery must change the request without exceeding the configured
    # model completion cap. Keep this in the existing truncation contract test.
    from forensia.ai.llm import json_response

    attempts: list[dict] = []

    def _recover_once(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            raise llm_client.LLMOutputTruncatedError("length", content='{"ok":')
        return '{"ok": true}'

    with (
        patch.object(json_response, "chat_completion", side_effect=_recover_once),
        patch.object(
            json_response, "get_llm_settings", return_value={"max_tokens": 16384}
        ),
    ):
        parsed = json_response.request_llm_json(
            [{"role": "user", "content": "return json"}],
            base_url="http://llama.test",
            model="m",
        )
    assert parsed == {"ok": True}
    assert [attempt["max_tokens"] for attempt in attempts] == [16384, 16384]
    assert "<RETRY_CONSTRAINT>" in attempts[1]["messages"][-1]["content"]
