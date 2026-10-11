from __future__ import annotations

import asyncio
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from forensia.llm import llm_client, schema_compat


@pytest.fixture(autouse=True)
def _reset_schema_mode_cache(monkeypatch) -> None:
    schema_compat._SCHEMA_MODE_CACHE.clear()
    monkeypatch.setattr(llm_client.time, "sleep", lambda _seconds: None)


class _FakeClient:
    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = responses
        self.requests: list[dict] = []
        self.headers: list[dict[str, str]] = []

    def post(self, url: str, json: dict, headers: dict[str, str]) -> httpx.Response:
        self.requests.append(deepcopy(json))
        self.headers.append(headers)
        if not self._responses:
            raise AssertionError("unexpected extra request")
        return self._responses.pop(0)


def _response(
    status_code: int,
    *,
    text: str = "",
    content: str = "{}",
    finish_reason: str = "stop",
    usage: dict | None = None,
) -> httpx.Response:
    request = httpx.Request("POST", "http://llama.test/v1/chat/completions")
    if status_code == 200:
        payload = {
            "choices": [
                {"message": {"content": content}, "finish_reason": finish_reason}
            ]
        }
        if usage is not None:
            payload["usage"] = usage
        return httpx.Response(status_code, json=payload, request=request)
    return httpx.Response(status_code, text=text, request=request)


def test_investigation_scope_closes_sync_and_outage_probe_clients() -> None:
    class _SyncClient:
        closed = False

        def close(self) -> None:
            self.closed = True

    class _AsyncClient:
        closed = False

        async def aclose(self) -> None:
            self.closed = True

    sync_client = _SyncClient()
    async_client = _AsyncClient()
    llm_client._SYNC_CLIENTS[("scope-test", 11)] = sync_client
    llm_client._ASYNC_CLIENTS[("scope-test", 22)] = async_client

    asyncio.run(llm_client.close_llm_clients("scope-test"))

    assert sync_client.closed
    assert async_client.closed
    assert not any(key[0] == "scope-test" for key in llm_client._SYNC_CLIENTS)
    assert not any(key[0] == "scope-test" for key in llm_client._ASYNC_CLIENTS)


def test_provider_error_does_not_persist_api_key(tmp_path) -> None:
    from forensia.config import Settings, settings_scope
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.llm.telemetry import (
        LLMTelemetry,
        reset_active_telemetry,
        set_active_telemetry,
    )

    client = _FakeClient(
        [_response(401, text="Authorization Bearer secret-key rejected")]
    )
    with CaseDB(Case.init(tmp_path)) as db:
        token = set_active_telemetry(LLMTelemetry(db, session_id="secret-test"))
        try:
            with (
                settings_scope(Settings(llm_api_key="secret-key")),
                patch.object(llm_client, "_get_http_client", return_value=client),
            ):
                with pytest.raises(httpx.HTTPStatusError):
                    llm_client.chat_completion(
                        [{"role": "user", "content": "return json"}],
                        model="local-model",
                        base_url="http://llama.test",
                    )
            summary, body = db.execute(
                "SELECT error_body_summary, response_body FROM trace.llm_provider_attempts"
            ).fetchone()
        finally:
            reset_active_telemetry(token)
        for value in (summary, body):
            assert "secret-key" not in value
            assert "[redacted]" in value


def test_chat_completion_retries_llama_strict_schema_failure_with_compatible_schema() -> (
    None
):
    client = _FakeClient(
        [
            _response(500, text="Failed to parse input: grammar rejected"),
            _response(200, content='{"ok": true}', finish_reason="length"),
        ]
    )
    messages: list[str] = []
    schema = {
        "title": "TestOutput",
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
    }

    with (
        patch.object(llm_client, "_get_http_client", return_value=client),
        patch.object(
            llm_client,
            "get_settings",
            return_value=SimpleNamespace(llm_api_key="test-token"),
        ),
    ):
        result = llm_client.chat_completion(
            [{"role": "user", "content": "return json"}],
            model="local-model",
            base_url="http://llama.test",
            json_schema=schema,
            status_callback=messages.append,
        )

    assert result == '{"ok": true}'
    assert client.requests[0]["temperature"] == 0.0
    assert client.headers == [
        {"Authorization": "Bearer test-token"},
        {"Authorization": "Bearer test-token"},
    ]
    assert client.requests[0]["response_format"]["json_schema"]["strict"] is True
    assert "strict" not in client.requests[1]["response_format"]["json_schema"]
    assert any("compatible json_schema" in message for message in messages)
    assert all("grammar violation" not in message.lower() for message in messages)
    metadata = llm_client.get_last_completion_metadata()
    assert metadata is not None
    assert (
        metadata.finish_reason,
        metadata.input_tokens_source,
        metadata.output_tokens_source,
    ) == (
        "length",
        "local_estimate",
        "local_estimate",
    )


def test_usage_sources_are_tracked_per_token_side() -> None:
    client = _FakeClient(
        [_response(200, content='{"ok": true}', usage={"prompt_tokens": 12})]
    )

    with patch.object(llm_client, "_get_http_client", return_value=client):
        llm_client.chat_completion(
            [{"role": "user", "content": "return json"}],
            model="local-model",
            base_url="http://llama.test",
        )

    metadata = llm_client.get_last_completion_metadata()
    assert metadata is not None
    assert metadata.input_tokens_source == "provider_actual"
    assert metadata.output_tokens_source == "local_estimate"


def test_chat_completion_skips_strict_after_server_rejected_it_once() -> None:
    """Once a base_url has rejected strict, subsequent calls must not waste a round-trip retrying it."""
    client = _FakeClient(
        [
            _response(500, text="Failed to parse input: grammar rejected"),
            _response(200, content='{"ok": true}'),
            _response(200, content='{"ok": true}'),
        ]
    )
    schema = {
        "title": "TestOutput",
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
    }

    with patch.object(llm_client, "_get_http_client", return_value=client):
        llm_client.chat_completion(
            [{"role": "user", "content": "first"}],
            model="local-model",
            base_url="http://llama.test",
            json_schema=schema,
        )
        llm_client.chat_completion(
            [{"role": "user", "content": "second"}],
            model="local-model",
            base_url="http://llama.test",
            json_schema=schema,
        )

    assert len(client.requests) == 3
    assert "strict" not in client.requests[2]["response_format"]["json_schema"]
    assert client.requests[2]["response_format"]["json_schema"].get("schema") == schema


def test_chat_completion_removes_schema_only_after_compatible_schema_is_rejected() -> (
    None
):
    client = _FakeClient(
        [
            _response(400, text="strict schema unsupported"),
            _response(400, text="schema unsupported"),
            _response(200, content='{"ok": true}'),
        ]
    )
    schema = {
        "title": "TestOutput",
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
    }

    with patch.object(llm_client, "_get_http_client", return_value=client):
        result = llm_client.chat_completion(
            [{"role": "user", "content": "return json"}],
            model="local-model",
            base_url="http://llama.test",
            json_schema=schema,
        )

    assert result == '{"ok": true}'
    assert client.requests[0]["response_format"]["json_schema"]["strict"] is True
    assert "strict" not in client.requests[1]["response_format"]["json_schema"]
    assert "response_format" not in client.requests[2]


def test_context_window_400_does_not_downgrade_schema_or_resend() -> None:
    client = _FakeClient([_response(400, text="maximum context length exceeded")])
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}

    with patch.object(llm_client, "_get_http_client", return_value=client):
        with pytest.raises(llm_client.LLMContextWindowError):
            llm_client.chat_completion(
                [{"role": "user", "content": "return json"}],
                model="local-model",
                base_url="http://llama.test",
                json_schema=schema,
            )

    assert len(client.requests) == 1
    assert client.requests[0]["response_format"]["json_schema"]["strict"] is True


def test_outage_recovery_uses_health_endpoint_without_inference_request() -> None:
    class _HealthClient:
        def __init__(self) -> None:
            self.get_urls: list[str] = []
            self.post_calls = 0

        async def get(self, url, **kwargs):
            self.get_urls.append(url)
            return httpx.Response(200, request=httpx.Request("GET", url))

        async def post(self, *args, **kwargs):
            self.post_calls += 1
            raise AssertionError("health probe must not issue an inference request")

    client = _HealthClient()

    async def run() -> None:
        with patch.object(llm_client, "_get_async_client", return_value=client):
            await llm_client.outage_wait_until_recovered("http://llama.test")

    asyncio.run(run())
    assert client.get_urls == ["http://llama.test/v1/models"]
    assert client.post_calls == 0


def test_stop_during_successful_health_probe_prevents_retry_boundary() -> None:
    from threading import Event

    from forensia.core.control import InvestigationStopped, stop_scope

    stop = Event()

    class _HealthClient:
        async def get(self, url, **kwargs):
            stop.set()
            return httpx.Response(200, request=httpx.Request("GET", url))

    async def run() -> None:
        with (
            patch.object(llm_client, "_get_async_client", return_value=_HealthClient()),
            stop_scope(stop),
        ):
            with pytest.raises(InvestigationStopped):
                await llm_client.outage_wait_until_recovered("http://llama.test")

    asyncio.run(run())


def test_stop_during_http_wait_applies_after_provider_receipt() -> None:
    from threading import Event

    from forensia.core.control import InvestigationStopped, stop_scope

    started = Event()
    release = Event()

    class _BlockingClient:
        calls = 0

        def post(self, url, json, headers):
            self.calls += 1
            started.set()
            assert release.wait(timeout=2)
            return _response(200, content='{"ok": true}')

    client = _BlockingClient()
    stop = Event()

    async def run() -> None:
        with (
            patch.object(llm_client, "_get_http_client", return_value=client),
            stop_scope(stop),
        ):
            request = asyncio.create_task(
                asyncio.to_thread(
                    llm_client.chat_completion,
                    [{"role": "user", "content": "return JSON"}],
                    "local-model",
                    "http://llama.test",
                )
            )
            assert await asyncio.to_thread(started.wait, 2)
            stop.set()
            release.set()
            with pytest.raises(InvestigationStopped):
                await request

    asyncio.run(run())
    assert client.calls == 1


@pytest.mark.parametrize(
    ("status_code", "text", "with_schema"),
    [(400, "schema unsupported", True), (500, "provider error", False)],
)
def test_stop_after_http_error_closes_owned_logical_call(
    tmp_path, status_code: int, text: str, with_schema: bool
) -> None:
    from threading import Event

    from forensia.core.case import Case
    from forensia.core.control import InvestigationStopped, stop_scope
    from forensia.db.database import CaseDB
    from forensia.llm.telemetry import (
        LLMTelemetry,
        reset_active_telemetry,
        set_active_telemetry,
    )

    stop = Event()

    class _StopAfterResponseClient:
        def post(self, url, json, headers):
            stop.set()
            return _response(status_code, text=text)

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    with CaseDB(Case.init(tmp_path)) as db:
        token = set_active_telemetry(LLMTelemetry(db, session_id="stop-test"))
        try:
            with (
                patch.object(
                    llm_client,
                    "_get_http_client",
                    return_value=_StopAfterResponseClient(),
                ),
                stop_scope(stop),
                pytest.raises(InvestigationStopped),
            ):
                llm_client.chat_completion(
                    [{"role": "user", "content": "return JSON"}],
                    model="local-model",
                    base_url="http://llama.test",
                    json_schema=schema if with_schema else None,
                )
            call_status, attempt_status = db.execute(
                "SELECT c.status, a.status FROM trace.llm_logical_calls c "
                "JOIN trace.llm_provider_attempts a USING (logical_call_id)"
            ).fetchone()
        finally:
            reset_active_telemetry(token)

    assert call_status == "discarded"
    assert attempt_status == "provider_error"
