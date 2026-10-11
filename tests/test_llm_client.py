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
    assert (metadata.finish_reason, metadata.usage_source) == (
        "length",
        "local_estimate",
    )


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
