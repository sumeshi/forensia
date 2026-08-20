from __future__ import annotations

from copy import deepcopy
from unittest.mock import patch

import httpx
import pytest

from forensia.ai.llm import llm_client


@pytest.fixture(autouse=True)
def _reset_schema_mode_cache() -> None:
    llm_client._SCHEMA_MODE_CACHE.clear()


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
        patch.object(llm_client.settings, "llm_api_key", "test-token"),
    ):
        result = llm_client.chat_completion(
            [{"role": "user", "content": "return json"}],
            model="local-model",
            base_url="http://llama.test",
            json_schema=schema,
            status_callback=messages.append,
        )

    assert result == '{"ok": true}'
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
    assert (metadata.finish_reason, metadata.usage_source) == ("length", "estimated")


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
