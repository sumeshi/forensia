"""The software contract suite must never contact an actual LLM provider."""

from __future__ import annotations

import httpx
import pytest


@pytest.fixture(autouse=True)
def offline_transport(monkeypatch):
    attempted: list[str] = []

    def reject(_transport, request):
        attempted.append(str(request.url))
        raise AssertionError(f"Unmocked HTTP request: {request.url}")

    async def reject_async(transport, request):
        reject(transport, request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", reject)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", reject_async)
    yield
    # A broad application fallback must not conceal accidental network access.
    assert not attempted, f"Unmocked HTTP requests: {attempted}"
