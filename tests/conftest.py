"""The software contract suite must never contact an actual LLM provider."""

from __future__ import annotations

import shutil
from importlib.metadata import version
from pathlib import Path

import httpx
import pytest


@pytest.fixture(scope="session")
def test_rules_install(tmp_path_factory):
    root = tmp_path_factory.mktemp("rules-install")
    path = root / "forensia/sigma" / version("forensia") / "sigma_bundle.json"
    path.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).parent / "fixtures/sigma/sigma_bundle.json", path)
    return root, path


@pytest.fixture(autouse=True)
def installed_test_rules(monkeypatch, test_rules_install):
    """Upstream regression data is a test input, never a package resource."""
    root, path = test_rules_install
    monkeypatch.setenv("XDG_DATA_HOME", str(root))
    monkeypatch.setattr("forensia.knowledge.resources.sigma_bundle_path", lambda: path)


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
