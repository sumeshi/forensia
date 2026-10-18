from __future__ import annotations

import os
from dataclasses import FrozenInstanceError
from unittest import mock

import pytest

from forensia import config


def test_settings_are_validated_and_frozen_for_scope() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "LLM_BASE_URL": "http://localhost:8080",
            "LLM_MODEL": "local-model",
            "LLM_TEMPERATURE": "0.25",
        },
    ):
        loaded = config.load_settings(require_inference=True)
    assert loaded.llm_model == "local-model"
    with config.settings_scope(loaded):
        assert config.get_settings() is loaded
        assert config.get_llm_settings()["temperature"] == 0.25
        with pytest.raises(FrozenInstanceError):
            loaded.llm_model = "changed"  # type: ignore[misc]
    assert config.get_settings() is not loaded


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LLM_MAX_TOKENS", "not-an-int"),
        ("LLM_TEMPERATURE", "nan"),
        ("LLM_TEMPERATURE", "2.1"),
        ("FORENSIA_OUTPUT_LANGUAGE", "klingon"),
        ("LLM_BASE_URL", "https://user:password@example.test"),
        ("LLM_BASE_URL", "http://example.test/v1"),
        ("LLM_BASE_URL", "http://example.test?token=secret"),
    ],
)
def test_invalid_environment_values_fail(name: str, value: str) -> None:
    with mock.patch.dict(os.environ, {name: value}):
        with pytest.raises(ValueError, match=name):
            config.load_settings()


def test_inference_endpoint_is_required_only_when_requested() -> None:
    with (
        mock.patch.dict(os.environ, {}, clear=True),
        mock.patch.object(config, "dotenv_values", return_value={}),
    ):
        assert config.load_settings().llm_base_url is None
        with pytest.raises(ValueError, match="LLM_BASE_URL, LLM_MODEL"):
            config.load_settings(require_inference=True)


def test_settings_snapshot_does_not_follow_later_environment_changes() -> None:
    with mock.patch.dict(os.environ, {"LLM_MODEL": "first"}):
        loaded = config.load_settings()
    with mock.patch.dict(os.environ, {"LLM_MODEL": "second"}):
        with config.settings_scope(loaded):
            assert config.get_settings().llm_model == "first"


def test_each_load_reads_current_dotenv_file_values(monkeypatch) -> None:
    values = {"LLM_MODEL": "first"}
    monkeypatch.setattr(config, "dotenv_values", lambda _path: values)
    with mock.patch.dict(os.environ, {}, clear=True):
        assert config.load_settings().llm_model == "first"
        values["LLM_MODEL"] = "second"
        assert config.load_settings().llm_model == "second"


def test_environment_overrides_dotenv_values(monkeypatch) -> None:
    monkeypatch.setattr(config, "dotenv_values", lambda _path: {"LLM_MODEL": "file"})
    with mock.patch.dict(os.environ, {"LLM_MODEL": "environment"}, clear=True):
        assert config.load_settings().llm_model == "environment"


def test_execution_budgets_are_validated_and_loaded() -> None:
    with (
        mock.patch.dict(os.environ, {}, clear=True),
        mock.patch.object(config, "dotenv_values", return_value={}),
    ):
        assert (
            config.load_settings().max_llm_calls == config.Settings().max_llm_calls == 0
        )
    with mock.patch.dict(
        os.environ,
        {
            "FORENSIA_MAX_ITERATIONS": "12",
            "FORENSIA_MAX_QUERIES_PER_HYPOTHESIS": "4",
            "LLM_MAX_CALLS": "80",
        },
    ):
        settings = config.load_settings()
    assert (
        settings.max_iterations,
        settings.max_queries_per_hypothesis,
        settings.max_llm_calls,
    ) == (12, 4, 80)


def test_direct_settings_reject_non_string_output_language() -> None:
    with pytest.raises(ValueError, match="llm_output_language"):
        config.Settings(llm_output_language=[])


def test_probe_interval_over_budget_is_rejected() -> None:
    with (
        mock.patch.dict(
            os.environ,
            {
                "LLM_OUTAGE_WALL_CLOCK_BUDGET_S": "10",
                "LLM_OUTAGE_PROBE_INTERVAL_S": "11",
            },
        ),
        pytest.raises(ValueError, match="cannot exceed outage budget"),
    ):
        config.load_settings()


def test_secret_is_only_present_in_runtime_settings() -> None:
    with mock.patch.dict(os.environ, {"LLM_API_KEY": "secret-for-request"}):
        loaded = config.load_settings()
    assert loaded.llm_api_key == "secret-for-request"
    assert "secret-for-request" not in repr(loaded)
