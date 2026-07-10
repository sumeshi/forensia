from __future__ import annotations

import os
from unittest import mock

from forensia import config
from forensia.ai.llm import llm_client
from forensia.report import answer_store


def test_reload_settings_updates_existing_imported_reference() -> None:
    original_settings = config.settings
    try:
        with mock.patch.dict(
            os.environ,
            {"LLM_OUTAGE_PROBE_INTERVAL_S": "7"},
        ):
            config.reload_settings()
            assert config.settings is original_settings
            assert llm_client.settings is original_settings
            assert llm_client.settings.llm_outage_probe_interval_s == 7
    finally:
        config.reload_settings()


def test_invalid_integer_environment_values_fall_back_to_defaults() -> None:
    try:
        with mock.patch.dict(
            os.environ,
            {
                "LLM_MAX_TOKENS": "not-an-int",
                "STRUCTURED_MARKDOWN_MAX_ROWS": "not-an-int",
            },
        ):
            config.reload_settings()
            assert config.settings.llm_max_tokens == 4096
            assert config.settings.structured_markdown_max_rows == 200
    finally:
        config.reload_settings()


def test_structured_answer_row_limit_uses_reloaded_setting() -> None:
    items = [{"value": index} for index in range(5)]
    try:
        with mock.patch.dict(
            os.environ,
            {"STRUCTURED_MARKDOWN_MAX_ROWS": "3"},
        ):
            config.reload_settings()
            rendered = answer_store.render_answer_block(items)
            assert any("| 0 |" in line for line in rendered)
            assert any("| 2 |" in line for line in rendered)
            assert not any("| 3 |" in line for line in rendered)
    finally:
        config.reload_settings()
