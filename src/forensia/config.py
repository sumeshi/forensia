from __future__ import annotations

import os
from dataclasses import dataclass, fields
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_max_tokens: int = 4096
    llm_thinking_language: str = "en"
    llm_output_language: str = "ja"
    llm_memory_max_bytes: int = 16384
    llm_report_max_queries_per_section: int = 3
    llm_reasoning_reserve_tokens: int = 0
    forensia_system_prompt_budget_chars: int = 24000
    # 0 = derive from the configured system-character budget.
    forensia_prompt_budget_tokens: int = 0
    forensia_ui_origins: str = ""
    structured_markdown_max_rows: int = 200
    llm_outage_wall_clock_budget_s: int = 28800
    llm_outage_probe_interval_s: int = 60


def _env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    raw_value = os.getenv(name)
    try:
        value = default if raw_value is None else int(raw_value)
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _build_settings() -> Settings:
    return Settings(
        llm_base_url=os.getenv("LLM_BASE_URL"),
        llm_model=os.getenv("LLM_MODEL"),
        llm_max_tokens=_env_int("LLM_MAX_TOKENS", 4096, minimum=1),
        llm_thinking_language=os.getenv("LLM_THINKING_LANGUAGE", "en"),
        llm_output_language=os.getenv("LLM_OUTPUT_LANGUAGE", "ja"),
        llm_memory_max_bytes=_env_int("LLM_MEMORY_MAX_BYTES", 16384, minimum=1),
        llm_report_max_queries_per_section=_env_int(
            "LLM_REPORT_MAX_QUERIES_PER_SECTION", 3, minimum=1
        ),
        llm_reasoning_reserve_tokens=_env_int(
            "LLM_REASONING_RESERVE_TOKENS", 0, minimum=0
        ),
        forensia_system_prompt_budget_chars=_env_int(
            "FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS", 24000, minimum=1
        ),
        forensia_prompt_budget_tokens=_env_int(
            "FORENSIA_PROMPT_BUDGET_TOKENS", 0, minimum=0
        ),
        forensia_ui_origins=os.getenv("FORENSIA_UI_ORIGINS", ""),
        structured_markdown_max_rows=_env_int(
            "STRUCTURED_MARKDOWN_MAX_ROWS", 200, minimum=1
        ),
        llm_outage_wall_clock_budget_s=_env_int(
            "LLM_OUTAGE_WALL_CLOCK_BUDGET_S", 28800, minimum=1
        ),
        llm_outage_probe_interval_s=_env_int(
            "LLM_OUTAGE_PROBE_INTERVAL_S", 60, minimum=1
        ),
    )


settings = _build_settings()


def reload_settings() -> None:
    refreshed = _build_settings()
    for field in fields(Settings):
        setattr(settings, field.name, getattr(refreshed, field.name))
    clear_llm_settings_cache()


def resolve_llm_config(
    base_url: str | None = None,
    model: str | None = None,
) -> tuple[str | None, str | None]:
    resolved_endpoint = base_url or settings.llm_base_url
    resolved_model = model or settings.llm_model
    return resolved_endpoint, resolved_model


@lru_cache(maxsize=1)
def get_llm_settings() -> dict:
    return {
        "max_tokens": settings.llm_max_tokens,
        "thinking_language": settings.llm_thinking_language,
        "output_language": settings.llm_output_language,
        "memory_max_bytes": settings.llm_memory_max_bytes,
        "report_max_queries_per_section": settings.llm_report_max_queries_per_section,
        "reasoning_reserve_tokens": settings.llm_reasoning_reserve_tokens,
    }


def clear_llm_settings_cache() -> None:
    get_llm_settings.cache_clear()


def get_system_prompt_budget_chars() -> int:
    return settings.forensia_system_prompt_budget_chars


def get_prompt_budget_tokens() -> int:
    """Return the total prompt budget, explicitly configured or auto-derived."""
    configured = settings.forensia_prompt_budget_tokens
    if configured > 0:
        return configured
    return max(512, settings.forensia_system_prompt_budget_chars // 2)
