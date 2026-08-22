from __future__ import annotations

import os
from dataclasses import dataclass, fields
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()

DEFAULT_PROMPT_BUDGET_TOKENS = 12000


@dataclass
class Settings:
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    llm_max_tokens: int = 4096
    llm_output_language: str = "ja"
    llm_memory_max_bytes: int = 0
    llm_report_max_queries_per_section: int = 3
    llm_reasoning_reserve_tokens: int = 0
    # 0 means unknown/auto; providers may still reject oversized requests.
    llm_context_window_tokens: int = 0
    forensia_system_prompt_budget_chars: int = 0
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
    except TypeError, ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _env_choice(name: str, default: str, choices: set[str]) -> str:
    value = os.getenv(name, default).strip().lower()
    return value if value in choices else default


def _build_settings() -> Settings:
    outage_budget_s = _env_int("LLM_OUTAGE_WALL_CLOCK_BUDGET_S", 28800, minimum=1)
    outage_probe_s = _env_int("LLM_OUTAGE_PROBE_INTERVAL_S", 60, minimum=1)
    return Settings(
        llm_base_url=os.getenv("LLM_BASE_URL"),
        llm_model=os.getenv("LLM_MODEL"),
        llm_api_key=os.getenv("LLM_API_KEY") or None,
        llm_max_tokens=_env_int("LLM_MAX_TOKENS", 4096, minimum=1),
        llm_output_language=_env_choice("FORENSIA_OUTPUT_LANGUAGE", "ja", {"ja", "en"}),
        llm_memory_max_bytes=_env_int("FORENSIA_MEMORY_MAX_BYTES", 0, minimum=0),
        llm_report_max_queries_per_section=_env_int(
            "FORENSIA_REPORT_MAX_QUERIES_PER_SECTION", 3, minimum=1
        ),
        llm_reasoning_reserve_tokens=_env_int(
            "LLM_REASONING_RESERVE_TOKENS", 0, minimum=0
        ),
        llm_context_window_tokens=_env_int(
            "LLM_CONTEXT_WINDOW_TOKENS", 0, minimum=0
        ),
        forensia_system_prompt_budget_chars=_env_int(
            "FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS", 0, minimum=0
        ),
        forensia_prompt_budget_tokens=_env_int(
            "FORENSIA_PROMPT_BUDGET_TOKENS", 0, minimum=0
        ),
        forensia_ui_origins=os.getenv("FORENSIA_UI_ORIGINS", ""),
        structured_markdown_max_rows=_env_int(
            "FORENSIA_REPORT_MARKDOWN_MAX_ROWS", 200, minimum=1
        ),
        llm_outage_wall_clock_budget_s=outage_budget_s,
        llm_outage_probe_interval_s=min(outage_probe_s, outage_budget_s),
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
        "output_language": settings.llm_output_language,
        "memory_max_bytes": get_memory_max_bytes(),
        "report_max_queries_per_section": settings.llm_report_max_queries_per_section,
        "reasoning_reserve_tokens": settings.llm_reasoning_reserve_tokens,
        "llm_context_window_tokens": settings.llm_context_window_tokens or None,
    }


def clear_llm_settings_cache() -> None:
    get_llm_settings.cache_clear()


def get_system_prompt_budget_chars() -> int:
    """Return the explicit system budget or derive it from the total prompt budget."""
    configured = settings.forensia_system_prompt_budget_chars
    if configured > 0:
        return configured
    return get_prompt_budget_tokens() * 2


def get_prompt_budget_tokens() -> int:
    """Return the total prompt budget or the conservative model-agnostic default."""
    configured = settings.forensia_prompt_budget_tokens
    if configured > 0:
        return configured
    return DEFAULT_PROMPT_BUDGET_TOKENS


def get_memory_max_bytes() -> int:
    """Return the overview compaction threshold derived from the prompt budget."""
    configured = settings.llm_memory_max_bytes
    if configured > 0:
        return configured
    return max(4096, min(65536, get_prompt_budget_tokens() * 4 // 3))
