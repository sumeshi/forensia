from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


def resolve_llm_config(
    base_url: str | None = None,
    model: str | None = None,
) -> tuple[str | None, str | None]:
    """Resolve LLM endpoint and model from CLI args or environment variables."""
    resolved_endpoint = base_url or os.getenv("LLM_BASE_URL")
    resolved_model = model or os.getenv("LLM_MODEL")
    return resolved_endpoint, resolved_model


@lru_cache(maxsize=1)
def get_llm_settings() -> dict:
    return {
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "4096")),
        "thinking_language": os.getenv("LLM_THINKING_LANGUAGE", "en"),
        "output_language": os.getenv("LLM_OUTPUT_LANGUAGE", "ja"),
        "memory_max_bytes": int(os.getenv("LLM_MEMORY_MAX_BYTES", "16384")),
        "report_max_queries_per_section": max(1, int(os.getenv("LLM_REPORT_MAX_QUERIES_PER_SECTION", "3"))),
        "reasoning_reserve_tokens": int(os.getenv("LLM_REASONING_RESERVE_TOKENS", "0")),
    }


def clear_llm_settings_cache() -> None:
    get_llm_settings.cache_clear()
