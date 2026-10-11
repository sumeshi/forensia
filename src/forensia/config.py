from __future__ import annotations

import contextvars
import math
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values

DEFAULT_PROMPT_BUDGET_TOKENS = 12000


@dataclass(frozen=True)
class Settings:
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = field(default=None, repr=False)
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.0
    llm_output_language: str = "ja"
    llm_reasoning_reserve_tokens: int = 0
    llm_context_window_tokens: int = 0
    forensia_system_prompt_budget_chars: int = 0
    forensia_prompt_budget_tokens: int = 0
    structured_markdown_max_rows: int = 200
    llm_outage_wall_clock_budget_s: int = 28800
    llm_outage_probe_interval_s: int = 60
    max_iterations: int = 20
    max_queries_per_hypothesis: int = 5
    max_llm_calls: int = 200

    def __post_init__(self) -> None:
        if self.llm_base_url is not None:
            _validate_base_url(self.llm_base_url)
        for name, value, minimum in (
            ("llm_max_tokens", self.llm_max_tokens, 1),
            ("llm_reasoning_reserve_tokens", self.llm_reasoning_reserve_tokens, 0),
            ("llm_context_window_tokens", self.llm_context_window_tokens, 0),
            (
                "forensia_system_prompt_budget_chars",
                self.forensia_system_prompt_budget_chars,
                0,
            ),
            ("forensia_prompt_budget_tokens", self.forensia_prompt_budget_tokens, 0),
            ("structured_markdown_max_rows", self.structured_markdown_max_rows, 1),
            ("llm_outage_wall_clock_budget_s", self.llm_outage_wall_clock_budget_s, 1),
            ("llm_outage_probe_interval_s", self.llm_outage_probe_interval_s, 1),
            ("max_iterations", self.max_iterations, 1),
            ("max_queries_per_hypothesis", self.max_queries_per_hypothesis, 1),
            ("max_llm_calls", self.max_llm_calls, 0),
        ):
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer at least {minimum}")
        if (
            type(self.llm_temperature) not in {int, float}
            or not math.isfinite(self.llm_temperature)
            or not 0 <= self.llm_temperature <= 2
        ):
            raise ValueError("llm_temperature must be a finite number between 0 and 2")
        if self.llm_outage_probe_interval_s > self.llm_outage_wall_clock_budget_s:
            raise ValueError("llm_outage_probe_interval_s cannot exceed outage budget")
        if not isinstance(
            self.llm_output_language, str
        ) or self.llm_output_language not in {"ja", "en"}:
            raise ValueError("llm_output_language must be 'ja' or 'en'")
        for name, value in (
            ("llm_model", self.llm_model),
            ("llm_api_key", self.llm_api_key),
        ):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string")


_DEFAULT_SETTINGS = Settings()
_active_settings: contextvars.ContextVar[Settings | None] = contextvars.ContextVar(
    "forensia_settings", default=None
)


def get_settings() -> Settings:
    return _active_settings.get() or _DEFAULT_SETTINGS


@contextmanager
def settings_scope(settings: Settings) -> Iterator[Settings]:
    token = _active_settings.set(settings)
    try:
        yield settings
    finally:
        _active_settings.reset(token)


def _int(env: dict[str, str], name: str, default: int, minimum: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _float(
    env: dict[str, str],
    name: str,
    default: float,
    minimum: float,
    maximum: float | None = None,
) -> float:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if (
        not math.isfinite(value)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        bound = (
            f"between {minimum} and {maximum}"
            if maximum is not None
            else f"at least {minimum}"
        )
        raise ValueError(f"{name} must be {bound}")
    return value


def _validate_base_url(endpoint: str) -> None:
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("LLM_BASE_URL must be a non-empty URL")
    parsed = urlsplit(endpoint)
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("LLM_BASE_URL contains an invalid port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "LLM_BASE_URL must be an http(s) server root without credentials, path, query, or fragment"
        )


def load_settings(
    *,
    env_file: str | Path | None = None,
    base_url: str | None = None,
    model: str | None = None,
    require_inference: bool = False,
) -> Settings:
    """Load and validate one immutable configuration snapshot."""
    file_values = dotenv_values(
        Path(env_file) if env_file is not None else Path.cwd() / ".env"
    )
    env = {key: value for key, value in file_values.items() if value is not None}
    env.update(os.environ)
    endpoint = (base_url or env.get("LLM_BASE_URL") or "").strip() or None
    model_id = (model or env.get("LLM_MODEL") or "").strip() or None
    if require_inference and (not endpoint or not model_id):
        missing = ", ".join(
            name
            for name, value in (("LLM_BASE_URL", endpoint), ("LLM_MODEL", model_id))
            if not value
        )
        raise ValueError(f"Inference requires {missing}")
    if endpoint:
        _validate_base_url(endpoint)
    language = env.get("FORENSIA_OUTPUT_LANGUAGE", "ja").strip().lower()
    if language not in {"ja", "en"}:
        raise ValueError("FORENSIA_OUTPUT_LANGUAGE must be 'ja' or 'en'")
    api_key = env.get("LLM_API_KEY", "").strip()
    budget = _int(env, "LLM_OUTAGE_WALL_CLOCK_BUDGET_S", 28800, 1)
    interval = _int(env, "LLM_OUTAGE_PROBE_INTERVAL_S", 60, 1)
    return Settings(
        llm_base_url=endpoint,
        llm_model=model_id,
        llm_api_key=api_key or None,
        llm_max_tokens=_int(env, "LLM_MAX_TOKENS", 4096, 1),
        llm_temperature=_float(env, "LLM_TEMPERATURE", 0.0, 0.0, 2.0),
        llm_output_language=language,
        llm_reasoning_reserve_tokens=_int(env, "LLM_REASONING_RESERVE_TOKENS", 0, 0),
        llm_context_window_tokens=_int(env, "LLM_CONTEXT_WINDOW_TOKENS", 0, 0),
        forensia_system_prompt_budget_chars=_int(
            env, "FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS", 0, 0
        ),
        forensia_prompt_budget_tokens=_int(env, "FORENSIA_PROMPT_BUDGET_TOKENS", 0, 0),
        structured_markdown_max_rows=_int(
            env, "FORENSIA_REPORT_MARKDOWN_MAX_ROWS", 200, 1
        ),
        llm_outage_wall_clock_budget_s=budget,
        llm_outage_probe_interval_s=interval,
        max_iterations=_int(env, "FORENSIA_MAX_ITERATIONS", 20, 1),
        max_queries_per_hypothesis=_int(
            env, "FORENSIA_MAX_QUERIES_PER_HYPOTHESIS", 5, 1
        ),
        max_llm_calls=_int(env, "LLM_MAX_CALLS", 200, 0),
    )


def resolve_llm_config(
    base_url: str | None = None, model: str | None = None
) -> tuple[str | None, str | None]:
    settings = get_settings()
    return base_url or settings.llm_base_url, model or settings.llm_model


def get_llm_settings() -> dict:
    settings = get_settings()
    return {
        "max_tokens": settings.llm_max_tokens,
        "temperature": settings.llm_temperature,
        "output_language": settings.llm_output_language,
        "reasoning_reserve_tokens": settings.llm_reasoning_reserve_tokens,
        "llm_context_window_tokens": settings.llm_context_window_tokens or None,
    }


def get_system_prompt_budget_chars() -> int:
    configured = get_settings().forensia_system_prompt_budget_chars
    return configured if configured > 0 else get_prompt_budget_tokens() * 2


def get_prompt_budget_tokens() -> int:
    return get_settings().forensia_prompt_budget_tokens or DEFAULT_PROMPT_BUDGET_TOKENS
