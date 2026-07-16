"""LLM call audit logging: persists prompts/responses per phase and tracks call counts."""

from __future__ import annotations

import json
import threading
from typing import Any

from forensia.core.case import Case
from forensia.core.textutil import slugify


class LLMCallLogger:
    def __init__(self, case: Case, session_id: str):
        self.case = case
        self.session_id = session_id
        self.base_dir = case.ai_logs_dir / slugify(session_id)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._total: int = 0
        self._entries: list[dict] = []
        # R7-11: Token and cache tracking
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0

    @property
    def total_calls(self) -> int:
        return self._total

    @property
    def total_input_tokens(self) -> int:
        return self._total_input_tokens

    @property
    def total_output_tokens(self) -> int:
        return self._total_output_tokens

    @property
    def cache_hit_rate(self) -> float:
        total = self._cache_hits + self._cache_misses
        return self._cache_hits / total if total > 0 else 0.0

    def count_by_phase(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for key, count in self._counts.items():
            phase = key.split("-", 1)[1] if "-" in key else key
            result[phase] = result.get(phase, 0) + count
        return result

    def write_summary(self) -> None:
        """Write per-phase call counts to ai_logs/<session>/summary.json."""
        path = self.base_dir / "summary.json"
        path.write_text(
            json.dumps(
                {
                    "session_id": self.session_id,
                    "total_calls": self._total,
                    "total_input_tokens": self._total_input_tokens,
                    "total_output_tokens": self._total_output_tokens,
                    "cache_hit_rate": round(self.cache_hit_rate, 3),
                    "per_phase": self.count_by_phase(),
                    "per_counter": dict(sorted(self._counts.items())),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    def record_cache_hit(self) -> None:
        """Record a cache hit (response served from cache)."""
        with self._lock:
            self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss (response from LLM)."""
        with self._lock:
            self._cache_misses += 1

    def write(
        self,
        *,
        iteration: int,
        phase: str,
        input_messages: list[dict[str, str]],
        output: Any,
        model: str,
        base_url: str,
        suffix: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Serialize an LLM call transcript to a JSON file on disk."""
        safe_phase = slugify(phase)
        safe_suffix = slugify(suffix or "")
        counter_key = f"{iteration:02d}-{safe_phase}-{safe_suffix}"
        with self._lock:
            next_index = self._counts.get(counter_key, 0) + 1
            self._counts[counter_key] = next_index
            self._total += 1
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
        file_stem = f"{iteration:02d}-{safe_phase}"
        if safe_suffix:
            file_stem += f"-{safe_suffix}"
        file_stem += f"-{next_index:02d}"
        path = self.base_dir / f"{file_stem}.json"
        path.write_text(
            json.dumps(
                {
                    "input": input_messages,
                    "output": output,
                    "meta": {
                        "model": model,
                        "base_url": base_url,
                        "session_id": self.session_id,
                        "iteration": iteration,
                        "phase": phase,
                        "suffix": suffix,
                        "call_index": next_index,
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                    },
                },
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
