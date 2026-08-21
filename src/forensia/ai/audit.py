"""LLM call audit logging: persists prompts/responses per phase and tracks call counts."""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from forensia.ai.llm.llm_client import get_last_completion_metadata
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
        self._request_fingerprints: dict[str, int] = {}
        self._action_fingerprints: dict[str, int] = {}

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
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> None:
        """Serialize an LLM call transcript to a JSON file on disk."""
        completion = get_last_completion_metadata()
        input_chars = sum(len(item.get("content", "")) for item in input_messages)
        output_text = json.dumps(output, ensure_ascii=False, default=str, sort_keys=True)
        if input_tokens is None:
            input_tokens = (
                completion.input_tokens
                if completion is not None
                else max(1, input_chars // 4)
            )
        if output_tokens is None:
            output_tokens = (
                completion.output_tokens
                if completion is not None
                else max(1, len(output_text) // 4)
            )
        usage_source = (
            completion.usage_source if completion is not None else "local_estimate"
        )
        request_payload = json.dumps(
            input_messages, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        request_fingerprint = hashlib.sha256(request_payload.encode()).hexdigest()[:20]
        action_fingerprint = hashlib.sha256(output_text.encode()).hexdigest()[:20]

        safe_phase = slugify(phase)
        safe_suffix = slugify(suffix or "")
        counter_key = f"{iteration:02d}-{safe_phase}-{safe_suffix}"
        with self._lock:
            next_index = self._counts.get(counter_key, 0) + 1
            self._counts[counter_key] = next_index
            self._total += 1
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
            request_repeat = self._request_fingerprints.get(request_fingerprint, 0)
            action_repeat = self._action_fingerprints.get(action_fingerprint, 0)
            self._request_fingerprints[request_fingerprint] = request_repeat + 1
            self._action_fingerprints[action_fingerprint] = action_repeat + 1
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
                        "usage_source": usage_source,
                        "finish_reason": (
                            completion.finish_reason if completion is not None else "unknown"
                        ),
                        "latency_ms": completion.latency_ms if completion is not None else None,
                        "input_chars": input_chars,
                        "message_chars_by_role": {
                            role: sum(
                                len(item.get("content", ""))
                                for item in input_messages
                                if item.get("role") == role
                            )
                            for role in {item.get("role", "unknown") for item in input_messages}
                        },
                        "request_fingerprint": request_fingerprint,
                        "action_fingerprint": action_fingerprint,
                        "repeated_request": request_repeat > 0,
                        "repeated_action": action_repeat > 0,
                    },
                },
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
