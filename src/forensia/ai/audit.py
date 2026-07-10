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

    @property
    def total_calls(self) -> int:
        return self._total

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
                    "per_phase": self.count_by_phase(),
                    "per_counter": dict(sorted(self._counts.items())),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

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
    ) -> None:
        """Serialize an LLM call transcript to a JSON file on disk."""
        safe_phase = slugify(phase)
        safe_suffix = slugify(suffix or "")
        counter_key = f"{iteration:02d}-{safe_phase}-{safe_suffix}"
        with self._lock:
            next_index = self._counts.get(counter_key, 0) + 1
            self._counts[counter_key] = next_index
        with self._lock:
            self._total += 1
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
                    },
                },
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
