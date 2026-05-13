from __future__ import annotations

import json
import threading
from typing import Any

from forensia.core.case import Case


def _slugify(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in value).strip("-") or "call"


class LLMCallLogger:
    def __init__(self, case: Case, session_id: str):
        self.case = case
        self.session_id = session_id
        self.base_dir = case.ai_logs_dir / _slugify(session_id)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

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
        safe_phase = _slugify(phase)
        safe_suffix = _slugify(suffix or "")
        counter_key = f"{iteration:02d}-{safe_phase}-{safe_suffix}"
        with self._lock:
            next_index = self._counts.get(counter_key, 0) + 1
            self._counts[counter_key] = next_index
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
