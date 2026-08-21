"""Parse and repair JSON from LLM output: candidate extraction, cheap repair, retry prompts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.llm.llm_client import (
    LLMContextWindowError,
    LLMOutputTruncatedError,
    LLMServerUnavailableError,
    async_chat_completion,
    chat_completion,
)
from forensia.ai.llm_telemetry import get_active_telemetry
from forensia.config import get_llm_settings

CODE_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_TRAILING_COMMA_RE = re.compile(r",\s*([\]}])")
_LINE_COMMENT_RE = re.compile(r"//[^\n\"]*\n")
MAX_JSON_REPAIR_ATTEMPTS = 3
MAX_JSON_COMPLETION_ATTEMPTS = 3


def _compact_messages_after_context_rejection(
    messages: list[dict[str, str]], *, base_url: str, model: str
) -> list[dict[str, str]] | None:
    """Create one bounded structured projection for an oversized request."""
    from forensia.ai.compaction import structured_compact

    total_chars = sum(len(str(item.get("content") or "")) for item in messages)
    if total_chars < 2048:
        return None
    target_total = max(2048, int(total_chars * 0.65))
    users = [i for i, item in enumerate(messages) if item.get("role") != "system"]
    if not users:
        return None
    per_message = max(1024, target_total // len(users))
    compacted = [dict(item) for item in messages]
    changed = False
    for index in users:
        content = str(compacted[index].get("content") or "")
        if len(content) <= per_message:
            continue
        shortened = structured_compact(
            content,
            per_message,
            base_url=base_url,
            model=model,
            preserve_recent_turns=3,
        )
        if shortened != content:
            compacted[index]["content"] = shortened
            changed = True
    return compacted if changed else None


@dataclass(frozen=True, slots=True)
class JsonRepairPipeline:
    """Normalize common model-output defects before strict object parsing."""

    stages: tuple[Callable[[str], str], ...]

    def normalize(self, text: str) -> str:
        """Apply deterministic repair stages in declaration order."""
        for stage in self.stages:
            text = stage(text)
        return text

    def parse_object(self, text: str) -> dict[str, Any]:
        """Parse normalized text and require a JSON object at the top level."""
        parsed = json.loads(self.normalize(text))
        if not isinstance(parsed, dict):
            raise RuntimeError(
                "LLM returned JSON, but top-level value was not an object"
            )
        return parsed


def _cheap_repair(text: str) -> str:
    """Fix common JSON syntax errors without an LLM call."""
    text = _LINE_COMMENT_RE.sub("\n", text)
    text = _TRAILING_COMMA_RE.sub(r"\1", text)
    return text


def _extract_candidate(text: str) -> str:
    """Strip markdown code fences and extract the first JSON object from a string."""
    stripped = text.strip()
    match = CODE_BLOCK_RE.search(stripped)
    if match:
        stripped = match.group(1).strip()

    first_brace = stripped.find("{")
    last_brace = stripped.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return stripped[first_brace : last_brace + 1]
    return stripped


JSON_REPAIR_PIPELINE = JsonRepairPipeline(
    stages=(_extract_candidate, _cheap_repair),
)


def _json_repair_messages(
    broken_output: str, parse_error: Exception
) -> list[dict[str, str]]:
    """Build the shared sync/async malformed-JSON repair request."""
    return [
        {
            "role": "system",
            "content": (
                "You repair malformed JSON. Return exactly one valid JSON object. "
                "Do not add markdown, explanation, or surrounding text. "
                "Preserve keys and values as much as possible."
            ),
        },
        {
            "role": "user",
            "content": (
                "Repair this malformed JSON into one valid JSON object.\n"
                f"Parse error: {parse_error}\n\n{broken_output}"
            ),
        },
    ]


def _request_json_repair(
    broken_output: str,
    parse_error: Exception,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    *,
    logical_call_id: str | None = None,
    ordinal: list[int] | None = None,
) -> str:
    """Send malformed JSON to the LLM for repair; returns a corrected string."""
    if status_callback:
        status_callback("Malformed JSON returned by LLM. Requesting JSON repair.")
    messages = _json_repair_messages(broken_output, parse_error)
    attempt_ordinal = ordinal[0] if ordinal is not None else 0
    if ordinal is not None:
        ordinal[0] += 1
    return chat_completion(
        messages=messages,
        model=model,
        base_url=base_url,
        status_callback=None,
        logical_call_id=logical_call_id,
        attempt_ordinal=attempt_ordinal,
        phase="json_repair",
    )


async def _async_request_json_repair(
    broken_output: str,
    parse_error: Exception,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    *,
    logical_call_id: str | None = None,
    ordinal: list[int] | None = None,
) -> str:
    """Async variant of _request_json_repair for parallel LLM repair calls."""
    if status_callback:
        status_callback("Malformed JSON returned by LLM. Requesting JSON repair.")
    messages = _json_repair_messages(broken_output, parse_error)
    return await async_chat_completion(
        messages=messages,
        model=model,
        base_url=base_url,
        status_callback=None,
        logical_call_id=logical_call_id,
        attempt_ordinal=(ordinal[0] if ordinal else 0),
        phase="json_repair",
    )


def parse_llm_json(
    output: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    *,
    telemetry=None,
    logical_call_id: str | None = None,
    ordinal: list[int] | None = None,
) -> dict[str, Any]:
    """Parse an LLM output string into a dict, with cheap repair and LLM-based repair fallback."""
    current_output = output
    current_error: Exception | None = None
    for repair_attempt in range(1, MAX_JSON_REPAIR_ATTEMPTS + 1):
        try:
            parsed = JSON_REPAIR_PIPELINE.parse_object(current_output)
        except RuntimeError:
            raise
        except Exception as parse_error:
            current_error = parse_error
            if repair_attempt >= MAX_JSON_REPAIR_ATTEMPTS:
                break
            if ordinal is not None:
                ordinal[0] += 1
            current_output = _request_json_repair(
                current_output,
                parse_error=parse_error,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
                logical_call_id=logical_call_id,
                ordinal=ordinal,
            )
            continue
        return parsed

    raise RuntimeError(
        f"LLM returned invalid JSON after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts: {current_error}"
    )


async def async_parse_llm_json(
    output: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    *,
    telemetry=None,
    logical_call_id: str | None = None,
    ordinal: list[int] | None = None,
) -> dict[str, Any]:
    """Async variant of parse_llm_json for parallel LLM JSON parsing."""
    current_output = output
    current_error: Exception | None = None
    for repair_attempt in range(1, MAX_JSON_REPAIR_ATTEMPTS + 1):
        try:
            parsed = JSON_REPAIR_PIPELINE.parse_object(current_output)
        except RuntimeError:
            raise
        except Exception as parse_error:
            current_error = parse_error
            if repair_attempt >= MAX_JSON_REPAIR_ATTEMPTS:
                break
            if ordinal is not None:
                ordinal[0] += 1
            current_output = await _async_request_json_repair(
                current_output,
                parse_error=parse_error,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
                logical_call_id=logical_call_id,
                ordinal=ordinal,
            )
            continue
        return parsed

    raise RuntimeError(
        f"LLM returned invalid JSON after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts: {current_error}"
    )


def request_llm_json(
    messages: list[dict[str, str]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
    json_schema: dict | None = None,
    max_tokens: int | None = None,
    *,
    logical_call_id: str | None = None,
) -> dict[str, Any]:
    """Send a chat request and return parsed JSON, with retry across both completion and parsing failures."""
    telemetry = get_active_telemetry()
    owned = False
    if logical_call_id is None and telemetry is not None:
        logical_call_id = telemetry.begin_logical_call(phase="request_llm_json")
        owned = True
    ordinal: list[int] = [0]

    def next_ordinal() -> int:
        value = ordinal[0]
        ordinal[0] += 1
        return value

    last_error: Exception | None = None
    seen_truncated_outputs: set[str] = set()
    seen_invalid_outputs: set[str] = set()
    context_compaction_used = False
    context_retry_fields: dict[str, Any] | None = None
    base_max = max_tokens if max_tokens is not None else get_llm_settings()["max_tokens"]
    for completion_attempt in range(1, MAX_JSON_COMPLETION_ATTEMPTS + 1):
        if completion_attempt > 1 and status_callback:
            status_callback(
                f"Malformed JSON persisted after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts. "
                f"Retrying original LLM request ({completion_attempt}/{MAX_JSON_COMPLETION_ATTEMPTS})."
            )
        try:
            first_max_tokens = max_tokens
            for _ in range(2):
                try:
                    retry_class = None
                    retry_reason = None
                    changed_fields = None
                    if first_max_tokens != base_max:
                        retry_class = "truncation"
                        retry_reason = "finish_reason=length; retry with larger output budget"
                        changed_fields = {"max_tokens": [base_max, first_max_tokens]}
                    output = chat_completion(
                        messages=messages,
                        model=model,
                        base_url=base_url,
                        max_tokens=first_max_tokens,
                        status_callback=status_callback,
                        json_schema=json_schema,
                        logical_call_id=logical_call_id,
                        attempt_ordinal=next_ordinal(),
                        phase="request_llm_json",
                        retry_class=retry_class,
                        retry_reason=retry_reason,
                        policy_decision=(
                            "compact_context" if context_retry_fields else None
                        ),
                        request_changed_fields=(
                            context_retry_fields or changed_fields
                        ),
                    )
                    break
                except LLMOutputTruncatedError as exc:
                    if exc.content:
                        fingerprint = hashlib.sha256(exc.content.encode()).hexdigest()
                        if fingerprint in seen_truncated_outputs:
                            raise LLMServerUnavailableError(
                                "LLM repeated identical truncated output; no-information retry stopped"
                            ) from exc
                        seen_truncated_outputs.add(fingerprint)
                    first_max_tokens = (
                        first_max_tokens or get_llm_settings()["max_tokens"]
                    ) * 2
                    if status_callback:
                        status_callback(
                            f"LLM output truncated, retrying with max_tokens={first_max_tokens}"
                        )
            else:
                raise LLMServerUnavailableError(
                    f"LLM output truncated after 3 attempts (max_tokens={first_max_tokens})"
                )
            if not output or not output.strip():
                raise LLMServerUnavailableError("LLM returned empty response")
        except LLMContextWindowError as exc:
            if not context_compaction_used:
                compacted = _compact_messages_after_context_rejection(
                    messages, base_url=base_url, model=model
                )
                if compacted is not None:
                    messages = compacted
                    context_compaction_used = True
                    context_retry_fields = {
                        "context_error": exc.status_code,
                        "decision": "structured_compaction",
                    }
                    if status_callback:
                        status_callback(
                            "LLM context window rejected; retrying after structured compaction"
                        )
                    continue
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="failed"
                )
            raise
        except LLMServerUnavailableError:
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="failed"
                )
            raise
        except Exception as exc:
            if audit_callback:
                audit_callback(
                    messages, output="<HTTP_ERROR>", parsed={"error": str(exc)}
                )
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="failed"
                )
            raise
        try:
            parsed = parse_llm_json(
                output,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
                logical_call_id=logical_call_id,
                ordinal=ordinal,
            )
            if audit_callback:
                audit_callback(messages, output, parsed)
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="success"
                )
            return parsed
        except Exception as error:
            last_error = error
            fingerprint = hashlib.sha256(output.encode()).hexdigest()
            if fingerprint in seen_invalid_outputs:
                raise RuntimeError(
                    "LLM repeated identical invalid JSON; no-information retry stopped"
                ) from error
            seen_invalid_outputs.add(fingerprint)
            continue
    if last_error is None:
        raise RuntimeError("LLM returned no JSON response")
    if owned:
        telemetry.close_logical_call(  # type: ignore[union-attr]
            logical_call_id=logical_call_id, status="failed"
        )
    raise RuntimeError(
        f"LLM JSON response failed after {MAX_JSON_COMPLETION_ATTEMPTS} full attempts: {last_error}"
    ) from last_error


async def async_request_llm_json(
    messages: list[dict[str, str]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
    json_schema: dict | None = None,
    max_tokens: int | None = None,
    *,
    logical_call_id: str | None = None,
) -> dict[str, Any]:
    """Async variant of request_llm_json for parallel LLM requests."""
    telemetry = get_active_telemetry()
    owned = False
    if logical_call_id is None and telemetry is not None:
        logical_call_id = telemetry.begin_logical_call(phase="request_llm_json")
        owned = True
    ordinal: list[int] = [0]

    def next_ordinal() -> int:
        value = ordinal[0]
        ordinal[0] += 1
        return value

    last_error: Exception | None = None
    seen_truncated_outputs: set[str] = set()
    seen_invalid_outputs: set[str] = set()
    context_compaction_used = False
    context_retry_fields: dict[str, Any] | None = None
    base_max = max_tokens if max_tokens is not None else get_llm_settings()["max_tokens"]
    for completion_attempt in range(1, MAX_JSON_COMPLETION_ATTEMPTS + 1):
        if completion_attempt > 1 and status_callback:
            status_callback(
                f"Malformed JSON persisted after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts. "
                f"Retrying original LLM request ({completion_attempt}/{MAX_JSON_COMPLETION_ATTEMPTS})."
            )
        try:
            first_max_tokens = max_tokens
            for _ in range(2):
                try:
                    retry_class = None
                    retry_reason = None
                    changed_fields = None
                    if first_max_tokens != base_max:
                        retry_class = "truncation"
                        retry_reason = "finish_reason=length; retry with larger output budget"
                        changed_fields = {"max_tokens": [base_max, first_max_tokens]}
                    output = await async_chat_completion(
                        messages=messages,
                        model=model,
                        base_url=base_url,
                        max_tokens=first_max_tokens,
                        status_callback=status_callback,
                        json_schema=json_schema,
                        logical_call_id=logical_call_id,
                        attempt_ordinal=next_ordinal(),
                        phase="request_llm_json",
                        retry_class=retry_class,
                        retry_reason=retry_reason,
                        policy_decision=(
                            "compact_context" if context_retry_fields else None
                        ),
                        request_changed_fields=(
                            context_retry_fields or changed_fields
                        ),
                    )
                    break
                except LLMOutputTruncatedError as exc:
                    if exc.content:
                        fingerprint = hashlib.sha256(exc.content.encode()).hexdigest()
                        if fingerprint in seen_truncated_outputs:
                            raise LLMServerUnavailableError(
                                "LLM repeated identical truncated output; no-information retry stopped"
                            ) from exc
                        seen_truncated_outputs.add(fingerprint)
                    first_max_tokens = (
                        first_max_tokens or get_llm_settings()["max_tokens"]
                    ) * 2
                    if status_callback:
                        status_callback(
                            f"LLM output truncated, retrying with max_tokens={first_max_tokens}"
                        )
            else:
                raise LLMServerUnavailableError(
                    f"LLM output truncated after 3 attempts (max_tokens={first_max_tokens})"
                )
            if not output or not output.strip():
                raise LLMServerUnavailableError("LLM returned empty response")
        except LLMContextWindowError as exc:
            if not context_compaction_used:
                compacted = _compact_messages_after_context_rejection(
                    messages, base_url=base_url, model=model
                )
                if compacted is not None:
                    messages = compacted
                    context_compaction_used = True
                    context_retry_fields = {
                        "context_error": exc.status_code,
                        "decision": "structured_compaction",
                    }
                    if status_callback:
                        status_callback(
                            "LLM context window rejected; retrying after structured compaction"
                        )
                    continue
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="failed"
                )
            raise
        except LLMServerUnavailableError:
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="failed"
                )
            raise
        except Exception as exc:
            if audit_callback:
                audit_callback(
                    messages, output="<HTTP_ERROR>", parsed={"error": str(exc)}
                )
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="failed"
                )
            raise
        try:
            parsed = await async_parse_llm_json(
                output,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
                logical_call_id=logical_call_id,
                ordinal=ordinal,
            )
            if audit_callback:
                audit_callback(messages, output, parsed)
            if owned:
                telemetry.close_logical_call(  # type: ignore[union-attr]
                    logical_call_id=logical_call_id, status="success"
                )
            return parsed
        except Exception as error:
            last_error = error
            fingerprint = hashlib.sha256(output.encode()).hexdigest()
            if fingerprint in seen_invalid_outputs:
                raise RuntimeError(
                    "LLM repeated identical invalid JSON; no-information retry stopped"
                ) from error
            seen_invalid_outputs.add(fingerprint)
            continue
    if last_error is None:
        raise RuntimeError("LLM returned no JSON response")
    if owned:
        telemetry.close_logical_call(  # type: ignore[union-attr]
            logical_call_id=logical_call_id, status="failed"
        )
    raise RuntimeError(
        f"LLM JSON response failed after {MAX_JSON_COMPLETION_ATTEMPTS} full attempts: {last_error}"
    ) from last_error
