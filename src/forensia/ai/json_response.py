from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from typing import Any

from forensia.ai.lmstudio import chat_completion, async_chat_completion

CODE_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_TRAILING_COMMA_RE = re.compile(r",\s*([\]}])")
_LINE_COMMENT_RE = re.compile(r"//[^\n\"]*\n")
MAX_JSON_REPAIR_ATTEMPTS = 3
MAX_JSON_COMPLETION_ATTEMPTS = 3


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
        return stripped[first_brace:last_brace + 1]
    return stripped


def _request_json_repair(
    broken_output: str,
    parse_error: Exception,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> str:
    """Send malformed JSON to the LLM for repair; returns a corrected string."""
    if status_callback:
        status_callback("Malformed JSON returned by LLM. Requesting JSON repair.")
    messages = [
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
                f"Parse error: {parse_error}\n\n"
                f"{broken_output}"
            ),
        },
    ]
    return chat_completion(
        messages=messages,
        model=model,
        base_url=base_url,
        status_callback=None,
    )


async def _async_request_json_repair(
    broken_output: str,
    parse_error: Exception,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> str:
    """Async variant of _request_json_repair for parallel LLM repair calls."""
    if status_callback:
        status_callback("Malformed JSON returned by LLM. Requesting JSON repair.")
    messages = [
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
                f"Parse error: {parse_error}\n\n"
                f"{broken_output}"
            ),
        },
    ]
    return await async_chat_completion(
        messages=messages,
        model=model,
        base_url=base_url,
        status_callback=None,
    )


def parse_llm_json(
    output: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Parse an LLM output string into a dict, with cheap repair and LLM-based repair fallback."""
    current_output = output
    current_error: Exception | None = None
    for repair_attempt in range(1, MAX_JSON_REPAIR_ATTEMPTS + 1):
        try:
            parsed = json.loads(_cheap_repair(_extract_candidate(current_output)))
        except Exception as parse_error:
            current_error = parse_error
            if repair_attempt >= MAX_JSON_REPAIR_ATTEMPTS:
                break
            current_output = _request_json_repair(
                current_output,
                parse_error=parse_error,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
            )
            continue
        if not isinstance(parsed, dict):
            raise RuntimeError("LLM returned JSON, but top-level value was not an object")
        return parsed

    raise RuntimeError(f"LLM returned invalid JSON after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts: {current_error}")


async def async_parse_llm_json(
    output: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Async variant of parse_llm_json for parallel LLM JSON parsing."""
    current_output = output
    current_error: Exception | None = None
    for repair_attempt in range(1, MAX_JSON_REPAIR_ATTEMPTS + 1):
        try:
            parsed = json.loads(_cheap_repair(_extract_candidate(current_output)))
        except Exception as parse_error:
            current_error = parse_error
            if repair_attempt >= MAX_JSON_REPAIR_ATTEMPTS:
                break
            current_output = await _async_request_json_repair(
                current_output,
                parse_error=parse_error,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
            )
            continue
        if not isinstance(parsed, dict):
            raise RuntimeError("LLM returned JSON, but top-level value was not an object")
        return parsed

    raise RuntimeError(f"LLM returned invalid JSON after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts: {current_error}")


def request_llm_json(
    messages: list[dict[str, str]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
    json_schema: dict | None = None,
) -> dict[str, Any]:
    """Send a chat request and return parsed JSON, with retry across both completion and parsing failures."""
    last_error: Exception | None = None
    for completion_attempt in range(1, MAX_JSON_COMPLETION_ATTEMPTS + 1):
        if completion_attempt > 1 and status_callback:
            status_callback(
                f"Malformed JSON persisted after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts. "
                f"Retrying original LLM request ({completion_attempt}/{MAX_JSON_COMPLETION_ATTEMPTS})."
            )
        try:
            output = chat_completion(
                messages=messages,
                model=model,
                base_url=base_url,
                status_callback=status_callback,
                json_schema=json_schema,
            )
        except Exception as exc:
            if audit_callback:
                audit_callback(messages, output="<HTTP_ERROR>", parsed={"error": str(exc)})
            raise
        try:
            parsed = parse_llm_json(
                output,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
            )
            if audit_callback:
                audit_callback(messages, output, parsed)
            return parsed
        except Exception as error:
            last_error = error
            continue
    if last_error is None:
        raise RuntimeError("LLM returned no JSON response")
    raise RuntimeError(
        f"LLM JSON response failed after {MAX_JSON_COMPLETION_ATTEMPTS} full attempts: {last_error}"
    ) from last_error


async def async_request_llm_json(
    messages: list[dict[str, str]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
    json_schema: dict | None = None,
) -> dict[str, Any]:
    """Async variant of request_llm_json for parallel LLM requests."""
    last_error: Exception | None = None
    for completion_attempt in range(1, MAX_JSON_COMPLETION_ATTEMPTS + 1):
        if completion_attempt > 1 and status_callback:
            status_callback(
                f"Malformed JSON persisted after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts. "
                f"Retrying original LLM request ({completion_attempt}/{MAX_JSON_COMPLETION_ATTEMPTS})."
            )
        try:
            output = await async_chat_completion(
                messages=messages,
                model=model,
                base_url=base_url,
                status_callback=status_callback,
                json_schema=json_schema,
            )
        except Exception as exc:
            if audit_callback:
                audit_callback(messages, output="<HTTP_ERROR>", parsed={"error": str(exc)})
            raise
        try:
            parsed = await async_parse_llm_json(
                output,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
            )
            if audit_callback:
                audit_callback(messages, output, parsed)
            return parsed
        except Exception as error:
            last_error = error
            continue
    if last_error is None:
        raise RuntimeError("LLM returned no JSON response")
    raise RuntimeError(
        f"LLM JSON response failed after {MAX_JSON_COMPLETION_ATTEMPTS} full attempts: {last_error}"
    ) from last_error
