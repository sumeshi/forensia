"""Parse and repair JSON from LLM output: candidate extraction, cheap repair, retry prompts."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from forensia.config import get_llm_settings, get_settings
from forensia.context.prompt_context import fit_prompt_messages
from forensia.core.control import InvestigationStopped, check_stop
from forensia.llm.llm_client import (
    LLMContextWindowError,
    LLMOutageBudgetExceededError,
    LLMOutputTruncatedError,
    LLMServerUnavailableError,
    LLMStructuredOutputError,
    chat_completion,
    outage_wait_until_recovered_sync,
)
from forensia.llm.telemetry import (
    LLMBudgetExceededError,
    get_active_telemetry,
)

CODE_BLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_TRAILING_COMMA_RE = re.compile(r",\s*([\]}])")
_LINE_COMMENT_RE = re.compile(r"//[^\n\"]*\n")
MAX_JSON_REPAIR_ATTEMPTS = 1
MAX_JSON_COMPLETION_ATTEMPTS = 2

_TRUNCATION_RECOVERY = (
    "<RETRY_CONSTRAINT>The previous response exceeded the output limit. "
    "Return exactly one concise JSON object matching OUTPUT_SCHEMA. Omit prose, "
    "analysis, repetition, markdown, and fields not required by the schema. "
    "Keep each explanatory string under 240 characters.</RETRY_CONSTRAINT>"
)
_STRUCTURED_OUTPUT_RECOVERY = (
    "<RETRY_CONSTRAINT>The provider could not parse the generated output. "
    "Return exactly one JSON object matching OUTPUT_SCHEMA. Do not include "
    "analysis, reasoning, markdown, or text before or after the JSON object. "
    "Keep the same requested scope and use concise values.</RETRY_CONSTRAINT>"
)


def _messages_for_output_retry(
    messages: list[dict[str, str]],
    instruction: str,
) -> list[dict[str, str]]:
    """Change a request without discarding input evidence."""
    retried = [dict(item) for item in messages]
    target = next(
        (
            index
            for index in range(len(retried) - 1, -1, -1)
            if retried[index].get("role") != "system"
        ),
        None,
    )
    if target is None:
        retried.append({"role": "user", "content": instruction})
    else:
        content = str(retried[target].get("content") or "")
        retried[target]["content"] = f"{content}\n\n{instruction}"
    if hasattr(messages, "retrieval_event_ids"):
        from forensia.context.prompt_context import PromptMessages

        return PromptMessages(
            retried,
            messages.retrieval_event_ids,
            getattr(messages, "omitted_optional_blocks", ()),
        )
    return retried


def _compact_messages_after_context_rejection(
    messages: list[dict[str, str]],
) -> list[dict[str, str]] | None:
    """After provider rejection, remove optional catalog blocks once; never replay unchanged context."""
    compacted = fit_prompt_messages(
        messages,
        force_optional_reduction=True,
    )
    if compacted is None or sum(
        len(item.get("content", "")) for item in compacted
    ) >= sum(len(item.get("content", "")) for item in messages):
        return None
    return compacted


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
    max_tokens: int | None = None,
) -> str:
    """Send malformed JSON to the LLM for repair; returns a corrected string."""
    if status_callback:
        status_callback("Malformed JSON returned by LLM. Requesting JSON repair.")
    messages = _json_repair_messages(broken_output, parse_error)
    check_stop()
    return _chat_completion_resuming_outage(
        messages=messages,
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        logical_call_id=logical_call_id,
        attempt_ordinal=ordinal if ordinal is not None else 0,
        phase="json_repair",
        max_tokens=max_tokens,
    )


def parse_llm_json(
    output: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    *,
    logical_call_id: str | None = None,
    ordinal: list[int] | None = None,
    correction_budget: list[int] | None = None,
    max_tokens: int | None = None,
) -> dict[str, Any]:
    """Parse an LLM output string into a dict, with cheap repair and LLM-based repair fallback."""
    correction_budget = correction_budget if correction_budget is not None else [1]
    try:
        return JSON_REPAIR_PIPELINE.parse_object(output)
    except RuntimeError:
        raise
    except Exception as parse_error:
        if correction_budget[0] <= 0:
            raise RuntimeError(
                f"LLM returned invalid JSON after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts: {parse_error}"
            ) from parse_error
        correction_budget[0] -= 1
        repair_error = parse_error

    repaired = _request_json_repair(
        output,
        parse_error=repair_error,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        logical_call_id=logical_call_id,
        ordinal=ordinal,
        max_tokens=max_tokens,
    )
    try:
        return JSON_REPAIR_PIPELINE.parse_object(repaired)
    except RuntimeError:
        raise
    except Exception as error:
        raise RuntimeError(
            f"LLM returned invalid JSON after {MAX_JSON_REPAIR_ATTEMPTS} repair attempts: {error}"
        ) from error


def _chat_completion_resuming_outage(
    *,
    status_callback: Callable[[str], None] | None = None,
    retry_metadata: dict[str, Any] | None = None,
    **kwargs: Any,
) -> str:
    deadline = None
    retry_metadata = retry_metadata if retry_metadata is not None else {}
    while True:
        try:
            return chat_completion(
                **(kwargs | {"status_callback": status_callback} | retry_metadata)
            )
        except LLMOutageBudgetExceededError:
            raise
        except LLMServerUnavailableError:
            budget_s = get_settings().llm_outage_wall_clock_budget_s
            deadline = deadline or (time.monotonic() + budget_s)
            remaining_s = deadline - time.monotonic()
            if remaining_s <= 0:
                raise LLMOutageBudgetExceededError(
                    f"LLM outage budget exceeded ({budget_s}s)"
                )
            if status_callback:
                status_callback(
                    "LLM unavailable; waiting before resuming the same request"
                )
            interval_s = get_settings().llm_outage_probe_interval_s
            until = min(deadline, time.monotonic() + interval_s)
            while time.monotonic() < until:
                check_stop()
                time.sleep(min(0.25, max(0, until - time.monotonic())))
            retry_metadata.update(
                retry_class="outage_recovery",
                retry_reason="transport failure; resumed the same request after recovery wait",
                policy_decision="resume_same_request",
            )
            remaining_s = deadline - time.monotonic()
            outage_wait_until_recovered_sync(
                kwargs["base_url"], status_callback, budget_s=remaining_s
            )
            if time.monotonic() >= deadline:
                raise LLMOutageBudgetExceededError(
                    f"LLM outage budget exceeded ({budget_s}s)"
                )


def request_llm_json(
    messages: list[dict[str, str]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    json_schema: dict | None = None,
    max_tokens: int | None = None,
    *,
    logical_call_id: str | None = None,
    telemetry_phase: str = "request_llm_json",
    correction_budget: list[int] | None = None,
    attempt_ordinal: list[int] | None = None,
) -> dict[str, Any]:
    """Send a chat request and return parsed JSON, with retry across both completion and parsing failures."""
    telemetry = get_active_telemetry()
    owned = False
    if logical_call_id is None and telemetry is not None:
        logical_call_id = telemetry.begin_logical_call(phase=telemetry_phase)
        owned = True
    correction_budget = correction_budget if correction_budget is not None else [1]

    def close_owned_call(status: Literal["discarded", "failed", "success"]) -> None:
        if owned and telemetry is not None and logical_call_id is not None:
            telemetry.close_logical_call(logical_call_id=logical_call_id, status=status)

    ordinal = attempt_ordinal if attempt_ordinal is not None else [0]

    seen_truncated_outputs: set[str] = set()
    context_compaction_used = False
    context_retry_fields: dict[str, Any] | None = None
    truncation_retry_fields: dict[str, Any] | None = None
    structured_retry_fields: dict[str, Any] | None = None
    configured_cap = int(get_llm_settings()["max_tokens"])
    base_max = min(int(max_tokens), configured_cap) if max_tokens else configured_cap
    for _ in range(MAX_JSON_COMPLETION_ATTEMPTS):
        outage_retry_metadata: dict[str, Any] = {}
        try:
            try:
                output = _chat_completion_resuming_outage(
                    messages=messages,
                    model=model,
                    base_url=base_url,
                    max_tokens=base_max,
                    status_callback=status_callback,
                    json_schema=json_schema,
                    logical_call_id=logical_call_id,
                    attempt_ordinal=ordinal,
                    phase=telemetry_phase,
                    retry_class=(
                        "truncation"
                        if truncation_retry_fields
                        else "structured_parse"
                        if structured_retry_fields
                        else None
                    ),
                    retry_reason=(
                        "finish_reason=length; concise JSON retry within original cap"
                        if truncation_retry_fields
                        else "provider could not parse generated output"
                        if structured_retry_fields
                        else None
                    ),
                    policy_decision=(
                        "compact_context"
                        if context_retry_fields
                        else "constrain_output"
                        if truncation_retry_fields
                        else "restate_structured_output"
                        if structured_retry_fields
                        else None
                    ),
                    request_changed_fields=(
                        context_retry_fields
                        or truncation_retry_fields
                        or structured_retry_fields
                    ),
                    retry_metadata=outage_retry_metadata,
                )
            except LLMOutputTruncatedError as exc:
                if exc.content:
                    fingerprint = hashlib.sha256(exc.content.encode()).hexdigest()
                    if fingerprint in seen_truncated_outputs:
                        raise LLMOutputTruncatedError(
                            "LLM repeated identical truncated output; no-information retry stopped",
                            content=exc.content,
                        ) from exc
                    seen_truncated_outputs.add(fingerprint)
                if correction_budget[0] <= 0:
                    raise
                correction_budget[0] -= 1
                messages = _messages_for_output_retry(messages, _TRUNCATION_RECOVERY)
                truncation_retry_fields = {
                    "decision": "constrain_output",
                    "max_tokens": base_max,
                }
                if status_callback:
                    status_callback(
                        "LLM output truncated; retrying once within the original output cap"
                    )
                continue
            except LLMStructuredOutputError as exc:
                if (
                    exc.error_code != "generated_output_parse_failed"
                    or correction_budget[0] <= 0
                ):
                    raise
                correction_budget[0] -= 1
                messages = _messages_for_output_retry(
                    messages, _STRUCTURED_OUTPUT_RECOVERY
                )
                structured_retry_fields = {
                    "decision": "restate_structured_output",
                    "error_code": exc.error_code,
                }
                if status_callback:
                    status_callback(
                        "LLM could not parse generated output; retrying once with the same schema"
                    )
                continue
            if not output or not output.strip():
                raise LLMServerUnavailableError("LLM returned empty response")
        except LLMContextWindowError as exc:
            if not context_compaction_used and correction_budget[0] > 0:
                try:
                    compacted = _compact_messages_after_context_rejection(messages)
                except Exception:
                    close_owned_call("failed")
                    raise
                if compacted is not None:
                    messages = compacted
                    context_compaction_used = True
                    correction_budget[0] -= 1
                    context_retry_fields = {
                        "context_error": exc.status_code,
                        "decision": "structured_compaction",
                    }
                    if status_callback:
                        status_callback(
                            "LLM context window rejected; retrying after structured compaction"
                        )
                    continue
            close_owned_call("failed")
            raise
        except InvestigationStopped:
            close_owned_call("discarded")
            raise
        except LLMServerUnavailableError:
            close_owned_call("failed")
            raise
        except Exception:
            close_owned_call("failed")
            raise
        try:
            parsed = parse_llm_json(
                output,
                base_url=base_url,
                model=model,
                status_callback=status_callback,
                logical_call_id=logical_call_id,
                ordinal=ordinal,
                correction_budget=correction_budget,
                max_tokens=base_max,
            )
            close_owned_call("success")
            return parsed
        except LLMBudgetExceededError:
            close_owned_call("failed")
            raise
        except InvestigationStopped:
            close_owned_call("discarded")
            raise
        except Exception as error:
            close_owned_call("failed")
            raise RuntimeError(
                f"LLM JSON response failed after one bounded correction: {error}"
            ) from error
    close_owned_call("failed")
    raise RuntimeError("LLM returned no JSON response")
