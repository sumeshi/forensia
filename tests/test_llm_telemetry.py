from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from forensia.core.case import Case
from forensia.core.session import LLMBudgetExceededError
from forensia.db.database import CaseDB
from forensia.llm import llm_client
from forensia.llm.telemetry import (
    LLMTelemetry,
    compute_effective_output_limit,
    set_active_telemetry,
    telemetry_scope,
)


def test_context_budget_subtracts_known_input_even_when_output_alone_fits() -> None:
    assert compute_effective_output_limit(
        configured_max_tokens=4096,
        reasoning_reserve_tokens=0,
        known_context_limit=8192,
        estimated_input_tokens=7000,
    ) == (4096, 0, 4096, 1192)


def test_context_budget_counts_reasoning_reserve_once() -> None:
    assert compute_effective_output_limit(
        configured_max_tokens=1000,
        reasoning_reserve_tokens=200,
        requested_override=800,
        known_context_limit=1500,
        estimated_input_tokens=600,
    ) == (1000, 200, 800, 900)


def test_context_budget_rejects_input_that_leaves_no_output_room() -> None:
    with pytest.raises(ValueError, match="no output budget remains"):
        compute_effective_output_limit(
            configured_max_tokens=1000,
            reasoning_reserve_tokens=0,
            known_context_limit=1000,
            estimated_input_tokens=1000,
        )


@pytest.fixture()
def telemetry(tmp_path) -> LLMTelemetry:
    case = Case.init(tmp_path)
    db = CaseDB(case)
    return LLMTelemetry(db, session_id="S-1")


def test_deterministic_op_is_not_counted_as_llm_attempt(telemetry) -> None:
    telemetry.record_deterministic_op(
        phase="report-section-block",
        op_type="render",
        target="appendix-24",
        duration_ms=5,
    )
    agg = telemetry.session_aggregates()
    assert agg["provider_attempt_count"] == 0
    assert agg["deterministic_op_count"] == 1
    rows = telemetry.db.execute(
        "SELECT op_type, target FROM trace.llm_deterministic_ops"
    ).fetchall()
    assert rows[0] == ("render", "appendix-24")


def test_logical_call_inherits_hypothesis_scope(telemetry) -> None:
    with telemetry_scope(hypothesis_id="H-CHAIN", iteration=3):
        logical_call_id = telemetry.begin_logical_call(phase="hypothesis_plan")

    row = telemetry.db.execute(
        "SELECT hypothesis_id, iteration FROM trace.llm_logical_calls "
        "WHERE logical_call_id = ?",
        (logical_call_id,),
    ).fetchone()
    assert row == ("H-CHAIN", 3)


def test_logical_call_cap_counts_failed_calls_and_blocks_before_transport(
    tmp_path,
) -> None:
    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-CAP", max_logical_calls=1)
    set_active_telemetry(tel)

    class _FailingClient:
        calls = 0

        def post(self, url, json, headers):
            self.calls += 1
            return httpx.Response(
                500, text="provider failure", request=httpx.Request("POST", url)
            )

    client = _FailingClient()
    try:
        with (
            patch.object(llm_client, "_get_http_client", return_value=client),
            patch.object(
                llm_client,
                "get_settings",
                return_value=SimpleNamespace(llm_api_key="tok"),
            ),
            patch.object(llm_client.time, "sleep"),
        ):
            with pytest.raises(llm_client.LLMServerUnavailableError):
                llm_client.chat_completion(
                    [{"role": "user", "content": "go"}],
                    model="m",
                    base_url="http://llama.test",
                )
            with pytest.raises(LLMBudgetExceededError):
                llm_client.chat_completion(
                    [{"role": "user", "content": "again"}],
                    model="m",
                    base_url="http://llama.test",
                )
    finally:
        set_active_telemetry(None)
    assert client.calls == llm_client._LLM_HTTP_RETRY_MAX
    assert db.execute(
        "SELECT status FROM trace.llm_logical_calls WHERE session_id = 'S-CAP'"
    ).fetchall() == [("failed",)]
    assert tel.session_aggregates()["logical_call_count"] == 1


def test_unexpected_transport_error_finalizes_attempt_and_call(tmp_path) -> None:
    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-UNEXPECTED")
    set_active_telemetry(tel)

    class _BrokenClient:
        def post(self, url, json, headers):
            raise ValueError("transport adapter failed")

    try:
        with (
            patch.object(llm_client, "_get_http_client", return_value=_BrokenClient()),
            patch.object(
                llm_client,
                "get_settings",
                return_value=SimpleNamespace(llm_api_key="tok"),
            ),
        ):
            with pytest.raises(ValueError, match="transport adapter failed"):
                llm_client.chat_completion(
                    [{"role": "user", "content": "go"}],
                    model="m",
                    base_url="http://llama.test",
                )
    finally:
        set_active_telemetry(None)
    assert db.execute(
        "SELECT status, exception_class FROM trace.llm_provider_attempts WHERE session_id = 'S-UNEXPECTED'"
    ).fetchall() == [("transport_error", "ValueError")]
    assert db.execute(
        "SELECT status FROM trace.llm_logical_calls WHERE session_id = 'S-UNEXPECTED'"
    ).fetchall() == [("failed",)]


def test_json_plan_and_repair_share_one_budgeted_logical_call(tmp_path) -> None:
    from forensia.llm import json_response

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-REPAIR", max_logical_calls=1)
    set_active_telemetry(tel)
    outputs = iter(["not json", '{"ok": true}'])
    try:
        with patch.object(
            json_response, "chat_completion", side_effect=lambda **_: next(outputs)
        ):
            assert json_response.request_llm_json(
                [{"role": "user", "content": "return json"}],
                base_url="http://llama.test",
                model="m",
            ) == {"ok": True}
    finally:
        set_active_telemetry(None)
    assert db.execute(
        "SELECT phase, status FROM trace.llm_logical_calls WHERE session_id = 'S-REPAIR'"
    ).fetchall() == [("request_llm_json", "success")]
    assert tel.session_aggregates()["logical_call_count"] == 1


def test_nested_context_compaction_budget_exhaustion_propagates(tmp_path) -> None:
    from forensia.llm import json_response

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-COMPACT", max_logical_calls=1)
    set_active_telemetry(tel)
    try:
        with (
            patch.object(
                json_response,
                "chat_completion",
                side_effect=llm_client.LLMContextWindowError(
                    "context rejected", status_code=400, body="too large"
                ),
            ),
            patch.object(
                json_response,
                "_compact_messages_after_context_rejection",
                side_effect=ValueError("required prompt exceeds budget"),
            ),
        ):
            with pytest.raises(ValueError, match="required prompt exceeds budget"):
                json_response.request_llm_json(
                    [{"role": "user", "content": "x" * 5000}],
                    base_url="http://llama.test",
                    model="m",
                )
    finally:
        set_active_telemetry(None)
    assert db.execute(
        "SELECT status FROM trace.llm_logical_calls WHERE session_id = 'S-COMPACT'"
    ).fetchall() == [("failed",)]


def test_required_prompt_budget_error_closes_owned_logical_call(tmp_path) -> None:
    from forensia.llm import json_response

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-PROMPT-BUDGET", max_logical_calls=1)
    set_active_telemetry(tel)
    messages = [{"role": "user", "content": "required evidence and policy"}]
    try:
        with (
            patch.object(
                json_response,
                "get_llm_settings",
                return_value={"max_tokens": 1},
            ),
            patch(
                "forensia.context.prompt_context.get_prompt_budget_tokens",
                return_value=1,
            ),
        ):
            with pytest.raises(ValueError, match="above the configured 1-token budget"):
                json_response.request_llm_json(
                    messages,
                    base_url="http://llama.test",
                    model="m",
                )
    finally:
        set_active_telemetry(None)

    assert messages[0]["content"] == "required evidence and policy"
    assert db.execute(
        "SELECT status FROM trace.llm_logical_calls WHERE session_id = 'S-PROMPT-BUDGET'"
    ).fetchall() == [("failed",)]
    assert tel.session_aggregates()["provider_attempt_count"] == 0


def test_usage_aggregates_keep_actual_estimated_and_unknown_separate(telemetry) -> None:
    logical_id = telemetry.begin_logical_call(phase="usage")
    common = dict(
        logical_call_id=logical_id,
        endpoint="http://llama.test/v1/chat/completions",
        provider="llama",
        model="m",
        schema_mode="json_object",
        request_fingerprint=None,
        configured_output_limit=100,
        reasoning_reserve_tokens=0,
        known_context_limit=None,
        effective_output_limit=100,
        requested_output_limit=100,
        input_chars=20,
    )
    actual = telemetry.begin_attempt(**common)
    telemetry.finalize_attempt(
        attempt_id=actual,
        status="success",
        input_tokens=10,
        output_tokens=4,
        input_tokens_source="provider_actual",
        output_tokens_source="provider_actual",
    )
    estimated = telemetry.begin_attempt(**common)
    telemetry.finalize_attempt(
        attempt_id=estimated,
        status="success",
        input_tokens=5,
        output_tokens=2,
        input_tokens_source="local_estimate",
        output_tokens_source="local_estimate",
    )
    unknown = telemetry.begin_attempt(**common)
    telemetry.finalize_attempt(attempt_id=unknown, status="success")
    agg = telemetry.session_aggregates()
    assert (agg["actual_input_tokens"], agg["actual_output_tokens"]) == (10, 4)
    assert (agg["estimated_input_tokens"], agg["estimated_output_tokens"]) == (5, 2)
    assert (
        agg["unknown_input_usage_attempts"],
        agg["unknown_output_usage_attempts"],
    ) == (1, 1)


def test_client_creates_attempt_receipts_for_retry_then_success(
    tmp_path, monkeypatch
) -> None:
    from unittest.mock import patch

    from forensia.context.prompt_context import PromptMessages

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-2")
    set_active_telemetry(tel)

    class _FakeClient:
        def __init__(self):
            self.calls = 0

        def post(self, url, json, headers):
            self.calls += 1
            if self.calls == 1:
                return httpx_500()
            return httpx_200()

    def httpx_500():
        import httpx

        req = httpx.Request("POST", "http://llama.test/v1/chat/completions")
        return httpx.Response(500, text="boom", request=req)

    def httpx_200():
        import httpx

        req = httpx.Request("POST", "http://llama.test/v1/chat/completions")
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
            request=req,
        )

    fake = _FakeClient()
    messages = PromptMessages([{"role": "user", "content": "go"}], ["ret-1"])
    with (
        patch.object(tel, "begin_attempt", wraps=tel.begin_attempt) as begin_attempt,
        patch.object(llm_client, "_get_http_client", return_value=fake),
        patch.object(
            llm_client, "get_settings", return_value=SimpleNamespace(llm_api_key="tok")
        ),
        patch.object(llm_client.time, "sleep"),
    ):
        result = llm_client.chat_completion(
            messages,
            model="m",
            base_url="http://llama.test",
        )
    assert result == '{"ok": true}'
    set_active_telemetry(None)

    rows = db.execute(
        "SELECT status, http_status, retry_ordinal, request_body, response_body, prompt_metadata "
        "FROM trace.llm_provider_attempts ORDER BY retry_ordinal"
    ).fetchall()
    # one failed 500 attempt + one success attempt
    assert rows[0][0] == "provider_error" and rows[0][1] == 500
    assert rows[1][0] == "success" and rows[1][1] == 200
    assert [row[2] for row in rows] == [0, 1]
    assert json.loads(rows[0][3])["messages"] == [{"role": "user", "content": "go"}]
    assert rows[0][4] == "boom"
    assert json.loads(rows[1][4])["choices"][0]["message"]["content"] == '{"ok": true}'
    assert begin_attempt.call_args_list[0].kwargs["prompt_metadata"][
        "retrieval_event_ids"
    ] == ["ret-1"]
    assert json.loads(rows[0][5])["retrieval_event_ids"] == ["ret-1"]
    assert json.loads(rows[1][5])["retrieval_event_ids"] == ["ret-1"]
    assert tel.session_aggregates()["logical_call_count"] == 1


def test_context_rejection_attempt_metadata_explains_optional_block_omissions(
    tmp_path,
) -> None:
    from unittest.mock import patch

    from forensia.context.prompt_context import PromptMessages
    from forensia.llm.json_response import request_llm_json

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-CONTEXT-COMPACTION")
    set_active_telemetry(tel)

    class _FakeClient:
        calls = 0

        def post(self, url, json, headers):
            self.calls += 1
            req = httpx.Request("POST", url)
            if self.calls == 1:
                return httpx.Response(400, text="context length exceeded", request=req)
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {"content": '{"ok": true}'},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 2},
                },
                request=req,
            )

    settings = {
        "llm_context_window_tokens": None,
        "max_tokens": 100,
        "temperature": 0,
        "reasoning_reserve_tokens": 0,
    }
    messages = PromptMessages(
        [
            {
                "role": "system",
                "content": "<TASK>" + ("required " * 40) + "</TASK>\n"
                "<ORG_KNOWLEDGE>" + ("optional " * 100) + "</ORG_KNOWLEDGE>\n"
                "<TEMPLATE_CONTEXT>" + ("template " * 20) + "</TEMPLATE_CONTEXT>",
            }
        ],
        ["retrieval-1"],
    )
    fake = _FakeClient()
    try:
        with (
            patch.object(llm_client, "_get_http_client", return_value=fake),
            patch.object(llm_client, "get_llm_settings", return_value=settings),
            patch.object(
                llm_client,
                "get_settings",
                return_value=SimpleNamespace(llm_api_key="tok"),
            ),
            patch(
                "forensia.context.prompt_context.get_llm_settings",
                return_value=settings,
            ),
            patch(
                "forensia.context.prompt_context.get_prompt_budget_tokens",
                return_value=200,
            ),
        ):
            assert request_llm_json(
                messages,
                base_url="http://llama.test",
                model="m",
            ) == {"ok": True}
    finally:
        set_active_telemetry(None)

    rows = db.execute(
        "SELECT status, prompt_metadata FROM trace.llm_provider_attempts "
        "WHERE session_id = 'S-CONTEXT-COMPACTION' ORDER BY start_time"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "provider_error"
    assert rows[1][0] == "success"
    assert json.loads(rows[0][1])["omitted_optional_blocks"] == [
        {"name": "ORG_KNOWLEDGE", "count": 1, "reason": "input_budget"}
    ]
    assert json.loads(rows[1][1])["omitted_optional_blocks"] == [
        {
            "name": "ORG_KNOWLEDGE",
            "count": 1,
            "reason": "provider_context_rejection",
        },
        {
            "name": "TEMPLATE_CONTEXT",
            "count": 1,
            "reason": "provider_context_rejection",
        },
    ]


def test_client_creates_timeout_attempt_receipt(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    import httpx

    case = Case.init(tmp_path)
    db = CaseDB(case)
    tel = LLMTelemetry(db, session_id="S-3")
    set_active_telemetry(tel)

    class _FakeClient:
        def post(self, url, json, headers):
            raise httpx.TimeoutException("read timeout")

    messages: list[str] = []
    with (
        patch.object(llm_client, "_get_http_client", return_value=_FakeClient()),
        patch.object(
            llm_client, "get_settings", return_value=SimpleNamespace(llm_api_key="tok")
        ),
    ):
        with pytest.raises(llm_client.LLMRequestTimeoutError):
            llm_client.chat_completion(
                [{"role": "user", "content": "go"}],
                model="m",
                base_url="http://llama.test",
                status_callback=messages.append,
            )
    set_active_telemetry(None)

    rows = db.execute(
        "SELECT status, error_type, deadline_fired FROM trace.llm_provider_attempts"
    ).fetchall()
    assert rows[0][0] == "timeout"
    assert rows[0][1] == "timeout"
    assert rows[0][2] == "read"
    assert len(rows) == 1
    assert messages == ["LLM request timed out; not replaying it as an outage"]


def _truncated_response() -> httpx.Response:
    req = httpx.Request("POST", "http://llama.test/v1/chat/completions")
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": '{"ok":'}, "finish_reason": "length"}]
        },
        request=req,
    )


def _assert_truncation_receipt(db: CaseDB, session_id: str) -> None:
    calls = db.execute(
        "SELECT status FROM trace.llm_logical_calls WHERE session_id = ?", (session_id,)
    ).fetchall()
    assert calls == [("failed",)]
    row = db.execute(
        """
        SELECT status, error_type, parse_status, finish_reason, truncated,
               accepted, discarded_reason, error_body_summary, response_fingerprint,
               request_body, response_body
        FROM trace.llm_provider_attempts WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()
    assert row[:7] == (
        "parse_error",
        "truncated",
        "truncated",
        "length",
        True,
        False,
        "finish_reason=length",
    )
    assert "content_head='{" in row[7]
    assert len(row[8]) == 24
    assert json.loads(row[9])["messages"] == [{"role": "user", "content": "go"}]
    assert json.loads(row[10])["choices"][0]["message"]["content"] == '{"ok":'


def test_unusable_truncation_closes_owned_call_failed_and_marks_attempt(
    tmp_path,
) -> None:
    """Unusable truncation raises LLMOutputTruncatedError,
    leaves the owned logical call failed, and the attempt receipt terminal and explicit."""
    case = Case.init(tmp_path)
    db = CaseDB(case)

    # --- sync path ---
    tel = LLMTelemetry(db, session_id="S-sync")
    set_active_telemetry(tel)

    class _FakeClient:
        def post(self, url, json, headers):
            return _truncated_response()

    with (
        patch.object(llm_client, "_get_http_client", return_value=_FakeClient()),
        patch.object(
            llm_client, "get_settings", return_value=SimpleNamespace(llm_api_key="tok")
        ),
    ):
        with pytest.raises(llm_client.LLMOutputTruncatedError):
            llm_client.chat_completion(
                [{"role": "user", "content": "go"}],
                model="m",
                base_url="http://llama.test",
            )
    set_active_telemetry(None)
    _assert_truncation_receipt(db, "S-sync")
    assert tel.session_aggregates()["provider_attempt_count"] == 1

    # JSON-level recovery must change the request without exceeding the configured
    # model completion cap. Keep this in the existing truncation contract test.
    from forensia.llm import json_response

    attempts: list[dict] = []

    def _recover_once(**kwargs):
        attempts.append(kwargs)
        if len(attempts) == 1:
            raise llm_client.LLMOutputTruncatedError("length", content='{"ok":')
        return '{"ok": true}'

    with (
        patch.object(json_response, "chat_completion", side_effect=_recover_once),
        patch.object(
            json_response, "get_llm_settings", return_value={"max_tokens": 16384}
        ),
    ):
        parsed = json_response.request_llm_json(
            [{"role": "user", "content": "return json"}],
            base_url="http://llama.test",
            model="m",
        )
    assert parsed == {"ok": True}
    assert [attempt["max_tokens"] for attempt in attempts] == [16384, 16384]
    assert "<RETRY_CONSTRAINT>" in attempts[1]["messages"][-1]["content"]
