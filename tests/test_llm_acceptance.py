"""Provider HTTP success and host JSON acceptance are independent receipts."""

from __future__ import annotations

import json
from copy import deepcopy

import httpx
import pytest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.llm import llm_client
from forensia.llm.json_response import request_llm_json
from forensia.llm.telemetry import (
    LLMTelemetry,
    reset_active_telemetry,
    set_active_telemetry,
)


class _Provider:
    def __init__(self, outputs: tuple[str, ...]) -> None:
        self.outputs = iter(outputs)
        self.requests: list[dict] = []

    def post(self, url: str, json: dict, headers: dict[str, str]) -> httpx.Response:
        self.requests.append(deepcopy(json))
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": next(self.outputs)},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            },
            request=httpx.Request("POST", url),
        )


@pytest.fixture()
def receipt_case(tmp_path, monkeypatch):
    with CaseDB(Case.init(tmp_path / "case")) as db:
        telemetry = LLMTelemetry(db, session_id="json-acceptance")
        token = set_active_telemetry(telemetry)

        def provider(*outputs: str) -> _Provider:
            client = _Provider(outputs)
            monkeypatch.setattr(llm_client, "_get_http_client", lambda: client)
            return client

        try:
            yield db, provider
        finally:
            reset_active_telemetry(token)


def _request(**kwargs):
    return request_llm_json(
        [{"role": "user", "content": "return an object"}],
        base_url="http://llm.invalid",
        model="test-model",
        **kwargs,
    )


def _attempts(db: CaseDB) -> list[dict]:
    cursor = db.execute(
        "SELECT attempt_id, parent_attempt_id, logical_call_id, status, "
        "http_status, parse_status, accepted, discarded_reason, error_type, "
        "input_tokens, output_tokens, response_body "
        "FROM trace.llm_provider_attempts ORDER BY retry_ordinal"
    )
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def test_unparsed_http_success_does_not_claim_host_acceptance(receipt_case) -> None:
    db, provider = receipt_case
    provider("unvalidated text")

    assert (
        llm_client.chat_completion(
            [{"role": "user", "content": "return text"}],
            model="test-model",
            base_url="http://llm.invalid",
        )
        == "unvalidated text"
    )

    (attempt,) = _attempts(db)
    assert attempt["status"] == "success"
    assert attempt["parse_status"] == "unparsed"
    assert attempt["accepted"] is None


@pytest.mark.parametrize("output", ['{"ok": true}', '{"ok": true,}'])
def test_json_parser_accepts_original_or_locally_repaired_response(
    receipt_case, output
) -> None:
    db, provider = receipt_case
    client = provider(output)

    assert _request() == {"ok": True}

    (attempt,) = _attempts(db)
    assert attempt["status"] == "success"
    assert attempt["parse_status"] == "parsed"
    assert attempt["accepted"] is True
    assert attempt["discarded_reason"] is None
    assert len(client.requests) == 1


@pytest.mark.parametrize("output", ["[]", ""])
def test_host_rejection_preserves_successful_provider_receipt(
    receipt_case, output
) -> None:
    db, provider = receipt_case
    client = provider(output)

    with pytest.raises(RuntimeError):
        _request()

    (attempt,) = _attempts(db)
    assert attempt["status"] == "success"
    assert attempt["http_status"] == 200
    assert attempt["error_type"] is None
    assert attempt["parse_status"] == "error"
    assert attempt["accepted"] is False
    assert attempt["discarded_reason"]
    assert len(client.requests) == 1
    assert db.execute("SELECT status FROM trace.llm_logical_calls").fetchall() == [
        ("failed",)
    ]


@pytest.mark.parametrize("repair", ['{"ok": true}', "still invalid"])
def test_repair_outcome_belongs_to_its_own_attempt(receipt_case, repair) -> None:
    db, provider = receipt_case
    client = provider("invalid original", repair)

    if repair.startswith("{"):
        assert _request() == {"ok": True}
        call_status = "success"
        repair_accepted = True
    else:
        with pytest.raises(RuntimeError, match="one bounded correction"):
            _request()
        call_status = "failed"
        repair_accepted = False

    original, repaired = _attempts(db)
    assert original["accepted"] is False
    assert original["parse_status"] == "error"
    assert repaired["accepted"] is repair_accepted
    assert repaired["parse_status"] == ("parsed" if repair_accepted else "error")
    assert repaired["parent_attempt_id"] == original["attempt_id"]
    assert original["logical_call_id"] == repaired["logical_call_id"]
    for attempt, content in ((original, "invalid original"), (repaired, repair)):
        assert attempt["status"] == "success"
        assert attempt["http_status"] == 200
        assert attempt["error_type"] is None
        assert (attempt["input_tokens"], attempt["output_tokens"]) == (11, 7)
        assert (
            json.loads(attempt["response_body"])["choices"][0]["message"]["content"]
            == content
        )
    assert len(client.requests) == 2
    assert db.execute("SELECT status FROM trace.llm_logical_calls").fetchall() == [
        (call_status,)
    ]
