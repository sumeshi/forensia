from __future__ import annotations

from copy import deepcopy
from unittest.mock import patch

import duckdb
import pytest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.rules import engine


@pytest.fixture
def db(tmp_path):
    with CaseDB(Case.init(tmp_path)) as database:
        yield database


@pytest.mark.parametrize(
    ("fallback", "expected_sql", "resolved"),
    [
        (
            {"phase": "keyword_in_raw_json", "keywords": [None, "a%b_c!d'e"]},
            "SELECT * FROM evtx_events WHERE "
            "raw_json LIKE '%a!%b!_c!!d''e%' ESCAPE '!' LIMIT 100",
            {"keywords": ["a%b_c!d'e"]},
        ),
        (
            {"phase": "related_event_ids", "event_ids": [None, "bad", "4720"]},
            "SELECT * FROM evtx_events WHERE event_id IN (4720) LIMIT 100",
            {"event_ids": [4720]},
        ),
        (
            {"phase": "artifact_table", "table": " EVTX_EVENTS "},
            "SELECT * FROM evtx_events LIMIT 100",
            {"table": "evtx_events"},
        ),
    ],
)
def test_fallback_observer_reports_exact_sql_and_resolved_inputs(
    db, fallback, expected_sql, resolved
) -> None:
    db.execute(
        "INSERT INTO evtx_events (evidence_id, event_id, raw_json) VALUES (?, ?, ?)",
        ["ev-1", 4720, '{"message":"a%b_c!d\'e"}'],
    )
    original = deepcopy(fallback)
    events = []
    order = []
    actual_iterator = engine.iter_rule_row_batches

    def observe(event):
        events.append(event)
        order.append(event["status"])

    def execute(database, rule):
        order.append("execute")
        assert events[0]["sql"] == rule.query
        yield from actual_iterator(database, rule)

    with patch.object(engine, "iter_rule_row_batches", side_effect=execute):
        rows = engine.execute_fallback_search(db, fallback, on_query=observe)

    assert [row["evidence_id"] for row in rows] == ["ev-1"]
    assert order == ["running", "execute", "completed"]
    assert events[0]["query_ref"] == events[1]["query_ref"]
    assert events[0]["query_ref"]
    for event in events:
        assert event["sql"] == expected_sql
        assert event["params"] == []
        assert event["phase"] == fallback["phase"]
        assert event["config"] == {**fallback, **resolved, "limit": 100}
        assert event["row_limit"] == 100
    assert events[0]["returned_count"] is None
    assert events[0]["truncated"] is None
    assert events[1]["returned_count"] == 1
    assert events[1]["truncated"] is False
    assert fallback == original


@pytest.mark.parametrize("has_match", [False, True])
def test_event_keyword_observer_reports_query_even_for_empty_results(
    db, monkeypatch, has_match
) -> None:
    monkeypatch.setattr(
        engine,
        "_load_event_id_hints",
        lambda: {4720: {"keywords_for_string_search": ["Needle", "needle"]}},
    )
    db.execute(
        "INSERT INTO evtx_events (evidence_id, raw_json) VALUES (?, ?)",
        ["ev-1", '{"message":"NEEDLE"}' if has_match else '{"message":"other"}'],
    )
    original_sql = "SELECT * FROM evtx_events WHERE event_id IN (4720, 999)"
    events = []
    order = []
    actual_execute = db.execute

    def execute(sql, params=None):
        order.append("execute")
        assert sql == events[0]["sql"]
        assert params is None
        return actual_execute(sql, params)

    def observe(event):
        order.append(event["status"])
        events.append(event)

    monkeypatch.setattr(db, "execute", execute)
    rows, fallback_info = engine.execute_event_keyword_fallback_search(
        db, original_sql, on_query=observe
    )

    assert order == ["running", "execute", "completed"]
    assert len(rows) == int(has_match)
    assert fallback_info == (
        {
            "phase": "keyword_in_raw_json",
            "event_ids": [4720],
            "keywords": ["Needle"],
            "source": "event_id_schema",
        }
        if has_match
        else None
    )
    assert events[0]["sql"] == (
        "SELECT * FROM evtx_events WHERE "
        "LOWER(CAST(raw_json AS VARCHAR)) LIKE '%needle%' ESCAPE '!' LIMIT 100"
    )
    assert events[0]["config"] == {
        "phase": "keyword_in_raw_json",
        "event_ids": [4720],
        "keywords": ["Needle"],
        "source": "event_id_schema",
        "original_sql": original_sql,
        "limit": 100,
    }
    assert events[1]["query_ref"] == events[0]["query_ref"]
    assert events[1]["returned_count"] == int(has_match)
    assert events[1]["truncated"] is False


@pytest.mark.parametrize(
    "fallback",
    [
        {},
        {"phase": "unknown"},
        {"phase": "keyword_in_raw_json"},
        {"phase": "keyword_in_raw_json", "keywords": "string"},
        {"phase": "keyword_in_raw_json", "keywords": [None, 1]},
        {"phase": "related_event_ids"},
        {"phase": "related_event_ids", "event_ids": [None, "bad"]},
        {"phase": "artifact_table"},
        {"phase": "artifact_table", "table": "findings"},
    ],
)
def test_invalid_fallback_without_sql_emits_no_events(fallback) -> None:
    events = []
    assert (
        engine.execute_fallback_search(object(), fallback, on_query=events.append) == []
    )
    assert events == []


@pytest.mark.parametrize("sql", ["SELECT 1", "SELECT 1 WHERE event_id = 999"])
def test_missing_event_keyword_configuration_emits_no_events(monkeypatch, sql) -> None:
    monkeypatch.setattr(engine, "_load_event_id_hints", lambda: {})
    events = []
    assert engine.execute_event_keyword_fallback_search(
        object(), sql, on_query=events.append
    ) == ([], None)
    assert engine._execute_keyword_search(object(), [], on_query=events.append) == []
    assert events == []


@pytest.mark.parametrize(
    "fallback",
    [
        {"phase": "keyword_in_raw_json", "keywords": ["needle"]},
        {"phase": "related_event_ids", "event_ids": [4720]},
        {"phase": "artifact_table", "table": "evtx_events"},
        None,
    ],
)
def test_fallback_sql_failure_is_observed_and_propagated(db, fallback) -> None:
    db.execute("DROP TABLE evtx_events")
    events = []
    with pytest.raises(duckdb.CatalogException) as caught:
        if fallback is None:
            engine._execute_keyword_search(db, ["needle"], on_query=events.append)
        else:
            engine.execute_fallback_search(db, fallback, on_query=events.append)

    assert [event["status"] for event in events] == ["running", "failed"]
    assert events[0]["query_ref"] == events[1]["query_ref"]
    assert events[0]["sql"] == events[1]["sql"]
    assert events[1]["error"] == str(caught.value)
    assert events[1]["reason"] == str(caught.value)
    assert events[1]["error_type"] == "CatalogException"
    assert events[1]["returned_count"] is None
    assert events[1]["truncated"] is None


@pytest.mark.parametrize("row_count", [0, 99, 100, 101])
def test_fallback_cap_is_unchanged_and_observer_keeps_truncation_unknown(db, row_count):
    db.execute(
        "INSERT INTO evtx_events (evidence_id) SELECT CAST(range AS VARCHAR) "
        "FROM range(?)",
        [row_count],
    )
    fallback = {"phase": "artifact_table", "table": "evtx_events"}
    events = []
    rows = engine.execute_fallback_search(db, fallback, on_query=events.append)
    plain_rows = engine.execute_fallback_search(db, fallback)

    assert len(rows) == min(row_count, 100)
    assert rows == plain_rows
    assert events[1]["returned_count"] == min(row_count, 100)
    assert events[1]["truncated"] is (False if row_count < 100 else None)
    next_events = []
    engine.execute_fallback_search(db, fallback, on_query=next_events.append)
    assert events[0]["query_ref"] != next_events[0]["query_ref"]
