#!/usr/bin/env python3
"""Read-only evaluation of the current case database.

Run ``python scripts/eval/run.py CASE`` or pass ``BASELINE AFTER`` to include
numeric deltas for measurements recorded in both current-schema cases. Reports
go to stdout unless an explicit output path outside every case is given.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb

from forensia.db.schema import SCHEMA_VERSION


def _json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def _unknown(reason: str) -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _measure(value: Any, reason: str | None = None) -> dict[str, Any]:
    return {"value": value, "reason": reason}


def _tree_stats(case_dir: Path) -> dict[str, Any]:
    case_files = case_bytes = finding_files = finding_bytes = 0
    findings_dir = case_dir / "findings"
    for path in case_dir.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        size = path.stat().st_size
        case_files += 1
        case_bytes += size
        if findings_dir in path.parents and path.suffix == ".json":
            finding_files += 1
            finding_bytes += size
    return {
        "case_files": _measure(case_files),
        "case_bytes": _measure(case_bytes),
        "finding_export_files": _measure(finding_files),
        "finding_export_bytes": _measure(finding_bytes),
        "elapsed_ms": _unknown("Stage elapsed time is not persisted in Case or Trace"),
        "peak_memory_bytes": _unknown(
            "Peak process memory is not persisted in Case or Trace"
        ),
    }


def _check_schema(conn: duckdb.DuckDBPyConnection) -> None:
    version = conn.execute("SELECT version FROM forensia_schema").fetchone()
    if version != (SCHEMA_VERSION,):
        raise ValueError(
            f"Unsupported case schema: {version}; expected version {SCHEMA_VERSION}"
        )


@contextmanager
def _read_only_case(case_dir: Path) -> Iterator[duckdb.DuckDBPyConnection]:
    """Open and validate the unified case database without permitting writes."""
    database_path = case_dir / "db" / "case.duckdb"
    if not database_path.is_file():
        raise FileNotFoundError(f"Case database not found under {case_dir / 'db'}")
    with duckdb.connect(str(database_path), read_only=True) as conn:
        _check_schema(conn)
        yield conn


def _latest_receipt(
    conn: duckdb.DuckDBPyConnection, phase: str
) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT output_json, created_at FROM trace.investigation_steps "
        "WHERE phase = ? ORDER BY created_at DESC, step_id DESC LIMIT 1",
        [phase],
    ).fetchone()
    if not row:
        return None
    output = _json(row[0])
    if not isinstance(output, dict):
        return {"status": "invalid_receipt", "created_at": str(row[1])}
    return {**output, "created_at": row[1].isoformat() if row[1] else None}


def _stage_elapsed_ms(conn: duckdb.DuckDBPyConnection, phase: str) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT output_json, created_at FROM trace.investigation_steps "
        "WHERE phase = ? ORDER BY created_at, step_id",
        [phase],
    ).fetchall()
    parsed = [(_json(output), timestamp) for output, timestamp in rows]
    if not parsed:
        return _unknown(f"No {phase} stage receipts are recorded")
    latest, end = parsed[-1]
    if not isinstance(latest, dict) or latest.get("status") != "completed":
        return _unknown(f"Latest {phase} receipt is not completed")
    revision = latest.get("revision")
    start = next(
        (
            timestamp
            for output, timestamp in reversed(parsed[:-1])
            if isinstance(output, dict)
            and output.get("status") == "running"
            and output.get("revision") == revision
        ),
        None,
    )
    if start is None or end is None:
        return _unknown(f"{phase} start or completion timestamp is absent")
    return _measure(max(0, round((end - start).total_seconds() * 1000)))


def _analysis_metrics(receipt: dict[str, Any] | None) -> dict[str, Any]:
    reason = "No pipeline-analyze receipt is recorded in Trace"
    if receipt is None:
        return {
            key: _unknown(reason)
            for key in (
                "analysis_rules_completed",
                "analysis_rules_not_observed",
                "analysis_rules_with_matches",
                "analysis_matches",
                "analysis_unfinished_rules",
            )
        }
    rules = receipt.get("rules")
    if not isinstance(rules, list):
        reason = "Latest pipeline-analyze receipt has no structured rules list"
        return {
            key: _unknown(reason)
            for key in (
                "analysis_rules_completed",
                "analysis_rules_not_observed",
                "analysis_rules_with_matches",
                "analysis_matches",
                "analysis_unfinished_rules",
            )
        }
    statuses = Counter(
        str((rule.get("execution") or {}).get("status") or "unknown")
        for rule in rules
        if isinstance(rule, dict)
    )
    completed = [
        rule
        for rule in rules
        if isinstance(rule, dict)
        and (rule.get("execution") or {}).get("status") == "completed"
    ]
    matches_known = all(
        isinstance((rule.get("execution") or {}).get("matches"), int)
        for rule in completed
    )
    rules_with_matches = (
        _measure(sum(rule["execution"]["matches"] > 0 for rule in completed))
        if matches_known
        else _unknown("Completed rule receipts contain missing match counts")
    )
    stage_complete = receipt.get("status") == "completed"
    rule_definitions = [
        {
            key: rule.get(key)
            for key in (
                "id",
                "format",
                "definition_sha256",
                "source_rule_id",
                "target",
                "fixture",
            )
            if key in rule
        }
        for rule in rules
        if isinstance(rule, dict)
    ]
    rule_definitions.sort(key=lambda item: str(item.get("id") or ""))
    executions = [
        {key: rule.get(key) for key in ("id", "query", "execution") if key in rule}
        for rule in rules
        if isinstance(rule, dict)
    ]
    executions.sort(key=lambda item: str(item.get("id") or ""))
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()
    return {
        "analysis_rules_completed": _measure(statuses["completed"]),
        "analysis_rules_not_observed": _measure(statuses["not_observed"]),
        "analysis_rules_with_matches": rules_with_matches,
        "analysis_matches": (
            _measure(sum(rule["execution"]["matches"] for rule in completed))
            if stage_complete and matches_known
            else _unknown(
                "Latest analysis receipt is incomplete or has unknown match counts"
            )
        ),
        "analysis_unfinished_rules": _measure(
            sum(
                count
                for status, count in statuses.items()
                if status not in {"completed", "not_observed"}
            )
        ),
        "analysis_identity": {
            "rule_definitions_sha256": hashlib.sha256(
                canonical(rule_definitions)
            ).hexdigest(),
            "executable_queries_and_outcomes_sha256": hashlib.sha256(
                canonical(executions)
            ).hexdigest(),
            "rule_count": len(rules),
        },
    }


def _bundle_identity(bundle: Any) -> dict[str, Any] | None:
    if not isinstance(bundle, dict):
        return None
    summary = bundle.get("summary") or {}
    summary_fields = (
        "admitted_bindings",
        "admitted_rules",
        "bindings",
        "by_conversion",
        "by_fixture",
    )
    return {
        key: bundle.get(key)
        for key in ("build_id", "artifact_sha256", "source", "environment_hashes")
        if key in bundle
    } | {
        "summary": {key: summary[key] for key in summary_fields if key in summary},
        "target_count": len(summary.get("by_target") or {}),
    }


def _rowset_fingerprint(conn: duckdb.DuckDBPyConnection, query: str) -> dict[str, Any]:
    cursor = conn.execute(query)
    hashes: list[str] = []
    while batch := cursor.fetchmany(1000):
        hashes.extend(
            hashlib.sha256(
                json.dumps(
                    row, sort_keys=True, ensure_ascii=False, default=str
                ).encode()
            ).hexdigest()
            for row in batch
        )
    hashes.sort()
    return {
        "rows": len(hashes),
        "sha256": hashlib.sha256("".join(hashes).encode()).hexdigest(),
    }


def _result_identity(conn: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    tables = {
        "evtx_events": (
            "evidence_id, source_file, channel, event_id, record_id, timestamp, computer, "
            "user_name, target_user, subject_user, src_ip, dst_ip, dst_port, protocol, "
            "logon_type, process_name, process_id, command_line, service_name, exception_code, "
            "object_dn, attribute, target_server, target_group, task_name, session_id, share_name, "
            "access_mask, normalized_src_ip, normalized_target_user, parent_process, "
            "parent_process_id, parent_cmd, child_process, child_process_id, child_cmd, parent_image, "
            "file_path, parent_guid, child_guid, clear_time, clear_event_id, first_seen, last_seen, "
            "hour_bucket, request_count, status, reason, message, tags, severity"
        ),
        "mft_entries": "*",
        "prefetch_executions": (
            "evidence_id, source_file, executable_name, exec_count, last_exec_time, exec_times, "
            "prefetch_hash, filenames, volumes, tags, severity"
        ),
        "registry_artifacts": (
            "artifact_id, dataset_id, source_ids, plugin, hive, key_path, value_name, timestamp, "
            "timestamp_kind"
        ),
    }
    result = {
        f"{name}_normalized": _rowset_fingerprint(conn, f"SELECT {columns} FROM {name}")
        for name, columns in tables.items()
    }
    result.update(
        {
            f"{name}_serialized": _rowset_fingerprint(conn, f"SELECT * FROM {name}")
            for name in ("evtx_events", "prefetch_executions", "registry_artifacts")
        }
    )
    result["findings"] = _rowset_fingerprint(
        conn,
        "SELECT finding_id, rule_id, title, summary, severity, confidence, status, tags, "
        "attack, evidence, ai_summary, missing_checks FROM findings",
    )
    result["suppressed_findings"] = _rowset_fingerprint(
        conn, "SELECT finding_id FROM findings WHERE status = 'suppressed'"
    )
    return result


def _token_usage(conn: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for direction in ("input", "output"):
        source_col = f"{direction}_tokens_source"
        token_col = f"{direction}_tokens"
        rows = conn.execute(
            f"SELECT {source_col}, COUNT(*), COUNT({token_col}), SUM({token_col}) "
            f"FROM trace.llm_provider_attempts GROUP BY {source_col}"
        ).fetchall()
        by_source = {
            str(source or "unknown"): (int(count), int(with_tokens), total)
            for source, count, with_tokens, total in rows
        }
        for source, label in (
            ("provider_actual", "actual"),
            ("local_estimate", "estimated"),
        ):
            count, with_tokens, total = by_source.get(source, (0, 0, None))
            result[f"{direction}_tokens_{label}"] = (
                _measure(int(total))
                if with_tokens
                else _unknown(f"No {label} {direction} token measurements are recorded")
            )
            result[f"{direction}_token_{label}_attempts"] = _measure(count)
        unmeasured = int(
            conn.execute(
                f"SELECT COUNT(*) FROM trace.llm_provider_attempts "
                f"WHERE {source_col} NOT IN ('provider_actual', 'local_estimate') "
                f"OR {source_col} IS NULL OR {token_col} IS NULL"
            ).fetchone()[0]
        )
        result[f"{direction}_token_unmeasured_attempts"] = _measure(unmeasured)
    return result


def _cycle_rows(conn: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    cycles: dict[tuple[str, int], dict[str, Any]] = {}

    def get_cycle(session_id: Any, iteration: Any) -> dict[str, Any] | None:
        if session_id is None or iteration is None:
            return None
        key = (str(session_id), int(iteration))
        return cycles.setdefault(
            key,
            {
                "session_id": key[0],
                "iteration": key[1],
                "reasoning_verdicts": {},
                "reasoning_entries": 0,
                "logical_calls": 0,
                "provider_attempts": 0,
                "candidate_outcomes": {},
            },
        )

    for session_id, iteration, verdict, count in conn.execute(
        "SELECT session_id, iteration, verdict, COUNT(*) "
        "FROM trace.hypothesis_reasoning WHERE session_id IS NOT NULL "
        "AND iteration IS NOT NULL GROUP BY session_id, iteration, verdict"
    ).fetchall():
        cycle = get_cycle(session_id, iteration)
        if cycle is not None:
            verdicts = cycle["reasoning_verdicts"]
            label = str(verdict or "unknown")
            verdicts[label] = verdicts.get(label, 0) + int(count)
            cycle["reasoning_entries"] = cycle.get("reasoning_entries", 0) + int(count)

    for session_id, iteration, count in conn.execute(
        "SELECT session_id, iteration, COUNT(*) FROM trace.llm_logical_calls "
        "WHERE session_id IS NOT NULL AND iteration IS NOT NULL "
        "GROUP BY session_id, iteration"
    ).fetchall():
        cycle = get_cycle(session_id, iteration)
        if cycle is not None:
            cycle["logical_calls"] += int(count)

    for session_id, iteration, count in conn.execute(
        "SELECT c.session_id, c.iteration, COUNT(*) "
        "FROM trace.llm_provider_attempts a "
        "JOIN trace.llm_logical_calls c USING (logical_call_id) "
        "WHERE c.session_id IS NOT NULL AND c.iteration IS NOT NULL "
        "GROUP BY c.session_id, c.iteration"
    ).fetchall():
        cycle = get_cycle(session_id, iteration)
        if cycle is not None:
            cycle["provider_attempts"] += int(count)

    for session_id, iteration, output_json in conn.execute(
        "SELECT session_id, iteration, output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad-candidate' AND session_id IS NOT NULL "
        "AND iteration IS NOT NULL"
    ).fetchall():
        cycle = get_cycle(session_id, iteration)
        output = _json(output_json) or {}
        if cycle is not None:
            outcomes = cycle["candidate_outcomes"]
            label = str(output.get("status") or "unknown")
            outcomes[label] = outcomes.get(label, 0) + 1
    for session_id, iteration, output_json in conn.execute(
        "SELECT session_id, iteration, output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad' AND session_id IS NOT NULL AND iteration IS NOT NULL"
    ).fetchall():
        cycle = get_cycle(session_id, iteration)
        output = _json(output_json) or {}
        if cycle is not None:
            cycle["plan_broad_status"] = output.get("status")
            cycle["candidate_summary"] = output.get("candidate_summary")
    return [cycles[key] for key in sorted(cycles)]


def extract_cycles(case_dir: Path) -> dict[str, Any]:
    """Read only per-cycle Trace measurements from the current case database."""
    case_dir = case_dir.resolve()
    try:
        with _read_only_case(case_dir) as conn:
            return {"cycles": _cycle_rows(conn), "reader_status": "complete"}
    except (
        duckdb.Error,
        FileNotFoundError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        return {
            "reader_status": "incomplete",
            "reason": f"Could not read the current Case/Trace schema: {type(exc).__name__}: {exc}",
        }


def _candidate_workflow(conn: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT step_id, input_json, output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad-candidate' ORDER BY created_at, step_id"
    ).fetchall()
    statuses: Counter[str] = Counter()
    draft_reached = 0
    admitted_ids: set[str] = set()
    for _step_id, _input_json, output_json in rows:
        output = _json(output_json) or {}
        status = str(output.get("status") or "unknown")
        statuses[status] += 1
        if status in {
            "invalid_draft",
            "admission_rejected",
            "merge_missing",
            "admitted",
        }:
            draft_reached += 1
        if status == "admitted" and output.get("admitted_hypothesis_id"):
            admitted_ids.add(str(output["admitted_hypothesis_id"]))

    admitted_persisted = {
        str(row[0])
        for row in conn.execute(
            "SELECT DISTINCT h.hypothesis_id FROM hypotheses h "
            "JOIN trace.investigation_steps s "
            "ON h.hypothesis_id = json_extract_string(s.output_json, '$.admitted_hypothesis_id') "
            "WHERE s.phase = 'plan-broad-candidate' "
            "AND json_extract_string(s.output_json, '$.status') = 'admitted'"
        ).fetchall()
    }
    verification_ids = {
        str(row[0])
        for row in conn.execute(
            "SELECT hypothesis_id FROM trace.investigation_steps "
            "WHERE hypothesis_id IS NOT NULL AND phase IN ('check', 'do') "
            "UNION SELECT hypothesis_id FROM trace.hypothesis_reasoning "
            "WHERE hypothesis_id IS NOT NULL"
        ).fetchall()
    }
    return {
        "candidate_population": _unknown("No plan-broad receipt is recorded"),
        "candidate_attempt_receipts": _measure(len(rows)),
        "candidate_outcome_counts": dict(sorted(statuses.items())),
        "draft_reached": _measure(draft_reached),
        "admitted_hypothesis_ids": _measure(len(admitted_ids)),
        "admitted_ids_present_in_case": _measure(len(admitted_persisted)),
        "admitted_with_check_or_reasoning": _measure(
            len(admitted_persisted & verification_ids)
        ),
    }


def _candidate_summary(conn: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    row = conn.execute(
        "SELECT output_json, created_at FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad' ORDER BY created_at DESC, step_id DESC LIMIT 1"
    ).fetchone()
    if not row:
        return _candidate_workflow(conn)
    output = _json(row[0]) or {}
    summary = output.get("candidate_summary")
    if not isinstance(summary, dict) or output.get("status") != "completed":
        result = _candidate_workflow(conn)
        result["candidate_population"] = _unknown(
            f"Latest plan-broad receipt status is {output.get('status', 'unknown')} and has no completed candidate summary"
        )
        result["latest_plan_broad_status"] = output.get("status")
        result["latest_plan_broad_created_at"] = row[1].isoformat() if row[1] else None
        return result
    result = _candidate_workflow(conn)
    result["latest_plan_broad_status"] = output["status"]
    result["latest_plan_broad_created_at"] = row[1].isoformat() if row[1] else None
    result["candidate_population"] = {
        "value": summary.get("candidate_count"),
        "reason": None
        if isinstance(summary.get("candidate_count"), int)
        else "Candidate count missing from receipt",
    }
    result["candidate_summary"] = {
        key: _measure(value)
        if isinstance(value, int)
        else _unknown("Field absent from plan-broad receipt")
        for key, value in summary.items()
        if key.endswith("_count")
        or key in {"available_hypothesis_slots", "remaining_call_allowance"}
    }
    return result


def _claim_traceability(conn: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    row = conn.execute(
        "WITH cited AS ("
        " SELECT DISTINCT json_extract_string(j.value, '$') AS evidence_id "
        " FROM claims c, json_each(c.evidence_ids) j "
        " WHERE c.evidence_ids IS NOT NULL"
        "), valid AS ("
        " SELECT evidence_id FROM evtx_events UNION "
        " SELECT evidence_id FROM mft_entries UNION "
        " SELECT evidence_id FROM prefetch_executions UNION "
        " SELECT evidence_id FROM prefetch_timeline UNION "
        " SELECT artifact_id AS evidence_id FROM registry_artifacts"
        ") SELECT COUNT(*), COUNT(*) FILTER (WHERE valid.evidence_id IS NOT NULL) "
        "FROM cited LEFT JOIN valid USING (evidence_id)"
    ).fetchone()
    cited, resolvable = map(int, row)
    if cited == 0:
        return {
            "value": None,
            "reason": "No claim evidence references are recorded",
            "cited_evidence_ids": 0,
            "resolvable_evidence_ids": 0,
        }
    return {
        "value": resolvable / cited,
        "reason": None,
        "cited_evidence_ids": cited,
        "resolvable_evidence_ids": resolvable,
    }


def _benign_link_rate(conn: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    confirmed = conn.execute(
        "WITH supported AS ("
        " SELECT h.hypothesis_id, COUNT(DISTINCT f.finding_id) AS linked_findings, "
        " BOOL_OR(COALESCE((SELECT BOOL_OR(starts_with("
        "   json_extract_string(tag.value, '$'), 'benign-context:')) "
        "   FROM json_each(f.tags) tag), FALSE)) AS has_benign_context "
        " FROM hypotheses h LEFT JOIN hypothesis_evidence he "
        " ON he.hypothesis_id = h.hypothesis_id "
        " AND he.role IN ('supporting', 'corroborating') "
        " LEFT JOIN findings f ON f.finding_id = he.finding_id "
        " WHERE h.verdict = 'confirmed' GROUP BY h.hypothesis_id"
        ") SELECT COUNT(*), COUNT(*) FILTER (WHERE linked_findings > 0), "
        " COUNT(*) FILTER (WHERE linked_findings > 0 AND has_benign_context) "
        " FROM supported"
    ).fetchone()
    total_confirmed, linked_confirmed, benign_confirmed = map(int, confirmed)
    if linked_confirmed == 0:
        reason = (
            "No confirmed hypotheses have support-linked Findings with persisted benign-context tags"
            if total_confirmed
            else "No confirmed hypotheses are recorded"
        )
        rate = _unknown(reason)
    else:
        rate = {
            "value": benign_confirmed / linked_confirmed,
            "reason": None,
            "confirmed_hypotheses": total_confirmed,
            "confirmed_with_finding_support": linked_confirmed,
            "confirmed_with_benign_tagged_support_link": benign_confirmed,
            "finding_support_coverage": linked_confirmed / total_confirmed
            if total_confirmed
            else None,
            "basis": "Historical support links; evidence currentness is not recomputed by this read-only evaluator",
        }
    return rate


def extract_case(case_dir: Path) -> dict[str, Any]:
    """Extract actual measurements from the current read-only case database."""
    case_dir = case_dir.resolve()
    result: dict[str, Any] = {"case_dir": str(case_dir), "cycles": []}
    result["storage"] = (
        _tree_stats(case_dir)
        if case_dir.is_dir()
        else {
            "case_files": _unknown("Case directory not found"),
            "case_bytes": _unknown("Case directory not found"),
        }
    )
    database_path = case_dir / "db" / "case.duckdb"
    if not database_path.is_file():
        result.update(
            reader_status="incomplete",
            reason=f"Case database not found under {case_dir / 'db'}",
        )
        return result

    try:
        with _read_only_case(case_dir) as conn:
            result["case_counts"] = {
                "findings": _measure(
                    int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
                ),
                "hypotheses": _measure(
                    int(conn.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0])
                ),
                "report_sections": _measure(
                    int(
                        conn.execute("SELECT COUNT(*) FROM report_sections").fetchone()[
                            0
                        ]
                    )
                ),
                "claims": _measure(
                    int(conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0])
                ),
                "report_query_runs": _measure(
                    int(
                        conn.execute(
                            "SELECT COUNT(*) FROM section_runs WHERE phase = 'query'"
                        ).fetchone()[0]
                    )
                ),
            }
            distinct_evidence = int(
                conn.execute(
                    "SELECT COUNT(DISTINCT json_extract_string(j.value, ?)) "
                    "FROM findings f, json_each(f.evidence) j",
                    ["$.evidence_id"],
                ).fetchone()[0]
            )
            result["case_counts"]["finding_rows"] = result["case_counts"]["findings"]
            result["case_counts"]["distinct_finding_evidence"] = _measure(
                distinct_evidence
            )

            analysis_receipt = _latest_receipt(conn, "pipeline-analyze")
            normalize_receipt = _latest_receipt(conn, "pipeline-normalize")
            result["pipeline_receipts"] = {
                "normalize": {
                    key: (normalize_receipt or {}).get(key)
                    for key in (
                        "status",
                        "revision",
                        "parser_revision",
                        "summary",
                        "created_at",
                    )
                }
                if normalize_receipt
                else None,
                "analyze": (
                    {
                        key: (analysis_receipt or {}).get(key)
                        for key in ("status", "revision", "summary", "created_at")
                    }
                    | {
                        "sigma_bundle": _bundle_identity(
                            (analysis_receipt or {}).get("sigma_bundle")
                        )
                    }
                )
                if analysis_receipt
                else None,
            }
            result["storage"]["elapsed_ms"] = _stage_elapsed_ms(
                conn, "pipeline-analyze"
            )
            result["result_identity"] = _result_identity(conn)
            result["case_counts"].update(_analysis_metrics(analysis_receipt))
            bundle = (analysis_receipt or {}).get("sigma_bundle")
            source_rows = [
                tuple(row)
                for row in conn.execute(
                    "SELECT sha256, source_kind, size FROM ingested_files ORDER BY sha256"
                ).fetchall()
            ]
            result["generation_identity"] = {
                "analysis_revision": (analysis_receipt or {}).get("revision"),
                "sigma_bundle": _bundle_identity(bundle),
                "input_source_count": len(source_rows),
                "input_source_bytes": sum(int(row[2] or 0) for row in source_rows),
                "input_source_fingerprint": hashlib.sha256(
                    json.dumps(source_rows, separators=(",", ":")).encode()
                ).hexdigest(),
                "input_families": [
                    {"source_kind": row[0], "files": row[1], "bytes": row[2]}
                    for row in conn.execute(
                        "SELECT source_kind, COUNT(*), SUM(size) FROM ingested_files "
                        "GROUP BY source_kind ORDER BY source_kind"
                    ).fetchall()
                ],
            }

            result["quality"] = {
                "confirmed_hypotheses_with_benign_tagged_finding_link_rate": _benign_link_rate(
                    conn
                ),
                "false_positive_count": _unknown(
                    "No persisted lead annotations or adjudicated outcomes are available"
                ),
                "false_negative_count": _unknown(
                    "No persisted lead annotations or adjudicated outcomes are available"
                ),
                "claim_evidence_traceability": _claim_traceability(conn),
            }

            result["usage"] = {
                "logical_calls": _measure(
                    int(
                        conn.execute(
                            "SELECT COUNT(*) FROM trace.llm_logical_calls"
                        ).fetchone()[0]
                    )
                ),
                "provider_attempts": _measure(
                    int(
                        conn.execute(
                            "SELECT COUNT(*) FROM trace.llm_provider_attempts"
                        ).fetchone()[0]
                    )
                ),
                "deterministic_ops": _measure(
                    int(
                        conn.execute(
                            "SELECT COUNT(*) FROM trace.llm_deterministic_ops"
                        ).fetchone()[0]
                    )
                ),
                "hypothesis_query_ops": _measure(
                    int(
                        conn.execute(
                            "SELECT COUNT(*) FROM trace.llm_deterministic_ops WHERE op_type = 'query'"
                        ).fetchone()[0]
                    )
                ),
                "report_query_runs": result["case_counts"]["report_query_runs"],
            }
            result["usage"].update(_token_usage(conn))
            result["llm_request_profiles"] = [
                {
                    "provider": row[0],
                    "model": row[1],
                    "schema_mode": row[2],
                    "configured_output_limit": row[3],
                    "known_context_limit": row[4],
                    "effective_output_limit": row[5],
                    "attempts": row[6],
                }
                for row in conn.execute(
                    "SELECT provider, model, schema_mode, configured_output_limit, "
                    "known_context_limit, effective_output_limit, COUNT(*) "
                    "FROM trace.llm_provider_attempts GROUP BY ALL "
                    "ORDER BY provider, model, schema_mode"
                ).fetchall()
            ]

            result["sessions"] = [
                {
                    "session_id": row[0],
                    "started_at": row[1].isoformat() if row[1] else None,
                    "finished_at": row[2].isoformat() if row[2] else None,
                    "iterations": row[3],
                    "status": row[4],
                    "terminal_reason": row[5],
                    "phase": row[6],
                    "status_reason": row[7],
                }
                for row in conn.execute(
                    "SELECT session_id, started_at, finished_at, iterations, status, "
                    "terminal_reason, phase, status_reason "
                    "FROM trace.investigation_sessions ORDER BY started_at, session_id"
                ).fetchall()
            ]
            outcome_rows = conn.execute(
                "SELECT session_id, SUM(created), SUM(resolved), "
                "SUM(confirmed_at_creation), SUM(refuted_at_creation) FROM ("
                " SELECT created_session AS session_id, 1 AS created, 0 AS resolved, "
                " CASE WHEN verdict = 'confirmed' THEN 1 ELSE 0 END AS confirmed_at_creation, "
                " CASE WHEN verdict = 'refuted' THEN 1 ELSE 0 END AS refuted_at_creation "
                " FROM hypotheses WHERE created_session IS NOT NULL UNION ALL "
                " SELECT resolved_session, 0, 1, 0, 0 FROM hypotheses "
                " WHERE resolved_session IS NOT NULL"
                ") GROUP BY session_id ORDER BY session_id"
            ).fetchall()
            result["session_hypothesis_outcomes"] = [
                {
                    "session_id": row[0],
                    "created": int(row[1] or 0),
                    "resolved": int(row[2] or 0),
                    "currently_confirmed_created": int(row[3] or 0),
                    "currently_refuted_created": int(row[4] or 0),
                }
                for row in outcome_rows
            ]

            result["candidate_workflow"] = _candidate_summary(conn)
            result["cycles"] = _cycle_rows(conn)
            result["reader_status"] = "complete"
    except (duckdb.Error, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        result["reader_status"] = "incomplete"
        result["reason"] = (
            f"Could not read the current Case/Trace schema: {type(exc).__name__}: {exc}"
        )
    return result


def _numeric_deltas(cases: list[dict[str, Any]]) -> dict[str, Any] | None:
    if len(cases) != 2:
        return None
    before, after = cases
    groups = ("case_counts", "quality", "usage", "storage")
    metrics: dict[str, Any] = {}
    for group in groups:
        metrics[group] = {}
        for key, new in after.get(group, {}).items():
            old = before.get(group, {}).get(key, {})
            old_value, new_value = old.get("value"), new.get("value")
            delta = (
                new_value - old_value
                if isinstance(old_value, (int, float))
                and isinstance(new_value, (int, float))
                else None
            )
            metrics[group][key] = {
                "before": old_value,
                "after": new_value,
                "delta": delta,
                "reason": None
                if delta is not None
                else "Both cases need a measured numeric value",
            }
    identity_keys = (
        "input_source_fingerprint",
        "sigma_bundle",
    )
    identities: dict[str, Any] = {}
    for key in identity_keys:
        old = before.get("generation_identity", {}).get(key)
        new = after.get("generation_identity", {}).get(key)
        identities[key] = {
            "before": old,
            "after": new,
            "match": old == new if old is not None and new is not None else None,
        }
    old_result = before.get("result_identity", {})
    new_result = after.get("result_identity", {})
    identities["result_sets"] = {
        name: {
            "before": old_result.get(name),
            "after": new_result.get(name),
            "match": old_result[name] == new_result[name]
            if name in old_result and name in new_result
            else None,
        }
        for name in sorted(set(old_result) | set(new_result))
    }
    identities["analysis_fingerprints"] = {
        name: {
            "before": before.get("case_counts", {})
            .get("analysis_identity", {})
            .get(name),
            "after": after.get("case_counts", {})
            .get("analysis_identity", {})
            .get(name),
            "match": before.get("case_counts", {})
            .get("analysis_identity", {})
            .get(name)
            == after.get("case_counts", {}).get("analysis_identity", {}).get(name),
        }
        for name in (
            "rule_definitions_sha256",
            "executable_queries_and_outcomes_sha256",
        )
    }
    return {
        "before_case": before["case_dir"],
        "after_case": after["case_dir"],
        "metrics": metrics,
        "identity_comparison": identities,
    }


def _markdown(data: dict[str, Any]) -> str:
    lines = ["# Investigation evaluation", ""]
    for case in data["cases"]:
        lines.extend(
            [
                f"## {case['case_dir']}",
                "",
                f"Reader status: {case['reader_status']}",
                "",
            ]
        )
        for group in ("case_counts", "quality", "usage", "storage"):
            values = case.get(group, {})
            if not values:
                continue
            lines.append(f"### {group.replace('_', ' ').title()}")
            for name, metric in values.items():
                if isinstance(metric, dict) and "value" in metric:
                    value = json.dumps(metric["value"], ensure_ascii=False)
                    reason = f" — {metric['reason']}" if metric.get("reason") else ""
                else:
                    value = json.dumps(metric, ensure_ascii=False, sort_keys=True)
                    reason = ""
                lines.append(f"- {name}: {value}{reason}")
            lines.append("")
    comparison = data.get("comparison")
    if comparison:
        lines.extend(["## Before/after deltas", ""])
        for group, metrics in comparison["metrics"].items():
            for name, metric in metrics.items():
                delta = metric["delta"] if metric["delta"] is not None else "unknown"
                lines.append(f"- {group}.{name}: {delta}")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "case_dirs", nargs="+", type=Path, help="one case, or baseline then after"
    )
    parser.add_argument(
        "--output", type=Path, help="write JSON outside evaluated cases"
    )
    parser.add_argument(
        "--markdown", type=Path, help="write Markdown outside evaluated cases"
    )
    args = parser.parse_args()
    if len(args.case_dirs) > 2:
        parser.error("pass one case or exactly baseline and after cases")

    roots = [path.resolve() for path in args.case_dirs]
    cases = [extract_case(path) for path in roots]
    data = {"cases": cases, "comparison": _numeric_deltas(cases)}
    for output in (args.output, args.markdown):
        if output is not None:
            target = output.resolve()
            if any(target == root or root in target.parents for root in roots):
                parser.error(
                    f"evaluation output must be outside case directories: {target}"
                )

    if args.output:
        args.output.resolve().write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    if args.markdown:
        args.markdown.resolve().write_text(_markdown(data), encoding="utf-8")
    return 0 if all(case["reader_status"] == "complete" for case in cases) else 2


if __name__ == "__main__":
    sys.exit(main())
