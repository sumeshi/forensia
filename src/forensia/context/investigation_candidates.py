"""Bounded, provenance preserving projection of current Findings for investigation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records
from forensia.db.query import fetch_records


def _projection_sql(*, include_members: bool = False) -> str:
    return f"""
    WITH finding_refs AS (
        SELECT f.finding_id, f.rule_id, f.title, f.summary, f.severity,
               f.confidence, f.status,
               json_extract_string(j.value, '$.evidence_id') AS evidence_id
          FROM findings f, json_each(f.evidence) j
         WHERE COALESCE(f.status, 'accepted') != 'suppressed'
    ),
    raw_matches AS (
        SELECT f.finding_id, f.rule_id, f.title, f.summary, f.severity,
               f.confidence, f.status, e.evidence_id, 'evtx' AS source_family,
               e.source_file, e.computer AS host, e.timestamp, e.target_user,
               e.src_ip, e.dst_ip, e.file_path, e.process_name, e.object_dn,
               e.event_id, sha256(CAST(to_json(e) AS VARCHAR)) AS content_hash
          FROM finding_refs f JOIN evtx_events e ON e.evidence_id = f.evidence_id
        UNION ALL
        SELECT f.finding_id, f.rule_id, f.title, f.summary, f.severity,
               f.confidence, f.status, e.evidence_id, 'mft' AS source_family,
               e.source_file, NULL AS host,
               COALESCE(e.si_modified, e.fn_modified, e.si_created, e.fn_created) AS timestamp,
               NULL AS target_user, NULL AS src_ip, NULL AS dst_ip, e.file_path,
               NULL AS process_name, NULL AS object_dn, NULL AS event_id,
               sha256(CAST(to_json(e) AS VARCHAR)) AS content_hash
          FROM finding_refs f JOIN mft_entries e ON e.evidence_id = f.evidence_id
        UNION ALL
        SELECT f.finding_id, f.rule_id, f.title, f.summary, f.severity,
               f.confidence, f.status, e.evidence_id, 'prefetch' AS source_family,
               e.source_file, NULL AS host, e.last_exec_time AS timestamp,
               NULL AS target_user, NULL AS src_ip, NULL AS dst_ip, NULL AS file_path,
               e.executable_name AS process_name, NULL AS object_dn, NULL AS event_id,
               sha256(CAST(to_json(e) AS VARCHAR)) AS content_hash
          FROM finding_refs f JOIN prefetch_executions e ON e.evidence_id = f.evidence_id
        UNION ALL
        SELECT f.finding_id, f.rule_id, f.title, f.summary, f.severity,
               f.confidence, f.status, e.evidence_id, 'prefetch' AS source_family,
               e.source_file, NULL AS host, e.exec_time AS timestamp,
               NULL AS target_user, NULL AS src_ip, NULL AS dst_ip, NULL AS file_path,
               e.executable_name AS process_name, NULL AS object_dn, NULL AS event_id,
               sha256(CAST(to_json(e) AS VARCHAR)) AS content_hash
          FROM finding_refs f JOIN prefetch_timeline e ON e.evidence_id = f.evidence_id
         WHERE NOT EXISTS (
             SELECT 1 FROM prefetch_executions x WHERE x.evidence_id = e.evidence_id
         )
        UNION ALL
        SELECT f.finding_id, f.rule_id, f.title, f.summary, f.severity,
               f.confidence, f.status, e.artifact_id AS evidence_id, 'registry' AS source_family,
               CAST(e.source_ids AS VARCHAR) AS source_file, NULL AS host,
               e.timestamp, NULL AS target_user, NULL AS src_ip, NULL AS dst_ip,
               e.key_path AS file_path, NULL AS process_name, e.key_path AS object_dn,
               NULL AS event_id,
               sha256(CAST(to_json(struct_pack(
                   artifact_id := e.artifact_id,
                   dataset_id := e.dataset_id,
                   source_ids := e.source_ids,
                   plugin := e.plugin,
                   hive := e.hive,
                   key_path := e.key_path,
                   value_name := e.value_name,
                   "timestamp" := e.timestamp,
                   timestamp_kind := e.timestamp_kind,
                   raw_json := e.raw_json
               )) AS VARCHAR)) AS content_hash
          FROM finding_refs f JOIN registry_artifacts e ON e.artifact_id = f.evidence_id
    ),
    evidence_matches AS (
        SELECT evidence_id,
               any_value(source_file) AS source_file,
               any_value(source_family) AS source_family,
               any_value(host) AS host,
               any_value(timestamp) AS timestamp,
               any_value(target_user) AS target_user,
               any_value(src_ip) AS src_ip,
               any_value(dst_ip) AS dst_ip,
               any_value(file_path) AS file_path,
               any_value(process_name) AS process_name,
               any_value(object_dn) AS object_dn,
               any_value(content_hash) AS content_hash,
               count(DISTINCT finding_id) AS match_count,
               sha256(string_agg(CAST(to_json(struct_pack(
                   finding_id := finding_id,
                   rule_id := rule_id,
                   title := title,
                   summary := summary,
                   severity := severity,
                   confidence := confidence,
                   status := status
               )) AS VARCHAR), '' ORDER BY finding_id)) AS finding_content_hash,
               list_sort(list(DISTINCT rule_id)) AS rule_ids,
               arg_min(finding_id, finding_id) AS representative_finding_id,
               arg_max(severity, CASE lower(severity)
                   WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                   WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END) AS severity,
               max(confidence) AS confidence
          FROM raw_matches
         GROUP BY evidence_id
    ),
    enriched AS (
        SELECT e.*,
               COALESCE(e.host, '') AS scope_host,
               COALESCE(CAST(e.timestamp AS VARCHAR), '') AS scope_time,
               COALESCE(
                   CASE WHEN NULLIF(e.target_user, '') IS NOT NULL
                        THEN 'target_user:' || e.target_user END,
                   CASE WHEN NULLIF(e.src_ip, '') IS NOT NULL
                        THEN 'src_ip:' || e.src_ip END,
                   CASE WHEN NULLIF(e.dst_ip, '') IS NOT NULL
                        THEN 'dst_ip:' || e.dst_ip END,
                   CASE WHEN NULLIF(e.file_path, '') IS NOT NULL
                        THEN 'file_path:' || e.file_path END,
                   CASE WHEN NULLIF(e.process_name, '') IS NOT NULL
                        THEN 'process_name:' || e.process_name END,
                   CASE WHEN NULLIF(e.object_dn, '') IS NOT NULL
                        THEN 'object_dn:' || e.object_dn END
               ) AS entity,
               sha256(to_json(e.rule_ids)::VARCHAR) AS rules_key,
               sha256(concat_ws(':', e.source_family, COALESCE(e.source_file, ''))) AS source_key,
               COALESCE(e.source_file, '') IN ('', '[]') AS source_missing
          FROM evidence_matches e
    ),
    candidate_rows AS (
        SELECT *,
               CASE WHEN entity IS NULL OR entity = '' OR scope_time = '' OR source_missing
                         OR (source_family = 'evtx' AND scope_host = '')
                    THEN evidence_id ELSE entity END AS entity_key,
               CASE WHEN entity IS NULL OR entity = '' OR scope_time = '' OR source_missing
                         OR (source_family = 'evtx' AND scope_host = '')
                    THEN true ELSE false END AS entity_is_unknown,
               CASE WHEN scope_time = '' THEN '' ELSE substr(scope_time, 1, 10) END AS day_scope
          FROM enriched
    ),
    grouped AS (
        SELECT rules_key, source_key, any_value(source_family) AS source_family,
               scope_host, day_scope, entity_key,
               count(*) AS evidence_count,
               sum(match_count) AS match_count,
               {"list_sort(list(evidence_id)) AS all_evidence_ids," if include_members else ""}
               {"list_sort(list_distinct(flatten(list(rule_ids)))) AS all_rule_ids," if include_members else ""}
               list_slice(list_sort(list(evidence_id)), 1, 3) AS representative_ids,
               list_slice(list_sort(list_distinct(flatten(list(rule_ids)))), 1, 20) AS rule_ids,
               len(list_distinct(flatten(list(rule_ids)))) AS rule_count,
               arg_min(representative_finding_id, evidence_id) AS representative_finding_id,
               sha256(first(entity_key)) AS entity_key_fingerprint,
               bool_or(entity_is_unknown) AS entity_is_unknown,
               max(CASE lower(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4
                   WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END) AS severity_rank,
               max(confidence) AS confidence,
               sha256(string_agg(evidence_id || ':' || content_hash || ':' || finding_content_hash,
                   ',' ORDER BY evidence_id)) AS membership_hash
          FROM candidate_rows
         GROUP BY rules_key, source_key, scope_host, day_scope, entity_key
    ),
    ranked_candidates AS (
    SELECT rules_key, source_key, source_family, scope_host, day_scope,
           evidence_count, match_count, representative_ids, rule_ids,
           rule_count, representative_finding_id,
           entity_key_fingerprint, entity_is_unknown,
           severity_rank, confidence, membership_hash
           {", all_evidence_ids" if include_members else ""}
           {", all_rule_ids" if include_members else ""}
      FROM grouped
    ),
    bucket_order AS (
        SELECT rules_key, source_key, scope_host, day_scope,
               max(severity_rank) AS bucket_severity,
               row_number() OVER (
                   ORDER BY max(severity_rank) DESC, rules_key, source_key,
                            scope_host, day_scope
               ) AS bucket_rank
          FROM ranked_candidates
         GROUP BY rules_key, source_key, scope_host, day_scope
    ),
    ordered AS (
        SELECT c.*,
               row_number() OVER (
                   PARTITION BY c.rules_key, c.source_key, c.scope_host, c.day_scope
                   ORDER BY c.severity_rank DESC, c.evidence_count DESC,
                            c.entity_key_fingerprint
               ) AS bucket_item_rank,
               b.bucket_rank,
               count(*) OVER () AS candidate_population_count,
               sum(c.match_count) OVER () AS match_population_count,
               sum(c.evidence_count) OVER () AS evidence_population_count
          FROM ranked_candidates c
          JOIN bucket_order b USING (rules_key, source_key, scope_host, day_scope)
    )
    SELECT * FROM ordered
     ORDER BY bucket_item_rank, bucket_rank
    """


def build_investigation_candidates(
    db: CaseDB,
    limit: int = 20,
    *,
    excluded_fingerprints: Iterable[str] = (),
    eligible: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Aggregate and stream current matches, then select and hydrate a bounded set.

    ``eligible`` receives metadata only and must be a pure in-memory predicate; it
    runs while the result cursor is being consumed and must not execute SQL.
    """
    result = db.execute(_projection_sql())
    columns = [item[0] for item in result.description]
    excluded = set(excluded_fingerprints)
    selected: list[dict[str, Any]] = []
    filtered_count = eligible_count = 0
    population_count = match_count = evidence_count_total = 0
    while raw_row := result.fetchone():
        row = dict(zip(columns, raw_row, strict=False))
        for key in ("rule_ids", "representative_ids"):
            value = row.get(key)
            if isinstance(value, str):
                try:
                    row[key] = json.loads(value)
                except json.JSONDecodeError:
                    row[key] = []
        population_count = int(row["candidate_population_count"])
        match_count = int(row["match_population_count"])
        evidence_count_total = int(row["evidence_population_count"])
        candidate_ref = (
            "cand-"
            + hashlib.sha256(
                json.dumps(
                    [
                        row["rules_key"],
                        row["source_key"],
                        row["scope_host"],
                        row["day_scope"],
                        row["entity_key_fingerprint"],
                    ],
                    separators=(",", ":"),
                    default=str,
                ).encode()
            ).hexdigest()[:20]
        )
        fingerprint = (
            "cf-"
            + hashlib.sha256(
                f"{candidate_ref}:{row['membership_hash']}:{row['evidence_count']}:{row['match_count']}".encode()
            ).hexdigest()[:24]
        )
        if candidate_ref in excluded or fingerprint in excluded:
            filtered_count += 1
            continue
        representative_ids = row.get("representative_ids") or []
        rule_ids = row.get("rule_ids") or []
        finding_id = row.get("representative_finding_id")
        candidate = {
            "finding_id": finding_id,
            "finding_ids": [finding_id] if finding_id else [],
            "rule_ids": rule_ids[:20],
            "rule_count": int(row["rule_count"]),
            "omitted_rule_count": max(0, int(row["rule_count"]) - len(rule_ids)),
            "title": "",
            "summary": "",
            "severity": _severity_label(int(row.get("severity_rank") or 0)),
            "confidence": float(row.get("confidence") or 0),
            "status": "current",
            "evidence": [],
            "candidate_ref": candidate_ref,
            "candidate_fingerprint": fingerprint,
            "match_count": int(row["match_count"]),
            "evidence_count": int(row["evidence_count"]),
            "omitted_count": max(
                0, int(row["evidence_count"]) - len(representative_ids)
            ),
            "evidence_ids": representative_ids,
            "scope": {
                "host": row["scope_host"] or None,
                "day": row["day_scope"] or None,
                "source_family": row["source_family"],
                "source_identity_fingerprint": row["source_key"] or None,
            },
            "expansion": {
                "candidate_ref": candidate_ref,
                "rules_key": row["rules_key"],
                "rule_ids": rule_ids,
                "source_identity_fingerprint": row["source_key"] or None,
                "host": row["scope_host"] or None,
                "day": row["day_scope"] or None,
                "entity_fingerprint": row["entity_key_fingerprint"],
                "entity_is_unknown": row["entity_is_unknown"],
            },
        }
        if eligible is not None and not eligible(candidate):
            filtered_count += 1
            continue
        eligible_count += 1
        if len(selected) < max(0, limit):
            selected.append(candidate)
    selected_ids = list(
        dict.fromkeys(
            str(evidence_id)
            for item in selected
            for evidence_id in item["evidence_ids"]
        )
    )
    selected_records = fetch_evidence_records(db, selected_ids)
    for item in selected:
        item["evidence"] = [
            selected_records[evidence_id]
            for evidence_id in item["evidence_ids"]
            if evidence_id in selected_records
        ]
    selected_finding_ids = list(
        dict.fromkeys(
            str(item["finding_id"]) for item in selected if item["finding_id"]
        )
    )
    if selected_finding_ids:
        placeholders = ", ".join("?" for _ in selected_finding_ids)
        finding_rows = fetch_records(
            db,
            f"SELECT finding_id, title, summary FROM findings WHERE finding_id IN ({placeholders})",
            tuple(selected_finding_ids),
        )
        finding_by_id = {str(row["finding_id"]): row for row in finding_rows}
        for item in selected:
            finding = finding_by_id.get(str(item["finding_id"]))
            if finding:
                item["title"] = finding.get("title") or "Investigation observations"
                item["summary"] = finding.get("summary") or ""
    return {
        "counts": {
            "match_count": match_count,
            "distinct_evidence_count": evidence_count_total,
            "candidate_count": population_count,
            "eligible_candidate_count": eligible_count,
            "excluded_count": filtered_count,
            "presented_count": len(selected),
            "unpresented_count": max(0, population_count - len(selected)),
        },
        "candidates": selected,
    }


def _severity_label(rank: int) -> str:
    return {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}.get(
        rank, "unknown"
    )


def expand_investigation_candidate(
    db: CaseDB, candidate: dict[str, Any], *, offset: int = 0, limit: int = 20
) -> list[dict[str, Any]]:
    """Fetch a bounded page of the candidate's current evidence rows by its full predicate."""
    if limit <= 0 or offset < 0:
        return []
    criteria = candidate.get("expansion") or {}
    rows = fetch_records(
        db,
        f"""
        SELECT list_slice(all_evidence_ids, ?, ?) AS evidence_ids
          FROM ({_projection_sql(include_members=True)}) p
         WHERE rules_key = ? AND source_key = ? AND scope_host = ?
           AND day_scope = ? AND entity_key_fingerprint = ?
        """,
        [
            offset + 1,
            offset + limit,
            criteria.get("rules_key", ""),
            criteria.get("source_identity_fingerprint") or "",
            criteria.get("host") or "",
            criteria.get("day") or "",
            criteria.get("entity_fingerprint", ""),
        ],
    )
    if not rows:
        return []
    ids = rows[0].get("evidence_ids") or []
    if isinstance(ids, str):
        try:
            ids = json.loads(ids)
        except json.JSONDecodeError:
            return []
    records = fetch_evidence_records(db, [str(eid) for eid in ids])
    return [records[str(eid)] for eid in ids if str(eid) in records]


def expand_investigation_candidate_rules(
    db: CaseDB, candidate: dict[str, Any], *, offset: int = 0, limit: int = 20
) -> list[str]:
    """Fetch a bounded page of every original Rule ref represented by a candidate."""
    if limit <= 0 or offset < 0:
        return []
    criteria = candidate.get("expansion") or {}
    rows = fetch_records(
        db,
        f"""
        SELECT list_slice(all_rule_ids, ?, ?) AS rule_ids
          FROM ({_projection_sql(include_members=True)}) p
         WHERE rules_key = ? AND source_key = ? AND scope_host = ?
           AND day_scope = ? AND entity_key_fingerprint = ?
        """,
        [
            offset + 1,
            offset + limit,
            criteria.get("rules_key", ""),
            criteria.get("source_identity_fingerprint") or "",
            criteria.get("host") or "",
            criteria.get("day") or "",
            criteria.get("entity_fingerprint", ""),
        ],
    )
    if not rows:
        return []
    rule_ids = rows[0].get("rule_ids") or []
    if isinstance(rule_ids, str):
        try:
            rule_ids = json.loads(rule_ids)
        except json.JSONDecodeError:
            return []
    return [str(rule_id) for rule_id in rule_ids]
