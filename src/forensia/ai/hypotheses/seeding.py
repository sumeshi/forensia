"""Session seeding: create initial findings and rule-derived hypotheses from profile rulepacks."""

from __future__ import annotations

import json
import re
from typing import Any

from forensia.ai.hypotheses.hypothesis_manager import merge_active_hypotheses
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.resources import profile_path, rulepacks_dir
from forensia.knowledge.rules.engine import (
    clear_rule_findings,
    generate_findings,
    run_rule,
    save_findings,
)
from forensia.knowledge.rules.loader import (
    _get_pack_map,
    _get_rule_cache,
    load_rules_from_dir,
)
from forensia.report.answers.keypoint_catalog import (
    REPORT_KEYPOINTS,
    _resolve_evidence_results,
)


def seed_findings(
    case: Case, db: CaseDB, profile: str, active_pack_ids: set[str] | None = None
) -> int:
    """Run profile rules and replace rule-derived seed findings on resume."""
    profile_file = profile_path(profile)
    rules_dir = rulepacks_dir()
    if active_pack_ids is not None:
        pack_map = _get_pack_map()
        rules = [
            r
            for r in load_rules_from_dir(rules_dir, profile_file)
            if pack_map.get(r.id) in active_pack_ids
        ]
    else:
        rules = load_rules_from_dir(rules_dir, profile_file)
    total = 0
    for rule in rules:
        clear_rule_findings(case, db, rule.id)
        findings = generate_findings(rule, run_rule(db, rule))
        save_findings(case, db, findings)
        total += len(findings)
    # Tag any findings that are entirely benign local auth (e.g. loopback 4648).
    from forensia.report.benign_auth import tag_benign_local_auth_findings

    tagged = tag_benign_local_auth_findings(db)
    if tagged:
        _log("TAG", f"tagged {tagged} findings as benign-context:loopback-local-auth")
    return total


def _seed_rule_hypotheses(
    db: CaseDB,
    state: SessionState,
    session_id: str,
    active_pack_ids: set[str] | None = None,
) -> None:
    """Seed hypotheses declared in rulepacks into active hypotheses.

    For each rule with hypotheses[] that produced at least one finding,
    renders description placeholders from the first finding's evidence row,
    builds a Hypothesis with source_rule_ids and source_decl_id, and merges
    into active hypotheses via merge_active_hypotheses with origin 'rule'.
    Called once after initial findings are seeded.

    When active_pack_ids is provided, only rules from those packs are considered.
    At most 2 hypotheses are seeded per rule to prevent EVTX rules from crowding
    out file/cloud/email hypotheses.
    """
    rule_cache = _get_rule_cache()
    pack_map = _get_pack_map() if active_pack_ids else {}
    seeded: list[Hypothesis] = []
    for rule in rule_cache.values():
        if not rule.hypotheses:
            continue
        if active_pack_ids and pack_map.get(rule.id) not in active_pack_ids:
            continue

        finding_rows = fetch_records(
            db,
            "SELECT evidence FROM findings WHERE rule_id = ? ORDER BY created_at LIMIT 1",
            (rule.id,),
        )
        if not finding_rows:
            continue
        evidence_json = finding_rows[0].get("evidence")
        evidence_rows: list[dict[str, Any]] = []
        if isinstance(evidence_json, str):
            try:
                evidence_rows = json.loads(evidence_json)
            except json.JSONDecodeError, TypeError:
                evidence_rows = []
        elif isinstance(evidence_json, list):
            evidence_rows = evidence_json
        # Cap at 2 hypotheses per rule
        seeds_from_rule = 0
        for decl in rule.hypotheses:
            if seeds_from_rule >= 2:
                _log(
                    "HYPOTHESIS",
                    f"[seed] cap per rule reached for {rule.id} (max 2), skipping decl {decl.id}",
                )
                break
            rendered_desc = decl.description
            # R2-03: resolve placeholders from evidence rows
            placeholder_keys = re.findall(r"\{(\w+)\}", rendered_desc)
            if placeholder_keys:
                unresolved = []
                for key in placeholder_keys:
                    value = None
                    for row in evidence_rows:
                        v = row.get(key)
                        if v is not None and str(v).strip():
                            value = v
                            break
                    if value is not None:
                        rendered_desc = rendered_desc.replace(
                            "{" + key + "}", str(value)
                        )
                    else:
                        unresolved.append(key)
                if unresolved:
                    has_fallback = bool(getattr(rule, "fallback_search", None))
                    if has_fallback:
                        for key in unresolved:
                            rendered_desc = rendered_desc.replace(
                                "{" + key + "}", f"unknown {key}"
                            )
                        required_entities = [
                            e
                            for e in (list(decl.required_entities or []))
                            if e not in unresolved
                        ]
                        _log(
                            "HYPOTHESIS",
                            f"[seed] unresolved {unresolved} for {rule.id}/{decl.id}, rendered as unknown",
                        )
                    else:
                        _log(
                            "HYPOTHESIS",
                            f"[seed] skipped {rule.id}/{decl.id}: unresolved placeholders {unresolved}",
                        )
                        continue
                else:
                    required_entities = list(decl.required_entities or [])
            else:
                required_entities = list(decl.required_entities or [])
            hyp = Hypothesis(
                id=f"draft-{rule.id}-{decl.id}",
                description=rendered_desc,
                status="active",
                verdict=None,
                summary="",
                source_rule_ids=[rule.id],
                source_decl_id=decl.id,
                required_entities=required_entities,
                confirm_when=dict(decl.confirm_when) if decl.confirm_when else None,
                evidence_requirements=(
                    dict(decl.evidence_requirements)
                    if decl.evidence_requirements
                    else None
                ),
            )
            seeded.append(hyp)
            seeds_from_rule += 1

    if seeded:
        state.active_hypotheses = merge_active_hypotheses(
            db=db,
            current=state.active_hypotheses,
            updates=seeded,
            resolved=state.resolved_hypotheses,
            session_id=session_id,
            origin="rule",
        )
        _log(
            "HYPOTHESIS",
            f"seeded {len(seeded)} rule-declared hypotheses (active={len(state.active_hypotheses)})",
        )
    # G-8: Pre-screen telemetry availability to avoid wasting LLM cycles on
    # hypotheses whose required event IDs are entirely absent from the case.
    prescreen_telemetry_availability(db, state, session_id)


def prescreen_telemetry_availability(
    db: CaseDB,
    state: SessionState,
    session_id: str,
) -> None:
    """Resolve as 'untestable' any active hypothesis whose confirm_when.co_observed_event_ids
    are entirely absent from the case evtx_events table.

    Rules:
    - No confirm_when or no co_observed_event_ids → skip (cannot determine)
    - ALL referenced event IDs missing → resolve as untestable immediately
    - SOME exist → let it proceed (normal investigation)

    This prevents wasting 3+ LLM cycles on hypotheses that will ultimately
    become untestable due to missing telemetry.
    """
    from forensia.ai.hypotheses.hypothesis_manager import resolve_hypothesis

    # Compute the set of event_ids present in the case.
    try:
        rows = db.execute(
            "SELECT DISTINCT event_id FROM evtx_events WHERE event_id IS NOT NULL"
        ).fetchall()
        available_event_ids: set[int] = {int(r[0]) for r in rows}
    except Exception:
        # Table may not exist yet or have no event_id column
        available_event_ids = set()

    screened = 0
    for hyp in list(state.active_hypotheses):
        confirm_when = hyp.confirm_when or {}
        co_observed = confirm_when.get("co_observed_event_ids")
        if not co_observed or not isinstance(co_observed, list):
            continue
        # Coerce to int set
        required_ids: set[int] = set()
        for eid in co_observed:
            try:
                required_ids.add(int(eid))
            except TypeError, ValueError:
                continue
        if not required_ids:
            continue
        # G-8: If ALL required event_ids are missing → untestable
        if not required_ids.intersection(available_event_ids):
            id_list = ", ".join(str(eid) for eid in sorted(required_ids))
            _log(
                "RESOLVE",
                f"{hyp.id} — untestable (pre-screen): required event IDs [{id_list}] "
                f"are not present in the available telemetry",
            )
            resolve_hypothesis(
                db=db,
                state=state,
                hypothesis_id=hyp.id,
                verdict="untestable",
                summary=(
                    f"Untestable: verification requires event IDs [{id_list}] "
                    "which are not present in the available telemetry — "
                    "absence of telemetry is not a disproof."
                ),
                session_id=session_id,
            )
            screened += 1
    if screened:
        _log(
            "HYPOTHESIS",
            f"pre-screened {screened} hypotheses as untestable "
            f"(missing telemetry, active={len(state.active_hypotheses)})",
        )


def _family_interleaved_keypoint_names() -> list[str]:
    """Order keypoint names round-robin across family prefixes (first '_' token).

    Deterministic replacement for shuffling: avoids the alphabetical bias that
    let one family (e.g. account_*) fill every truncated slice, while keeping
    scan order reproducible across runs (investigation paths must be auditable).
    """
    groups: dict[str, list[str]] = {}
    for name in sorted(REPORT_KEYPOINTS.keys()):
        family = name.split("_", 1)[0]
        groups.setdefault(family, []).append(name)
    families = sorted(groups)
    ordered: list[str] = []
    for index in range(max((len(v) for v in groups.values()), default=0)):
        for family in families:
            if index < len(groups[family]):
                ordered.append(groups[family][index])
    return ordered


def _scan_report_keypoints(
    case: Case, db: CaseDB, *, limit: int = 80
) -> list[dict[str, Any]]:
    """Run each report keypoint once and keep only the ones that produced rows."""
    observed: list[dict[str, Any]] = []
    for index, keypoint_name in enumerate(
        _family_interleaved_keypoint_names(), start=1
    ):
        try:
            result = _resolve_evidence_results(case, db, keypoints=[keypoint_name])[0]
        except Exception as exc:
            _log("PIVOT", f"keypoint scan failed for {keypoint_name}: {exc}")
            continue
        row_count = int(result.get("row_count") or 0)
        if row_count <= 0:
            continue
        observed.append(
            {
                "keypoint": keypoint_name,
                "row_count": row_count,
                "description": str(result.get("description") or ""),
                "evidence_ids": list(result.get("evidence_ids") or []),
            }
        )
        if len(observed) >= limit:
            break
    return observed
