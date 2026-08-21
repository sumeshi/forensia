from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensia.api.progress import list_progress_events
from forensia.api.service import (
    get_case_dto,
    get_case_stats_dto,
    list_ai_reviews_dto,
    list_attack_coverage_dto,
    list_claims_dto,
    list_entity_cards_dto,
    list_event_volume_dto,
    list_findings_dto,
    list_hypotheses_dto,
    list_hypothesis_reasoning_map_dto,
    list_latest_hypothesis_reasoning_dto,
    list_mft_timeline_dto,
    list_section_questions_dto,
    list_sessions_dto,
    list_steps_dto,
)
from forensia.api.service_investigation import (
    get_investigation_state_dto,
    list_evidence_coverage_dto,
    list_evidence_sources_dto,
    list_hypothesis_evidence_dto,
    list_hypothesis_relations_dto,
    list_investigation_tasks_dto,
    list_report_gaps_dto,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)

VOLATILE_SNAPSHOT_INTERVAL_S = 5.0


def snapshot_dir(case: Case) -> Path:
    """Return the API snapshot directory (creates if missing)."""
    path = case.reports_dir / "api"
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )


def snapshot_metadata(db: CaseDB) -> dict[str, Any]:
    """Describe the durable state revision represented by a generated snapshot."""
    row = db.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM findings), "
        "(SELECT COUNT(*) FROM hypotheses), "
        "(SELECT COUNT(*) FROM report_sections), "
        "(SELECT COUNT(*) FROM evidence_sources), "
        "(SELECT MAX(updated_at) FROM hypotheses), "
        "(SELECT MAX(last_filled_at) FROM report_sections), "
        "(SELECT MAX(updated_at) FROM investigation_state)"
    ).fetchone()
    state_row = db.execute(
        "SELECT status FROM investigation_state WHERE state_id = 'case'"
    ).fetchone()
    running_row = db.execute(
        "SELECT COUNT(*) FROM investigation_sessions WHERE status = 'running'"
    ).fetchone()
    values = list(row) if isinstance(row, (tuple, list)) else []
    revision = hashlib.sha256(
        json.dumps(values, default=str, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    durable_status = (
        str(state_row[0] or "") if isinstance(state_row, (tuple, list)) else ""
    )
    in_progress = (
        bool(int(running_row[0] or 0))
        if isinstance(running_row, (tuple, list))
        else False
    )
    if durable_status == "active":
        in_progress = True
    updated_values = [str(value) for value in values[4:] if value is not None]
    # Timestamps in the case DB are stored naive UTC. Present them as explicit
    # UTC so the UI never reinterprets them as local time (GOAL.md §7, T-50.7).
    authoritative_updated_at = None
    if updated_values:
        authoritative_updated_at = max(updated_values) + "+00:00"
    return {
        "generation_revision": revision,
        "state_revision": revision,
        "timezone": "UTC",
        "generated_at": datetime.now(UTC).isoformat(),
        "authoritative_updated_at": authoritative_updated_at,
        "state": "in-progress" if in_progress else "current",
        "stale": False,
        "durable_investigation_status": durable_status or "unknown",
    }


def write_snapshot_metadata(case: Case, db: CaseDB) -> None:
    write_json(snapshot_dir(case) / "snapshot_metadata.json", snapshot_metadata(db))


def clear_api_snapshots(case: Case) -> None:
    """Remove all cached API snapshot files for this case."""
    snap_dir = snapshot_dir(case)
    for path in snap_dir.glob("*"):
        if path.is_file():
            path.unlink()


def write_progress_snapshot(case: Case, db: CaseDB) -> None:
    """Write progress events snapshot to the cache directory."""
    snap_dir = snapshot_dir(case)
    write_json(
        snap_dir / "progress_events.json",
        list_progress_events(db, after_index=0, limit=1000),
    )


def write_volatile_api_snapshots(case: Case, db: CaseDB) -> None:
    """Write only the API snapshots that change mid-investigation (skip heavy ones)."""
    from forensia.api.service import (
        get_case_stats_dto,
        list_attack_coverage_dto,
        list_entity_cards_dto,
        list_findings_dto,
        list_hypotheses_dto,
        list_hypothesis_reasoning_map_dto,
        list_latest_hypothesis_reasoning_dto,
        list_section_questions_dto,
    )

    snap_dir = snapshot_dir(case)
    snap_dir.mkdir(parents=True, exist_ok=True)

    data = {}
    try:
        data["hypotheses"] = list_hypotheses_dto(db).model_dump()
    except Exception:
        logger.debug("Failed to build volatile hypotheses snapshot", exc_info=True)
    try:
        stats = get_case_stats_dto(db)
        data["stats"] = stats.model_dump()
    except Exception:
        logger.debug("Failed to build volatile stats snapshot", exc_info=True)
    try:
        findings = list_findings_dto(db, severity="low", limit=500)
        data["findings"] = [f.model_dump() for f in findings]
    except Exception:
        logger.debug("Failed to build volatile findings snapshot", exc_info=True)
    try:
        data["attack_coverage"] = [a.model_dump() for a in list_attack_coverage_dto(db)]
    except Exception:
        logger.debug("Failed to build volatile attack_coverage snapshot", exc_info=True)
    try:
        data["section_questions"] = [
            q.model_dump() for q in list_section_questions_dto(db)
        ]
    except Exception:
        logger.debug(
            "Failed to build volatile section_questions snapshot", exc_info=True
        )
    try:
        data["hypothesis_reasoning"] = {
            hypothesis_id: [entry.model_dump() for entry in entries]
            for hypothesis_id, entries in list_hypothesis_reasoning_map_dto(
                db, limit_per_hypothesis=20
            ).items()
        }
    except Exception:
        logger.debug(
            "Failed to build volatile hypothesis_reasoning snapshot", exc_info=True
        )
    try:
        data["hypotheses_reasoning_latest"] = [
            entry.model_dump()
            for entry in list_latest_hypothesis_reasoning_dto(db, limit=200)
        ]
    except Exception:
        logger.debug(
            "Failed to build volatile hypotheses_reasoning_latest snapshot",
            exc_info=True,
        )
    try:
        data["entities"] = [item.model_dump() for item in list_entity_cards_dto(case)]
    except Exception:
        logger.debug("Failed to build volatile entities snapshot", exc_info=True)

    for name, payload in data.items():
        write_json(snap_dir / f"{name}.json", payload)
    write_snapshot_metadata(case, db)


def write_full_api_snapshots(case: Case, db: CaseDB) -> None:
    """Write all API DTO snapshots (case, stats, findings, hypotheses, sessions, etc.) to the cache directory."""
    snap_dir = snapshot_dir(case)
    write_json(snap_dir / "case.json", get_case_dto(case).model_dump(mode="json"))
    write_json(snap_dir / "stats.json", get_case_stats_dto(db).model_dump(mode="json"))
    write_json(
        snap_dir / "findings.json",
        [item.model_dump(mode="json") for item in list_findings_dto(db, limit=500)],
    )
    hypotheses = list_hypotheses_dto(db)
    write_json(snap_dir / "hypotheses.json", hypotheses.model_dump(mode="json"))
    sessions = list_sessions_dto(db)
    write_json(
        snap_dir / "sessions.json",
        [item.model_dump(mode="json") for item in sessions],
    )
    hypotheses_reasoning = {
        hypothesis_id: [entry.model_dump(mode="json") for entry in entries]
        for hypothesis_id, entries in list_hypothesis_reasoning_map_dto(
            db, limit_per_hypothesis=20
        ).items()
    }
    write_json(snap_dir / "hypothesis_reasoning.json", hypotheses_reasoning)
    write_json(
        snap_dir / "hypotheses_reasoning_latest.json",
        [
            item.model_dump(mode="json")
            for item in list_latest_hypothesis_reasoning_dto(db, limit=200)
        ],
    )
    steps_by_session = {
        session.session_id: [
            item.model_dump(mode="json")
            for item in list_steps_dto(db, session.session_id)
        ]
        for session in sessions
    }
    write_json(snap_dir / "session_steps.json", steps_by_session)
    write_json(
        snap_dir / "section_questions.json",
        [item.model_dump(mode="json") for item in list_section_questions_dto(db)],
    )
    write_json(
        snap_dir / "claims.json",
        [item.model_dump(mode="json") for item in list_claims_dto(db)],
    )
    write_json(
        snap_dir / "mft_timeline.json",
        [item.model_dump(mode="json") for item in list_mft_timeline_dto(db, limit=500)],
    )
    for bucket in ("year", "month", "day", "hour"):
        for source in ("all", "detected"):
            write_json(
                snap_dir / f"event_volume_{bucket}_{source}.json",
                [
                    item.model_dump(mode="json")
                    for item in list_event_volume_dto(db, bucket=bucket, source=source)
                ],
            )
    write_json(
        snap_dir / "entities.json",
        [item.model_dump(mode="json") for item in list_entity_cards_dto(case)],
    )
    write_json(
        snap_dir / "attack_coverage.json",
        [item.model_dump(mode="json") for item in list_attack_coverage_dto(db)],
    )
    write_json(
        snap_dir / "ai_reviews.json",
        [item.model_dump(mode="json") for item in list_ai_reviews_dto(db)],
    )
    try:
        sources = list_evidence_sources_dto(db)
        write_json(
            snap_dir / "evidence_sources.json", [s.model_dump() for s in sources]
        )
    except Exception:
        logger.debug("Failed to write evidence_sources snapshot", exc_info=True)
    try:
        coverage = list_evidence_coverage_dto(db)
        write_json(
            snap_dir / "evidence_coverage.json", [c.model_dump() for c in coverage]
        )
    except Exception:
        logger.debug("Failed to write evidence_coverage snapshot", exc_info=True)
    try:
        inv_state = get_investigation_state_dto(db)
        if inv_state:
            write_json(snap_dir / "investigation_state.json", inv_state.model_dump())
    except Exception:
        logger.debug("Failed to write investigation_state snapshot", exc_info=True)
    try:
        gaps = list_report_gaps_dto(db)
        write_json(snap_dir / "report_gaps.json", [g.model_dump() for g in gaps])
    except Exception:
        logger.debug("Failed to write report_gaps snapshot", exc_info=True)
    try:
        tasks = list_investigation_tasks_dto(db)
        write_json(
            snap_dir / "investigation_tasks.json", [t.model_dump() for t in tasks]
        )
    except Exception:
        logger.debug("Failed to write investigation_tasks snapshot", exc_info=True)
    try:
        relations = list_hypothesis_relations_dto(db)
        write_json(
            snap_dir / "hypothesis_relations.json",
            [item.model_dump() for item in relations],
        )
        links = list_hypothesis_evidence_dto(db)
        write_json(
            snap_dir / "hypothesis_evidence.json",
            [item.model_dump() for item in links],
        )
    except Exception:
        logger.debug("Failed to write hypothesis graph snapshots", exc_info=True)
    write_snapshot_metadata(case, db)


def write_platform_snapshots(case: Case, db: CaseDB) -> None:
    """Convenience: write both full API and progress snapshots."""
    write_full_api_snapshots(case, db)
    write_progress_snapshot(case, db)


def load_snapshot(case: Case, name: str) -> Any | None:
    """Load a previously cached API snapshot by filename; returns None if missing."""
    path = snapshot_dir(case) / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
