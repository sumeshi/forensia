from __future__ import annotations

import json
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
    list_report_sections_dto,
    list_section_questions_dto,
    list_sessions_dto,
    list_steps_dto,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.report_brief import write_report_brief

VOLATILE_SNAPSHOT_INTERVAL_S = 5.0


def _snapshot_dir(case: Case) -> Path:
    """Return the API snapshot directory (creates if missing)."""
    path = case.reports_dir / "api"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )


def clear_api_snapshots(case: Case) -> None:
    """Remove all cached API snapshot files for this case."""
    snapshot_dir = _snapshot_dir(case)
    for path in snapshot_dir.glob("*"):
        if path.is_file():
            path.unlink()


def write_progress_snapshot(case: Case, db: CaseDB) -> None:
    """Write progress events snapshot to the cache directory."""
    snapshot_dir = _snapshot_dir(case)
    _write_json(
        snapshot_dir / "progress_events.json",
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
        list_report_sections_dto,
        list_section_questions_dto,
    )

    snap_dir = _snapshot_dir(case)
    snap_dir.mkdir(parents=True, exist_ok=True)

    data = {}
    try:
        data["hypotheses"] = list_hypotheses_dto(db).model_dump()
    except Exception:
        pass
    try:
        stats = get_case_stats_dto(db)
        data["stats"] = stats.model_dump()
    except Exception:
        pass
    try:
        findings = list_findings_dto(db, severity="low", limit=500)
        data["findings"] = [f.model_dump() for f in findings]
    except Exception:
        pass
    try:
        data["attack_coverage"] = [a.model_dump() for a in list_attack_coverage_dto(db)]
    except Exception:
        pass
    try:
        data["report_sections"] = [r.model_dump() for r in list_report_sections_dto(db)]
    except Exception:
        pass
    try:
        data["section_questions"] = [
            q.model_dump() for q in list_section_questions_dto(db)
        ]
    except Exception:
        pass
    try:
        data["hypothesis_reasoning"] = {
            hypothesis_id: [entry.model_dump() for entry in entries]
            for hypothesis_id, entries in list_hypothesis_reasoning_map_dto(
                db, limit_per_hypothesis=20
            ).items()
        }
    except Exception:
        pass
    try:
        data["hypotheses_reasoning_latest"] = [
            entry.model_dump()
            for entry in list_latest_hypothesis_reasoning_dto(db, limit=200)
        ]
    except Exception:
        pass
    try:
        data["entities"] = [item.model_dump() for item in list_entity_cards_dto(case)]
    except Exception:
        pass

    for name, payload in data.items():
        _write_json(snap_dir / f"{name}.json", payload)


def write_full_api_snapshots(case: Case, db: CaseDB) -> None:
    """Write all API DTO snapshots (case, stats, findings, hypotheses, sessions, etc.) to the cache directory."""
    snapshot_dir = _snapshot_dir(case)
    _write_json(snapshot_dir / "case.json", get_case_dto(case).model_dump(mode="json"))
    _write_json(
        snapshot_dir / "stats.json", get_case_stats_dto(db).model_dump(mode="json")
    )
    _write_json(
        snapshot_dir / "findings.json",
        [item.model_dump(mode="json") for item in list_findings_dto(db, limit=500)],
    )
    hypotheses = list_hypotheses_dto(db)
    _write_json(snapshot_dir / "hypotheses.json", hypotheses.model_dump(mode="json"))
    sessions = list_sessions_dto(db)
    _write_json(
        snapshot_dir / "sessions.json",
        [item.model_dump(mode="json") for item in sessions],
    )
    hypotheses_reasoning = {
        hypothesis_id: [entry.model_dump(mode="json") for entry in entries]
        for hypothesis_id, entries in list_hypothesis_reasoning_map_dto(
            db, limit_per_hypothesis=20
        ).items()
    }
    _write_json(snapshot_dir / "hypothesis_reasoning.json", hypotheses_reasoning)
    _write_json(
        snapshot_dir / "hypotheses_reasoning_latest.json",
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
    _write_json(snapshot_dir / "session_steps.json", steps_by_session)
    _write_json(
        snapshot_dir / "report_sections.json",
        [item.model_dump(mode="json") for item in list_report_sections_dto(db)],
    )
    _write_json(
        snapshot_dir / "section_questions.json",
        [item.model_dump(mode="json") for item in list_section_questions_dto(db)],
    )
    _write_json(
        snapshot_dir / "claims.json",
        [item.model_dump(mode="json") for item in list_claims_dto(db)],
    )
    _write_json(
        snapshot_dir / "mft_timeline.json",
        [item.model_dump(mode="json") for item in list_mft_timeline_dto(db, limit=500)],
    )
    for bucket in ("year", "month", "day", "hour"):
        for source in ("all", "detected"):
            _write_json(
                snapshot_dir / f"event_volume_{bucket}_{source}.json",
                [
                    item.model_dump(mode="json")
                    for item in list_event_volume_dto(db, bucket=bucket, source=source)
                ],
            )
    _write_json(
        snapshot_dir / "entities.json",
        [item.model_dump(mode="json") for item in list_entity_cards_dto(case)],
    )
    _write_json(
        snapshot_dir / "attack_coverage.json",
        [item.model_dump(mode="json") for item in list_attack_coverage_dto(db)],
    )
    _write_json(
        snapshot_dir / "ai_reviews.json",
        [item.model_dump(mode="json") for item in list_ai_reviews_dto(db)],
    )
    _write_json(snapshot_dir / "report_brief.json", write_report_brief(case, db))


def write_api_snapshots(case: Case, db: CaseDB) -> None:
    """Convenience: write both full API and progress snapshots."""
    write_full_api_snapshots(case, db)
    write_progress_snapshot(case, db)


def load_snapshot(case: Case, name: str) -> Any | None:
    """Load a previously cached API snapshot by filename; returns None if missing."""
    path = _snapshot_dir(case) / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
