"""Snapshot persistence is a projection of the real case, not mocked DTOs."""

from forensia.api.cache import (
    clear_api_snapshots,
    load_snapshot,
    write_platform_snapshots,
)
from forensia.api.progress import record_progress_event
from forensia.core.case import Case
from forensia.db.database import CaseDB


def test_platform_snapshots_serialize_empty_case_and_replace_previous_state(tmp_path):
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        write_platform_snapshots(case, db)
        expected = {
            "case",
            "stats",
            "findings",
            "hypotheses",
            "sessions",
            "hypothesis_reasoning",
            "hypotheses_reasoning_latest",
            "session_steps",
            "section_questions",
            "claims",
            "mft_timeline",
            "entities",
            "attack_coverage",
            "ai_reviews",
            "progress_events",
            "evidence_sources",
            "evidence_coverage",
            "report_gaps",
            "investigation_tasks",
            "hypothesis_relations",
            "hypothesis_evidence",
            "snapshot_metadata",
        }
        expected.update(
            f"event_volume_{bucket}_{source}"
            for bucket in ("year", "month", "day", "hour")
            for source in ("all", "detected")
        )
        for name in expected:
            assert load_snapshot(case, f"{name}.json") is not None, name
        assert load_snapshot(case, "findings.json") == []
        assert load_snapshot(case, "hypothesis_reasoning.json") == {}
        assert load_snapshot(case, "stats.json")["active_hypotheses"] == 0
        assert load_snapshot(case, "case.json")["case_name"] == case.path.name
        previous_metadata = load_snapshot(case, "snapshot_metadata.json")
        assert previous_metadata["state"] == "current"

        db.execute(
            "INSERT INTO investigation_sessions (session_id, status) VALUES ('S-1', 'running')"
        )

        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status) VALUES (?, ?, ?)",
            ("H-1", "Verify service installation", "active"),
        )
        record_progress_event(db, {"stage": "investigate", "status": "running"})
        write_platform_snapshots(case, db)
        assert load_snapshot(case, "stats.json")["active_hypotheses"] == 1
        assert (
            load_snapshot(case, "hypotheses.json")["active"][0]["hypothesis_id"]
            == "H-1"
        )
        assert load_snapshot(case, "progress_events.json")[0]["status"] == "running"
        metadata = load_snapshot(case, "snapshot_metadata.json")
        assert metadata["state"] == "in-progress"
        assert (
            metadata["generation_revision"] != previous_metadata["generation_revision"]
        )


def test_clear_snapshots_preserves_nested_and_outside_files(tmp_path):
    case = Case.init(tmp_path)
    snap_dir = case.reports_dir / "api"
    (snap_dir / "nested").mkdir(parents=True)
    for name in ("a.json", "b.json", "c.txt", "nested/keep.json"):
        (snap_dir / name).write_text("{}", encoding="utf-8")
    outside = case.reports_dir / "report.md"
    outside.write_text("Authored report", encoding="utf-8")
    clear_api_snapshots(case)
    assert set(snap_dir.iterdir()) == {snap_dir / "nested"}
    assert (snap_dir / "nested/keep.json").read_text() == "{}"
    assert outside.read_text() == "Authored report"


def test_missing_snapshot_is_unavailable(tmp_path):
    assert load_snapshot(Case.init(tmp_path), "missing.json") is None
