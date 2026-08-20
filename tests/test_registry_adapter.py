import json
import sys
from pathlib import Path
from types import ModuleType

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.evidence.registry import (
    _dataset_id,
    _iter_reg2es_records,
    admit_registry_datasets,
    detect_registry_candidate,
    normalize_registry,
    register_registry_dataset,
)
from forensia.knowledge.coverage import refresh_evidence_coverage


def test_registry_detection_requires_regf_and_keeps_logs_as_companions(
    tmp_path: Path,
) -> None:
    primary = tmp_path / "SYSTEM"
    primary.write_bytes(b"regf" + b"\0" * 8)
    log = tmp_path / "SYSTEM.LOG1"
    log.write_bytes(b"transaction")
    not_hive = tmp_path / "SOFTWARE"
    not_hive.write_bytes(b"text")

    assert detect_registry_candidate(primary).kind == "primary"
    assert detect_registry_candidate(not_hive) is None
    datasets = admit_registry_datasets([primary, log])
    assert len(datasets) == 1
    assert [item.kind for item in datasets[0].members] == ["primary", "transaction_log"]
    orphan = tmp_path / "ORPHAN.LOG1"
    orphan.write_bytes(b"transaction")
    assert admit_registry_datasets([orphan]) == ()
    unrelated = tmp_path / "SYSTEMATIC.LOG1"
    unrelated.write_bytes(b"transaction")
    assert len(admit_registry_datasets([primary, unrelated])[0].members) == 1


def test_same_directory_does_not_merge_unattributed_hives(tmp_path: Path) -> None:
    first = tmp_path / "SYSTEM"
    second = tmp_path / "SOFTWARE"
    first.write_bytes(b"regf")
    second.write_bytes(b"regf")

    datasets = admit_registry_datasets([first, second])
    assert len(datasets) == 2


def test_explicit_identity_can_join_hives(tmp_path: Path) -> None:
    first = tmp_path / "SYSTEM"
    second = tmp_path / "SOFTWARE"
    first.write_bytes(b"regf")
    second.write_bytes(b"regf")

    datasets = admit_registry_datasets(
        [first, second], identities={first: "host-a/acq-1", second: "host-a/acq-1"}
    )
    assert len(datasets) == 1
    assert len(datasets[0].members) == 2


def test_reg2es_chunk_generator_is_flattened_and_closed(
    monkeypatch, tmp_path: Path
) -> None:
    closed = []

    class FakeReg2es:
        def __init__(self, **kwargs):
            assert kwargs["error_policy"] == "raise"
            assert kwargs["input_paths"] == [str(tmp_path / "SYSTEM")]

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            closed.append(True)

        def gen_records(self):
            yield [{"id": 1}, {"id": 2}]
            yield [{"id": 3}]

    reg2es_module = ModuleType("reg2es")
    models_module = ModuleType("reg2es.models")
    model_module = ModuleType("reg2es.models.Reg2es")
    model_module.Reg2es = FakeReg2es
    monkeypatch.setitem(sys.modules, "reg2es", reg2es_module)
    monkeypatch.setitem(sys.modules, "reg2es.models", models_module)
    monkeypatch.setitem(sys.modules, "reg2es.models.Reg2es", model_module)

    assert list(_iter_reg2es_records([tmp_path / "SYSTEM"])) == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]
    assert closed == [True]


def test_registry_raw_records_and_parser_timestamps_are_traceable(
    tmp_path: Path,
) -> None:
    case = Case.init(tmp_path / "case")
    primary = tmp_path / "SYSTEM"
    primary.write_bytes(b"regf")
    raw = case.raw_dir / "registry-test.jsonl"
    record = (
        '{"@timestamp":"2020-01-02T03:04:05+00:00",'
        '"event":{"action":"services"},"registry":{"hive":"HKLM",'
        '"path":"HKLM\\\\SYSTEM\\\\x","value":"ImagePath"},'
        '"log":{"file":{"path":"/collection/one/SYSTEM"}},'
        '"reg2es":{"plugin":{"name":"services"},"source":'
        '{"hive":"SYSTEM","key_path":"x"}}}\n'
    )
    raw.write_text(record + record, encoding="utf-8")
    dataset = admit_registry_datasets([primary])[0]
    source_id = "a" * 64
    with CaseDB(case) as db:
        register_evidence_source(
            db,
            source_id=source_id,
            artifact_family="registry",
            display_path=primary.name,
            ingest_status="parsed",
            parser_name="reg2es",
            parser_version="2.0.0",
        )
        register_registry_dataset(
            db,
            dataset,
            source_ids={primary: source_id},
            raw_path=raw,
        )
        assert normalize_registry(case, db) == 2
        refresh_evidence_coverage(db)
        artifact = db.execute(
            "SELECT dataset_id, source_ids, raw_json FROM registry_artifacts"
        ).fetchone()
        assert db.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone()[0] == 2
        first_ids = {
            row[0]
            for row in db.execute(
                "SELECT artifact_id FROM registry_artifacts ORDER BY artifact_id"
            ).fetchall()
        }
        moved_record = record.replace("/collection/one/SYSTEM", "/other/two/SYSTEM")
        raw.write_text(moved_record + moved_record, encoding="utf-8")
        assert normalize_registry(case, db) == 2
        second_ids = {
            row[0]
            for row in db.execute(
                "SELECT artifact_id FROM registry_artifacts ORDER BY artifact_id"
            ).fetchall()
        }
        assert first_ids == second_ids
        timeline = db.execute(
            "SELECT artifact_id, timestamp, timestamp_kind FROM registry_timeline"
        ).fetchone()
        coverage = db.execute(
            "SELECT state, reason_code FROM evidence_coverage "
            "WHERE source_family = 'registry'"
        ).fetchone()
        raw.write_text(moved_record + "not-json\n", encoding="utf-8")
        assert normalize_registry(case, db) == 0
        assert db.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone()[0] == 2
        assert db.execute(
            "SELECT ingest_status, error_code FROM registry_datasets"
        ).fetchone() == ("partial", "raw_malformed")
    assert json.loads(artifact[1]) == [source_id]
    assert '"event"' in artifact[2]
    assert timeline[0].startswith("registry-")
    assert str(timeline[2]) == "parser:@timestamp"
    assert coverage == ("partial", "parser_plugin_completeness_unproven")
    other_primary = tmp_path / "other" / "SYSTEM"
    other_primary.parent.mkdir()
    other_primary.write_bytes(b"regf")
    other_dataset = admit_registry_datasets([other_primary])[0]
    assert _dataset_id(dataset, {primary: source_id}) == _dataset_id(
        other_dataset, {other_primary: source_id}
    )
