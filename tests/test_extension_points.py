"""Minimal contribution contracts for the extension cookbook."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from forensia.evidence import artifacts
from forensia.knowledge import questions
from forensia.knowledge.rules.loader import load_rules_from_dir
from forensia.report.answers import answer_registry, keypoint_catalog, table_registry
from forensia.report.sections import quality_gates
from forensia.report.sections.template_parsing import parse_block_hints, parse_template


def test_artifact_adapter_registration(monkeypatch) -> None:
    class ExampleAdapter:
        name = "example"

        def can_handle(self, path: Path) -> bool:
            return path.suffix == ".example"

    monkeypatch.setattr(
        artifacts,
        "_ARTIFACT_ADAPTER_FACTORIES",
        list(artifacts._ARTIFACT_ADAPTER_FACTORIES),
    )
    artifacts.register_artifact_adapter(ExampleAdapter, prepend=True)
    assert artifacts.get_artifact_adapters()[0].name == "example"


def test_detection_rule_is_discovered_from_yaml(tmp_path: Path) -> None:
    rule = {
        "id": "example-rule",
        "title": "Example rule",
        "query": "SELECT 1 AS evidence_id",
        "finding": {"title": "Example", "summary": "Observed example"},
    }
    (tmp_path / "example.yaml").write_text(json.dumps(rule), encoding="utf-8")
    assert [item.id for item in load_rules_from_dir(tmp_path)] == ["example-rule"]


def test_question_spec_is_discovered_from_yaml(tmp_path: Path, monkeypatch) -> None:
    schema = {
        "question_types": [
            {
                "name": "example_question",
                "answer_spec": "example_question",
                "builder_policy": "generic",
                "evidence_chain": [{"source": "events", "query": "SELECT 1"}],
            }
        ]
    }
    (tmp_path / "question_routing.yaml").write_text(
        json.dumps(schema), encoding="utf-8"
    )
    monkeypatch.setattr(questions, "_schema_dir", lambda: tmp_path)
    questions.load_question_specs.cache_clear()
    try:
        assert questions.question_spec_for_answer_spec("example_question") is not None
    finally:
        questions.load_question_specs.cache_clear()


def test_report_block_discovers_template_and_registered_keypoint(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        keypoint_catalog, "REPORT_KEYPOINTS", dict(keypoint_catalog.REPORT_KEYPOINTS)
    )
    monkeypatch.setattr(
        keypoint_catalog,
        "REPORT_KEYPOINT_ALIASES",
        dict(keypoint_catalog.REPORT_KEYPOINT_ALIASES),
    )

    def resolver(_case, _db):
        return []

    keypoint_catalog.register_report_keypoint(
        "example_keypoint", "Example evidence", resolver, aliases=("example",)
    )
    template = tmp_path / "7_example.md"
    template.write_text(
        "# Example\n\n## Block\n<!-- evidence_keypoints: example -->",
        encoding="utf-8",
    )
    body, _meta = parse_template(str(template))
    hints = parse_block_hints(body)
    assert keypoint_catalog.REPORT_KEYPOINT_ALIASES["example"] == "example_keypoint"
    assert hints["evidence_keypoints"] == ["example"]


def test_table_builder_registration(monkeypatch) -> None:
    monkeypatch.setattr(table_registry, "TABLE_BLOCKS", dict(table_registry.TABLE_BLOCKS))
    table_registry.register_table_block(
        "example_table",
        lambda _db: [{"name": "row"}],
        (("name", "Name"),),
    )
    rendered = table_registry.render_table_block(MagicMock(), "example_table")
    assert rendered is not None and "| Name |" in rendered and "row" in rendered


def test_quality_gate_registration(monkeypatch) -> None:
    monkeypatch.setattr(
        quality_gates, "_QUALITY_CHECKS", list(quality_gates._QUALITY_CHECKS)
    )

    def example_check(_body, _context):
        return "Example extension finding.", 0.2

    quality_gates.register_quality_check(example_check)
    gaps, confidence = quality_gates.quality_gate_section(
        "example",
        "Example",
        "This is an ordinary evidence-backed narrative paragraph " * 3,
        [],
        1.0,
    )
    assert "Example extension finding." in gaps
    assert confidence == 0.2


def test_structured_answer_builder_registration(monkeypatch) -> None:
    monkeypatch.setattr(
        answer_registry,
        "_STRUCTURED_ANSWER_BUILDERS",
        dict(answer_registry._STRUCTURED_ANSWER_BUILDERS),
    )

    def builder(_case, _db, answer_id, section_key, block_heading):
        return {
            "answer_id": answer_id,
            "section_key": section_key,
            "block_heading": block_heading,
            "answer": [],
        }

    answer_registry.register_structured_answer_builder("example-answer", builder)
    assert "example_answer" in answer_registry.structured_answer_builder_names()
