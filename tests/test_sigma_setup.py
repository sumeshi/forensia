"""Acquired and explicit rules remain reproducible, attributable and offline."""

from __future__ import annotations

import hashlib
import html as html_module
import io
import json
import tarfile
from pathlib import Path

import httpx
import pytest
import yaml

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.rules.engine import (
    generate_findings,
    iter_rule_row_batches,
    save_findings,
)
from forensia.knowledge.rules.loader import load_rule_by_id
from forensia.knowledge.sigma import setup
from forensia.knowledge.sigma_bundle import load_sigma_bundle, sigma_bundle_scope
from forensia.pipeline import _pin_case_rules, run_investigation, run_report
from forensia.report.sections.report_input import resolve_report_sources
from forensia.report.sections.section_refresher import async_refresh_report_sections


def _source(
    path: Path, *, rule_id: str = "1f91948f-4ff5-49e3-83cd-3dd553fdcdbb"
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                "title": "Independent log clearing rule",
                "id": rule_id,
                "author": "Independent | Analyst <example> " * 20,
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 1102}, "condition": "selection"},
                "level": "high",
            }
        )
    )
    return path


def test_setup_download_is_pinned_and_reuses_valid_install(tmp_path, monkeypatch):
    upstream = tmp_path / "upstream"
    _source(upstream / "rules/windows/custom.yml")
    (upstream / "LICENSE").write_text("Independent test rules license")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        tar.add(upstream, arcname=f"sigma-{setup.UPSTREAM_REVISION}")
    payload = archive.getvalue()
    installed = tmp_path / "installed/sigma_bundle.json"
    monkeypatch.setattr(setup, "sigma_bundle_path", lambda: installed)
    monkeypatch.setattr(
        "forensia.knowledge.resources.sigma_bundle_path", lambda: installed
    )
    monkeypatch.setattr(
        setup, "UPSTREAM_ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest()
    )
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, content=payload)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        monkeypatch.setattr(setup.httpx, "stream", client.stream)
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        run_investigation(tmp_path / "case", input_dir=str(input_dir))
        assert installed.is_file()
        bundle = load_sigma_bundle(installed)
        assert bundle["source"]["commit"] == setup.UPSTREAM_REVISION
        assert (
            bundle["source"]["licenses"][0]["text"] == "Independent test rules license"
        )
        assert bundle["summary"]["admitted_rules"] == 1
        assert setup.prepare_rule_bundle() == installed
        assert len(requests) == 1
        assert str(requests[0].url) == setup.UPSTREAM_ARCHIVE_URL


def test_failed_download_does_not_install_partial_rules(tmp_path, monkeypatch):
    installed = tmp_path / "installed/sigma_bundle.json"
    monkeypatch.setattr(setup, "sigma_bundle_path", lambda: installed)
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"wrong archive")
        )
    ) as client:
        monkeypatch.setattr(setup.httpx, "stream", client.stream)
        with pytest.raises(ValueError, match="SHA-256"):
            setup.prepare_rule_bundle()
    assert not installed.exists()


def test_custom_rules_and_case_resume_do_not_require_default_install(
    tmp_path, monkeypatch
):
    source = _source(tmp_path / "custom.yml")
    installed = tmp_path / "cache/sigma_bundle.json"
    monkeypatch.setattr(setup, "sigma_bundle_path", lambda: installed)
    # Python and Runtime consumers resolve the same default; it is deliberately absent.
    monkeypatch.setattr(
        "forensia.knowledge.resources.sigma_bundle_path", lambda: installed
    )
    case_dir = tmp_path / "case"
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    run_investigation(case_dir, input_dir=str(input_dir), rules=source)
    with CaseDB(Case.open(case_dir)) as db:
        original = _pin_case_rules(db)
        assert original["source"]["repository"] == source.as_uri()
        assert original["source"]["commit"] is None
        receipt = db.execute(
            "SELECT output_json FROM trace.investigation_steps WHERE phase='pipeline-analyze' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        cache_file = next(installed.parent.glob("*.json"))
        assert (
            json.loads(receipt[0])["sigma_bundle"]["artifact_sha256"]
            == hashlib.sha256(cache_file.read_bytes()).hexdigest()
        )
    source.unlink()
    for cached in installed.parent.glob("*.json"):
        cached.unlink()
    run_investigation(case_dir)
    with CaseDB(Case.open(case_dir)) as db:
        assert _pin_case_rules(db)["build_id"] == original["build_id"]
        assert (
            db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps WHERE phase='sigma-rules'"
            ).fetchone()[0]
            == 1
        )


def test_custom_author_survives_match_persistence_markdown_and_html(
    tmp_path, monkeypatch
):
    import asyncio

    source = _source(tmp_path / "rules/neutral.yml")
    monkeypatch.setattr(
        setup, "sigma_bundle_path", lambda: tmp_path / "cache/sigma_bundle.json"
    )
    bundle = load_sigma_bundle(setup.prepare_rule_bundle(source))
    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db, sigma_bundle_scope(bundle):
        _pin_case_rules(db, bundle)
        rule = load_rule_by_id("sigma-1f91948f-4ff5-49e3-83cd-3dd553fdcdbb-security")
        assert rule is not None
        evidence_id = "evtx-" + "c" * 64 + "-security-000000000001"
        db.execute(
            "INSERT INTO evtx_events (evidence_id,event_id,channel,computer,timestamp,raw_json) VALUES (?,1102,'Security','UNRELATED-HOST','2026-09-03 11:24:00',?)",
            [
                evidence_id,
                json.dumps(
                    {"winlog": {"provider": {"name": "Microsoft-Windows-Eventlog"}}}
                ),
            ],
        )
        findings = [
            finding
            for batch in iter_rule_row_batches(db, rule)
            for finding in generate_findings(rule, batch)
        ]
        assert len(findings) == 1
        author = findings[0].evidence[0]["sigma_author"].strip()
        assert findings[0].evidence[0]["sigma_source"] == source.as_uri()
        save_findings(case, db, findings)
        from forensia.pipeline import pin_investigation_inputs

        pin_investigation_inputs(case, db)
        result = asyncio.run(
            async_refresh_report_sections(
                case=case,
                db=db,
                session_id="attribution",
                iteration=1,
                base_url="",
                model="",
                sections=resolve_report_sources(case, case.report_template_dir),
                progress_callback=None,
                focus_sections=[],
                allow_narration=False,
            )
        )
        assert result["updated_sections"] == 5
        markdown, html = run_report(case.path, db=db)
    assert author.replace("|", r"\|") in markdown.read_text()
    assert html_module.escape(author) in html.read_text()
    assert source.as_uri() in markdown.read_text()
    assert "SigmaHQ contributors" not in markdown.read_text()


def test_rule_lookup_uses_each_case_bundle_without_cross_case_cache(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        setup, "sigma_bundle_path", lambda: tmp_path / "cache/sigma_bundle.json"
    )
    first_id = "18cf98db-e10d-4ad0-bafb-d08a988363b1"
    second_id = "18cf98db-e10d-4ad0-bafb-d08a988363b2"
    first = load_sigma_bundle(
        setup.prepare_rule_bundle(
            _source(tmp_path / "first/rule.yml", rule_id=first_id)
        )
    )
    second = load_sigma_bundle(
        setup.prepare_rule_bundle(
            _source(tmp_path / "second/rule.yml", rule_id=second_id)
        )
    )
    for bundle, present, absent in (
        (first, first_id, second_id),
        (second, second_id, first_id),
        (first, first_id, second_id),
    ):
        with sigma_bundle_scope(bundle):
            assert load_rule_by_id(f"sigma-{present}-security") is not None
            assert load_rule_by_id(f"sigma-{absent}-security") is None


def test_rejected_custom_install_preserves_previous_rules(tmp_path, monkeypatch):
    installed = tmp_path / "cache/sigma_bundle.json"
    monkeypatch.setattr(setup, "sigma_bundle_path", lambda: installed)
    source = _source(tmp_path / "rule.yml")
    assert setup.prepare_rule_bundle(source, install=True) == installed
    original = installed.read_bytes()
    data = yaml.safe_load(source.read_text())
    data["logsource"] = {"product": "linux", "service": "unmapped-service"}
    source.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match="No executable Sigma rules"):
        setup.prepare_rule_bundle(source, install=True)
    assert installed.read_bytes() == original
