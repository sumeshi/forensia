"""Kernel entry boundary (V2-02) and the FORENSIA.md policy input seam (V2-05).

The display-agnostic pipeline entry is shared by Runtime and Python callers.
Importing it must not require a terminal presentation
library or an HTTP server: those belong to the display adapters.

The V2-05 tests drive the real pipeline entry (and the real CLI adapter)
over a disposable case with the LLM boundary stubbed offline. They verify
that a case-root ``FORENSIA.md`` is adopted, recorded, and routed only to
the investigation roles, that an oversized policy refuses with a reason,
and that no gate-phase prompt carries the policy.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import pytest

FORBIDDEN = ("typer", "click", "rich", "fastapi", "uvicorn")

# Investigation roles that may receive adopted policy text (V2-05). Every
# other captured role — checker, evidence, report narration — must be
# policy-free: the Evidence/settlement gates are not instruction-driven.
_POLICY_ROLES = ("plan-broad-gap", "plan-broad-draft", "hypothesis-plan")
_POLICY_BUDGET_SMALL = 100


def test_pipeline_import_requires_no_terminal_or_http_server_dependencies() -> None:
    script = (
        "import sys; import forensia.pipeline; "
        "loaded = sorted({name for name in sys.modules "
        "for dep in ('typer', 'click', 'rich', 'fastapi', 'uvicorn') "
        "if name == dep or name.startswith(dep + '.')}); "
        "print(loaded, file=sys.stderr); assert not loaded, loaded"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr


def test_missing_manifest_does_not_initialize_over_existing_case_database() -> None:
    from forensia.pipeline import UsageError, _open_or_init_case

    with tempfile.TemporaryDirectory() as tmpdir:
        case_dir = Path(tmpdir) / "case"
        db_dir = case_dir / "db"
        db_dir.mkdir(parents=True)
        database = db_dir / "case.duckdb"
        original = b"preserve existing database"
        database.write_bytes(original)

        try:
            _open_or_init_case(case_dir, str(case_dir / "input"), "UTC", None)
        except UsageError as exc:
            assert "manifest is missing" in str(exc)
        else:
            raise AssertionError("existing database without manifest was initialized")

        assert database.read_bytes() == original
        assert not (case_dir / "manifest.yaml").exists()


def test_direct_python_stop_request_and_signal_handler_restore(tmp_path) -> None:
    import signal

    from forensia.core.control import InvestigationStopped, check_stop, stop_scope
    from forensia.pipeline import _execution_entry

    original = signal.getsignal(signal.SIGINT)

    @_execution_entry
    def interrupted(case_dir, *, stop_requested, max_llm_calls):
        from forensia.config import get_settings

        assert get_settings().max_llm_calls == max_llm_calls
        with stop_scope(stop_requested):
            signal.raise_signal(signal.SIGINT)
            check_stop()

    with pytest.raises(InvestigationStopped):
        interrupted(tmp_path / "case", max_llm_calls=7)
    assert signal.getsignal(signal.SIGINT) is original


def test_loop_stops_when_operator_requests_stop_during_report(tmp_path) -> None:
    import asyncio
    from threading import Event
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch

    import forensia.investigation.investigator as investigator
    from forensia.core.control import stop_scope

    stop = Event()
    env = SimpleNamespace(
        max_iter=1,
        report_only=True,
        state=SimpleNamespace(
            iteration=0, active_hypotheses=[], resolved_hypotheses=[]
        ),
        ctx=SimpleNamespace(interrupted=False),
        db=None,
        case=None,
        session_id="session-stop",
        base_url="",
        model="",
        progress_callback=None,
        max_queries_per_hypothesis=1,
        case_profile=None,
        report_every_n_cycles=1,
        report_sections=[],
        no_progress_limit=1,
    )

    async def report_phase(**_kwargs):
        stop.set()
        return {}, "ok"

    with (
        patch.object(investigator, "evaluation_snapshot", return_value={}),
        patch.object(
            investigator, "_run_cycle_body", new=AsyncMock(return_value=(True, []))
        ),
        patch.object(investigator, "_run_report_phase", side_effect=report_phase),
        stop_scope(stop),
    ):
        result = asyncio.run(investigator._run_investigation_loop(env))

    assert result == ("stopped", 0, "interrupted")


def test_python_entry_pins_markdown_before_evidence_work(tmp_path, monkeypatch) -> None:
    import forensia.pipeline as pipeline
    from forensia.investigation.case_policy import load_recorded_policy
    from forensia.report.sections.report_input import decide_report_sources

    inputs = tmp_path / "input"
    inputs.mkdir()
    policy = tmp_path / "FORENSIA.md"
    policy.write_text("# Objective\n\nPreserve this objective.", encoding="utf-8")
    report = tmp_path / "REPORT.md"
    report.write_text("# Original section\n\nPreserve this question.", encoding="utf-8")

    def evidence_work(*_args):
        policy.unlink()
        report.unlink()

    def investigate(case, db, _base_url, _model, root, *_args, **kwargs):
        assert kwargs["manual_resume"] is True
        assert kwargs["forensia_policy"].body.endswith("Preserve this objective.")
        assert load_recorded_policy(db)["body"].endswith("Preserve this objective.")
        decision = decide_report_sources(case, db, root, kwargs["report_spec"])
        assert decision.sections[0].section_key == "01_original_section"
        assert "Preserve this question." in decision.sections[0].body

    monkeypatch.setattr(pipeline, "_run_evidence_stages", evidence_work)
    monkeypatch.setattr(pipeline, "_run_investigate_stage", investigate)
    output = pipeline.run_investigation(
        tmp_path / "case",
        input_dir=str(inputs),
        llm_base_url="http://127.0.0.1:1",
        model="fixed-model",
        forensia_md=policy,
        report_spec=report,
        manual_resume=True,
    )
    assert output.is_file()


@pytest.mark.parametrize(
    "proposal_case", ["accepted", "invalid_entity", "typed_primary"]
)
def test_public_run_records_provider_planned_query_or_bounded_rejection(
    tmp_path, monkeypatch, proposal_case
) -> None:
    import httpx

    import forensia.llm.llm_client as llm_client
    from forensia.core.evidence import make_prefetch_evidence_id
    from forensia.pipeline import run_investigation

    prefetch_source = "b" * 64
    prefetch_evidence_id = make_prefetch_evidence_id(
        prefetch_source, "Sample.exe", "12345678"
    )

    class Provider:
        def __init__(self) -> None:
            self.schemas: list[str] = []
            self.requests: list[dict] = []
            self.rejected_modes: list[str] = []
            self.query_actions: list[dict] = []

        def post(self, url, json, headers):
            self.requests.append(json)
            schema = (
                json.get("response_format", {}).get("json_schema", {}).get("schema", {})
            )
            title = str(schema.get("title") or "")
            if not title:
                prompt = "\n".join(
                    str(message.get("content") or "")
                    for message in json.get("messages", [])
                )
                roles = (
                    ("GapIdentifier", "You are a gap_identifier"),
                    ("HypothesisDrafter", "You are a hypothesis_drafter"),
                    ("QueryIntentResponse", "Return exactly one action as JSON"),
                    ("VerdictReview", "You are a verdict_reviewer"),
                    ("FindingExtractor", "You are a finding_extractor"),
                    ("ParagraphNarrate", "You are a section_narrator"),
                )
                title = next((name for name, marker in roles if marker in prompt), "")
            self.schemas.append(title)
            if title not in {
                "GapIdentifier",
                "HypothesisDrafter",
                "QueryIntentResponse",
                "VerdictReview",
                "FindingExtractor",
                "ParagraphNarrate",
            }:
                raise AssertionError(f"unexpected provider schema: {title}")
            prompt = "\n".join(
                str(message.get("content") or "")
                for message in json.get("messages", [])
            )
            if json.get("response_format"):
                mode = (
                    "strict"
                    if json["response_format"].get("json_schema", {}).get("strict")
                    else "compatible"
                )
                self.rejected_modes.append(mode)
                request = httpx.Request("POST", url)
                return httpx.Response(
                    400,
                    json={"error": {"message": "response_format unsupported"}},
                    request=request,
                )
            responses = {
                "GapIdentifier": {"gap_areas": []},
                "HypothesisDrafter": {
                    "hypothesis": {
                        "description": (
                            'At least 1 prefetch observation has executable_name equals "sample.exe".'
                            if proposal_case == "typed_primary"
                            else "A new service named Updater was installed on host-01."
                        ),
                        "required_entities": (
                            ["not_a_column"]
                            if proposal_case == "invalid_entity"
                            else (
                                ["executable_name"]
                                if proposal_case == "typed_primary"
                                else ["computer", "service_name"]
                            )
                        ),
                        "source_rule_ids": [
                            "seed-prefetch-rule"
                            if proposal_case == "typed_primary"
                            else "seed-service-rule"
                        ],
                        "confirm_when": (
                            {
                                "observation": {
                                    "family": "prefetch",
                                    "capability": "process_execution",
                                    "field": "executable_name",
                                    "operator": "equals",
                                    "value": "sample.exe",
                                }
                            }
                            if proposal_case == "typed_primary"
                            else {
                                "co_observed_event_ids": [4697],
                                "event_contexts": [
                                    {
                                        "event_id": 4697,
                                        "channel": "Security",
                                        "provider": "Microsoft-Windows-Security-Auditing",
                                    }
                                ],
                            }
                        ),
                    }
                },
                "QueryIntentResponse": {
                    "action": {
                        "intent": "Inspect observed service installation on host-01",
                        "target_table": "evtx_events",
                        "template_id": "q_service_or_task_after_host_logon",
                        "params": {"computer": "host-01", "hours": 24},
                        "sql": "",
                    }
                },
                "VerdictReview": {
                    "verdict": "confirmed",
                    "rationale": "The observed service installation matches the declared event condition.",
                    "missing_questions": [],
                    "confidence": 0.9,
                },
                "FindingExtractor": {"findings": []},
                "ParagraphNarrate": {
                    "body": "The evidence records a service installation on host-01 and supports the bounded event claim."
                },
            }
            payload = responses.get(title, {})
            if title == "HypothesisDrafter" and proposal_case == "typed_primary":
                payload["hypothesis"].pop("description")
            if title == "QueryIntentResponse":
                self.query_actions.append(payload["action"])
            request = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {"content": json_module.dumps(payload)},
                            "finish_reason": "stop",
                        }
                    ]
                },
                request=request,
            )

    import json as json_module

    provider = Provider()
    monkeypatch.setattr(llm_client, "_get_http_client", lambda: provider)
    case_dir = tmp_path / "case"
    input_dir = tmp_path / "input"
    input_dir.mkdir()

    def seed_observation(_case, db):
        if proposal_case == "typed_primary":
            db.execute(
                "INSERT INTO prefetch_executions (evidence_id, source_file, "
                "executable_name, exec_count, last_exec_time) VALUES "
                "(?, ?, 'Sample.exe', 1, '2026-01-01T00:00:00')",
                [prefetch_evidence_id, prefetch_source],
            )
            db.execute(
                "INSERT INTO evidence_sources (source_id, artifact_family, "
                "display_path, ingest_status, parser_name, parser_version, row_count) "
                "VALUES (?, 'prefetch', 'sample.pf', 'normalized', 'prefetch', 'test', 1)",
                [prefetch_source],
            )
            db.execute(
                "INSERT INTO findings (finding_id, rule_id, title, summary, severity, "
                "confidence, status, evidence) VALUES ('F-prefetch-seed', "
                "'seed-prefetch-rule', 'Prefetch execution', 'sample.exe observed', "
                "'medium', 0.8, 'accepted', ?)",
                [json_module.dumps([{"evidence_id": prefetch_evidence_id}])],
            )
            return
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, "
            "event_id, channel, service_name, command_line, raw_json) VALUES "
            "('evtx-service-event-1', 'seed-service-source', 'host-01', "
            "'2026-01-01T00:00:00', 4697, 'Security', "
            '\'Updater\', \'updater.exe\', \'{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}\')'
        )
        db.execute(
            "INSERT INTO evidence_sources (source_id, artifact_family, display_path, "
            "ingest_status, parser_name, parser_version, row_count) VALUES "
            "('seed-service-source', 'evtx', 'seeded.evtx', 'normalized', 'evtx', 'test', 1)"
        )
        db.execute(
            "INSERT INTO findings (finding_id, rule_id, title, summary, severity, "
            "confidence, status, evidence) VALUES ('F-service-seed', 'seed-service-rule', "
            "'Observed service installation', 'Service installation on host-01', "
            "'medium', 0.8, 'accepted', ?)",
            [json_module.dumps([{"evidence_id": "evtx-service-event-1"}])],
        )

    report = run_investigation(
        case_dir,
        input_dir=str(input_dir),
        llm_base_url=f"http://{proposal_case}.provider.test",
        model="controlled-provider",
        max_iter=1,
        max_llm_calls=12,
        pre_investigation=seed_observation,
    )
    assert provider.rejected_modes[:2] == ["strict", "compatible"]
    assert any(not request.get("response_format") for request in provider.requests)
    assert report.is_file()
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.investigation.work_state import broad_plan_terminal_facts

    with CaseDB(Case.open(case_dir), read_only=True) as db:
        do_outputs = db.execute(
            "SELECT output_json FROM trace.investigation_steps WHERE phase = 'do' "
            "ORDER BY created_at"
        ).fetchall()
        session_id = db.execute(
            "SELECT session_id FROM trace.investigation_sessions ORDER BY started_at DESC LIMIT 1"
        ).fetchone()[0]
        if proposal_case == "invalid_entity":
            facts = broad_plan_terminal_facts(db, session_id)
            candidate_attempts = db.execute(
                "SELECT output_json FROM trace.investigation_steps "
                "WHERE phase = 'plan-broad-candidate'"
            ).fetchall()
            assert "QueryIntentResponse" not in provider.schemas
            assert [
                title for title in provider.schemas if title == "HypothesisDrafter"
            ] == [
                "HypothesisDrafter",
                "HypothesisDrafter",
            ]
            assert facts["awaiting_proposal_correction"]
            assert any(
                json_module.loads(row[0]).get("status") == "feasibility_rejected"
                for row in candidate_attempts
            )
            correction_request = [
                request
                for title, request in zip(provider.schemas, provider.requests)
                if title == "HypothesisDrafter"
            ][1]
            self_feedback = "\n".join(
                str(message.get("content"))
                for message in correction_request["messages"]
            )
            assert "required_entity_unobservable" in self_feedback
            assert (
                json_module.loads(candidate_attempts[0][0])["correction_calls_used"]
                == 1
            )
        else:
            check = db.execute(
                "SELECT output_json FROM trace.investigation_steps WHERE phase = 'check' "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            settlement = db.execute(
                "SELECT status, reason FROM trace.progress_events "
                "WHERE kind = 'investigation.settlement' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            final_hypothesis = db.execute(
                "SELECT status FROM hypotheses ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            receipts = [
                json_module.loads(row[0]).get("tool_receipt") for row in do_outputs
            ]
            assert any(receipt and receipt.get("receipt_id") for receipt in receipts)
            assert check and json_module.loads(check[0])["assessment"]["assessment_id"]
            if proposal_case == "typed_primary":
                assert "VerdictReview" not in provider.schemas
                assert "QueryIntentResponse" not in provider.schemas
                assert "FindingExtractor" not in provider.schemas
                assert len(receipts) == 1
                assert receipts[0]["result_refs"]["evidence_ids"] == [
                    prefetch_evidence_id
                ]
                assert final_hypothesis == ("confirmed",)
                saved = db.execute(
                    "SELECT description, sufficiency_status, verification_spec FROM hypotheses"
                ).fetchone()
                observation = json_module.loads(saved[2])["support_conditions"][
                    "observation"
                ]
                assert observation["evidence_ids"] == [prefetch_evidence_id]
                assert prefetch_evidence_id in saved[0]
                assert saved[1] == "sufficient"
                markdown = (case_dir / "reports/report.md").read_text()
                assert saved[0] in markdown
                assert prefetch_evidence_id in markdown
                validation = json_module.loads(
                    (case_dir / "reports/report_validation.json").read_text()
                )
                assert validation["fatal_errors"] == []
                from forensia.report.report_validation import derive_publication_state

                assert (
                    derive_publication_state(db)["claim_scope"]
                    == "confirmed_observations"
                )
            else:
                assert "QueryIntentResponse" in provider.schemas
                assert settlement and settlement[0] == "completed" and settlement[1]
                assert final_hypothesis == ("confirmed",)


def test_mft_only_resume_uses_normalization_receipt_and_parser_revision() -> None:
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.pipeline import _run_normalize_stage, _sources_normalized

    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        calls: list[object] = []
        normalized = {
            "evtx_rows": 0,
            "mft_entries": 4,
            "mft_timeline_rows": 2,
            "prefetch_executions": 0,
            "prefetch_timeline": 0,
            "registry_artifacts": 0,
        }
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO evidence_sources "
                "(source_id, artifact_family, display_path, ingest_status, "
                "parser_name, parser_version, row_count) "
                "VALUES ('mft-source', 'mft', 'disk.mft', 'normalized', 'mft', '1', 4)"
            )
            db.execute(
                "INSERT INTO ingested_files(sha256, path, source_kind, size, ingested_at) "
                "VALUES ('mft-source', 'disk.mft', 'mft', 128, current_timestamp)"
            )
            push = mock.Mock()

            def normalize(*args, **kwargs):
                calls.append(kwargs.get("source_keys"))
                return normalized

            with mock.patch("forensia.pipeline.normalize_all", side_effect=normalize):
                _run_normalize_stage(
                    case, db, False, {"new_files": 1}, push, None, "test-run"
                )
                _run_normalize_stage(
                    case, db, False, {"new_files": 0}, push, None, "test-run"
                )
                assert len(calls) == 1, calls
                db.execute(
                    "DELETE FROM evidence_sources WHERE source_id = 'mft-source'"
                )
                assert not _sources_normalized(db), (
                    "An ingested source without status cannot be current"
                )
                db.execute(
                    "INSERT INTO evidence_sources (source_id, artifact_family, ingest_status) VALUES ('mft-source', 'mft', 'normalized')"
                )

                with mock.patch(
                    "forensia.pipeline._parser_revision", return_value="new-parser"
                ):
                    _run_normalize_stage(
                        case, db, False, {"new_files": 0}, push, None, "test-run"
                    )
                assert len(calls) == 2, calls
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, display_path, ingest_status, "
                    "parser_name, parser_version, row_count) "
                    "VALUES ('new-mft-source', 'mft', 'other.mft', 'ingested', 'mft', '1', 0)"
                )
                db.execute(
                    "INSERT INTO ingested_files(sha256, path, source_kind, size, ingested_at) "
                    "VALUES ('new-mft-source', 'other.mft', 'mft', 64, current_timestamp)"
                )
                with mock.patch(
                    "forensia.pipeline._parser_revision", return_value="newer-parser"
                ):
                    _run_normalize_stage(
                        case,
                        db,
                        False,
                        {"new_files": 1, "new_source_keys": ["new-mft-source"]},
                        push,
                        None,
                        "test-run",
                    )
                assert len(calls) == 3 and calls[-1] is None, calls


def test_run_add_invalidates_then_renders_standard_report_exports(
    tmp_path, monkeypatch
):
    import forensia.pipeline as pipeline
    from forensia.core.case import Case
    from forensia.db.database import CaseDB

    case = Case.init(tmp_path / "case")
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (case.path / "REPORT.md").write_text("original input", encoding="utf-8")
    (case.path / "FORENSIA.md").write_text("original policy", encoding="utf-8")
    custom_export = case.reports_dir / "custom.html"
    custom_export.write_text("user export", encoding="utf-8")
    standard = (
        case.reports_dir / "report.md",
        case.reports_dir / "report.html",
        case.reports_dir / "report_validation.json",
    )
    for path in standard:
        path.write_text("old report", encoding="utf-8")

    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.investigation_steps "
            "(step_id, phase, output_json, created_at) VALUES "
            "('report-input', 'report-input', ?, now())",
            [
                json.dumps(
                    {
                        "sections": [
                            {"section_key": "current-section"},
                            {"section_key": "stale-section"},
                        ]
                    }
                )
            ],
        )
        db.execute(
            "INSERT INTO report_sections "
            "(section_key, title, body, status, update_count, stale) VALUES "
            "('current-section', 'Current', '# Current evidence\\n\\nVerified current source.', 'draft', 1, false), "
            "('stale-section', 'Stale', '# Old source\\n\\nSTALE-SOURCE-SENTINEL', 'draft', 1, false)"
        )

        def invalidate(_case, _db, *_args):
            assert all(not path.exists() for path in standard)
            _db.execute(
                "UPDATE report_sections SET stale = true "
                "WHERE section_key = 'stale-section'"
            )

        monkeypatch.setattr(pipeline, "_run_evidence_stages", invalidate)
        pipeline.run_add(case.path, input_dir, db=db)

        markdown = standard[0].read_text(encoding="utf-8")
        html = standard[1].read_text(encoding="utf-8")
        validation = json.loads(standard[2].read_text(encoding="utf-8"))
        assert db.execute(
            "SELECT body, stale FROM report_sections WHERE section_key = 'stale-section'"
        ).fetchone() == ("# Old source\\n\\nSTALE-SOURCE-SENTINEL", True)

        standard[0].unlink()
        from forensia.report.render.html import render_html_report

        render_html_report(case, db)
        html_without_markdown = standard[1].read_text(encoding="utf-8")

    assert "Verified current source." in markdown
    assert "STALE-SOURCE-SENTINEL" not in markdown
    assert "stale-section" in markdown
    assert "Verified current source." in html
    assert "STALE-SOURCE-SENTINEL" not in html
    assert "stale-section" in html
    assert "STALE-SOURCE-SENTINEL" not in html_without_markdown
    assert "stale-section" in html_without_markdown
    assert validation["publication_status"] == "needs_review"
    assert "stale-section" in validation["publication_state"]["stale_section_keys"]
    assert custom_export.read_text(encoding="utf-8") == "user export"
    assert (case.path / "REPORT.md").read_text(encoding="utf-8") == "original input"
    assert (case.path / "FORENSIA.md").read_text(encoding="utf-8") == "original policy"


def test_run_add_render_failure_does_not_leave_old_standard_exports(
    tmp_path, monkeypatch
):
    import forensia.pipeline as pipeline
    from forensia.core.case import Case
    from forensia.db.database import CaseDB

    case = Case.init(tmp_path / "case")
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    standard = (
        case.reports_dir / "report.md",
        case.reports_dir / "report.html",
        case.reports_dir / "report_validation.json",
    )
    for path in standard:
        path.write_text("old report", encoding="utf-8")

    def invalidate(*_args):
        return None

    def fail_render(*_args, **_kwargs):
        raise RuntimeError("render failed")

    monkeypatch.setattr(pipeline, "_run_evidence_stages", invalidate)
    monkeypatch.setattr(pipeline, "_run_report_stage", fail_render)
    with CaseDB(case) as db, pytest.raises(RuntimeError, match="render failed"):
        pipeline.run_add(case.path, input_dir, db=db)

    assert all(not path.exists() for path in standard)


def test_resume_stop_after_raw_normalization_preserves_findings(tmp_path, monkeypatch):
    from threading import Event

    import forensia.pipeline as pipeline
    from forensia.core.case import Case
    from forensia.core.control import InvestigationStopped
    from forensia.db.database import CaseDB

    case = Case.init(tmp_path / "case")
    (case.raw_dir / "pending.jsonl").write_text("{}\n", encoding="utf-8")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO findings (finding_id, rule_id) VALUES ('retained', 'old-rule')"
        )
    stop = Event()

    def normalize(*_args):
        stop.set()
        return True

    monkeypatch.setattr(pipeline, "_run_normalize_stage", normalize)
    with pytest.raises(InvestigationStopped):
        pipeline.run_investigation(case.path, stop_requested=stop)
    with CaseDB(case, read_only=True) as db:
        assert db.execute("SELECT finding_id FROM findings").fetchall() == [
            ("retained",)
        ]


def _stub_llm(captured: list[tuple[str, str]]):
    """Deterministic offline LLM boundary that records every prompt it sees.

    The gap_identifier picks an existing REPORT_KEYPOINTS id so the drafter
    really runs; the drafter returns nothing the host can parse, so the loop
    stays bounded and offline while both plan prompts get captured. Other
    roles short-circuit like the offline harness used for V2-02.
    """

    def router(**kwargs):
        phase = kwargs.get("telemetry_phase", "")
        system_content = str(kwargs["messages"][0].get("content", ""))
        if not phase:
            phase = "other"
        captured.append((phase, system_content))
        if "gap_identifier" in system_content:
            return {
                "gap_areas": [
                    {
                        "keypoint_id": "host_execution_activity",
                        "why_uncovered": "no active hypothesis targets the execution keypoint",
                        "required_entities": ["computer", "process_name"],
                    }
                ]
            }
        return {}

    return (
        mock.patch("forensia.llm.json_response.request_llm_json", side_effect=router),
    )


POLICY_BODY = """# Investigation Objective
- Determine which host executed the suspect archive

# Scope
- MFT + prefetch only, no network telemetry in scope

# Constraints
- Never treat hash collisions as identity

Guidance line GUIDANCE-SENTINEL-495a: count prefetch browser artifacts first.
"""


def test_case_root_forensia_md_is_adopted_recorded_and_routed_to_investigation_roles() -> (
    None
):
    """V2-05 real CLI path with a normalized match: adoption and prompt routing."""
    from forensia import pipeline as pipeline_module
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.investigation import case_policy as case_policy_module

    captured: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        case_dir = Path(tmpdir) / "case"
        input_dir = case_dir / "input"
        input_dir.mkdir(parents=True)
        (case_dir / "FORENSIA.md").write_text(POLICY_BODY, encoding="utf-8")
        case = Case.init(case_dir)
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO evtx_events (evidence_id, source_file, computer, "
                "timestamp, target_user, event_id) VALUES "
                "('evtx-policy-match', 'seeded-normalized-source', 'host-01', "
                "'2026-01-01T00:00:00', 'analyst', 4624)"
            )
            db.execute(
                "INSERT INTO evidence_sources (source_id, artifact_family, "
                "display_path, ingest_status, parser_name, parser_version, row_count) "
                "VALUES ('seeded-normalized-source', 'evtx', 'seeded.evtx', "
                "'normalized', 'evtx', 'test-fixture', 1)"
            )
            db.execute(
                "INSERT INTO findings (finding_id, rule_id, title, summary, severity, "
                "confidence, status, evidence) VALUES ('F-policy-match', "
                "'seeded-observed-match', 'Observed logon', 'Normalized evidence lead', "
                "'medium', 0.8, 'accepted', ?)",
                [json.dumps([{"evidence_id": "evtx-policy-match"}])],
            )
            pipeline_module._record_stage_receipt(
                db,
                "pipeline-normalize",
                pipeline_module._sources_current_revision(db),
                "seeded normalized candidate fixture",
                details={"parser_revision": pipeline_module._parser_revision()},
            )
            pipeline_module._record_stage_receipt(
                db,
                "pipeline-analyze",
                pipeline_module._analysis_revision(case),
                "seeded candidate finding fixture",
            )

        with ExitStack() as stack:
            for cm in _stub_llm(captured):
                stack.enter_context(cm)
            pipeline_module.run_investigation(
                case_dir,
                input_dir=str(input_dir),
                llm_base_url="http://127.0.0.1:1",
                model="offline-stub",
                max_iter=1,
            )

        case = Case.open(case_dir)
        with CaseDB(case) as db:
            terminal_event_count = db.execute(
                "SELECT COUNT(*) FROM trace.progress_events "
                "WHERE kind = 'investigation.terminal'"
            ).fetchone()[0]
            assert terminal_event_count == 1, terminal_event_count
            steps = db.execute(
                "SELECT output_json FROM trace.investigation_steps WHERE phase = 'forensia-md'"
            ).fetchall()
            assert steps, "adoption receipt step missing"
            record = json.loads(str(steps[0][0]))
            assert record["policy_state"] == "adopted"
            assert "GUIDANCE-SENTINEL-495a" in record["body"]
            assert record["source"] == "case_root"
            assert record["source_path"].endswith("FORENSIA.md")
            assert record["roles"] == list(case_policy_module.CASE_POLICY_ROLES)
            assert record["notice"] is None
            # The adopted objective reached the work-admission objective seam.
            state_row = db.execute(
                "SELECT objective FROM investigation_state WHERE state_id = 'case'"
            ).fetchone()
            assert "host executed the suspect archive" in str(state_row[0]), state_row
            gap_row = db.execute(
                "SELECT status FROM report_gaps WHERE description = "
                "'Investigation objective not configured'"
            ).fetchone()
            # On a fresh case the configuration gap is never left open: it is
            # either absent or resolved through the adopted objective.
            assert gap_row is None or gap_row[0] == "resolved", gap_row

        # Policy text changes the adopted prompt candidates as intended: the
        # sentinel guidance lands in the plan prompts of the investigation
        # roles, and no other phase carries the policy block.
        assert captured, "no LLM prompts were observed"
        phases_with_policy = {
            phase for (phase, system) in captured if "CASE_INSTRUCTIONS" in system
        }
        assert phases_with_policy
        assert phases_with_policy <= set(_POLICY_ROLES), phases_with_policy
        assert all(
            "GUIDANCE-SENTINEL-495a" in system
            for (phase, system) in captured
            if phase in phases_with_policy
        )
        for phase, system in captured:
            if phase in _POLICY_ROLES:
                continue
            assert "CASE_INSTRUCTIONS" not in system, (phase, system[:120])


def test_resume_keeps_recorded_policy_and_explicit_path_adopts_edited_body() -> None:
    """V2-05 resume semantics on the real investigate() path with a real DB:
    recorded revision stays in force, differences surface explicitly, and an
    explicit path reload adopts the edited body without touching Case State."""
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.investigation import investigator as investigator_module
    from forensia.investigation.case_policy import CasePolicyInput
    from forensia.pipeline import UsageError, resolve_forensia_policy_input

    body_a = (
        "# Investigation Objective\n- objective-marker-alpha: audit logon chains\n"
        "\n# Constraints\n- only normalized evidence\n"
    )
    body_b = (
        "# Investigation Objective\n- objective-marker-beta: audit browser use\n"
        "\n# Constraints\n- only normalized evidence\n"
    )

    def router(**kwargs):
        system_content = str(kwargs["messages"][0].get("content", ""))
        if "section-check" in system_content:
            return {"verdict": "sufficient", "fact_updates": []}
        return {"action": "write", "enough_to_write": True}

    def stubs():
        return (
            mock.patch(
                "forensia.llm.json_response.request_llm_json", side_effect=router
            ),
            mock.patch.object(
                investigator_module,
                "async_refresh_report_sections",
                new=mock.AsyncMock(return_value={"report_status": {}, "gaps": []}),
            ),
        )

    def run_investigate(db, policy_input, progress_callback=None):
        with ExitStack() as stack:
            for cm in stubs():
                stack.enter_context(cm)
            return asyncio.run(
                investigator_module.investigate(
                    case=case,
                    db=db,
                    base_url="http://127.0.0.1:9",
                    model="offline-stub",
                    max_iter=1,
                    report_only=False,
                    forensia_policy=policy_input,
                    progress_callback=progress_callback,
                )
            )

    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        policy_path = Path(tmpdir) / "FORENSIA.md"
        policy_path.write_text(body_a, encoding="utf-8")

        policy_a = CasePolicyInput(
            body=body_a, source="case_root", source_path=str(policy_path)
        )
        with CaseDB(case) as db:

            def latest_record():
                row = db.execute(
                    "SELECT output_json FROM trace.investigation_steps "
                    "WHERE phase = 'forensia-md' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                return json.loads(str(row[0])) if row and row[0] else None

            run_investigate(db, policy_a)
            record1 = latest_record()
            assert record1["policy_state"] == "adopted"
            assert "objective-marker-alpha" in record1["body"]

            # Edit the file; resume WITHOUT explicit reload keeps the recorded body.
            policy_path.write_text(body_b, encoding="utf-8")
            policy_after_edit = CasePolicyInput(
                body=body_b, source="case_root", source_path=str(policy_path)
            )
            difference_messages: list[str] = []

            def note_progress(payload):
                text = str(payload.get("summary") or "")
                if text:
                    difference_messages.append(text)

            run_investigate(db, policy_after_edit, progress_callback=note_progress)
            record2 = latest_record()
            assert record2["policy_state"] == "pinned"
            assert "objective-marker-alpha" in record2["body"], record2["body"][:120]
            assert "objective-marker-beta" not in record2["body"]
            assert record2["notice"], "difference must be surfaced explicitly"
            assert any(
                "recorded revision remains" in message
                for message in difference_messages
            ), difference_messages

            # Explicit-path reload adopts the edited body at this session start.
            explicit_policy = CasePolicyInput(
                body=body_b, source="explicit_path", source_path=str(policy_path)
            )
            run_investigate(db, explicit_policy)
            record3 = latest_record()
            assert record3["policy_state"] == "adopted"
            assert "objective-marker-beta" in record3["body"]

            # A changed file is pinned, but the recorded revision must still
            # fit the current session budget; explicit reload validates its body.
            with mock.patch(
                "forensia.investigation.case_policy.get_system_prompt_budget_chars",
                return_value=10,
            ):
                assert (
                    resolve_forensia_policy_input(
                        case, None, recorded_policy_exists=True
                    )
                    is not None
                )
                try:
                    resolve_forensia_policy_input(
                        case, policy_path, recorded_policy_exists=True
                    )
                except UsageError:
                    pass
                else:
                    raise AssertionError("oversized explicit reload was accepted")
                with pytest.raises(ValueError, match="budget allows 5 chars"):
                    run_investigate(db, None)
                assert "objective-marker-beta" in latest_record()["body"]

            # Removing the file also keeps the last adopted revision on resume.
            policy_path.unlink()
            run_investigate(db, None)
            record4 = latest_record()
            assert record4["policy_state"] == "pinned"
            assert "objective-marker-beta" in record4["body"]
            assert record4["current_file"] == {"present": False}

            # The Case State authority was never rewritten by file reload:
            # the accepted objective (first adoption) stays and sessions all
            # ended with a receipt.
            state = db.execute(
                "SELECT objective FROM investigation_state WHERE state_id = 'case'"
            ).fetchone()
            assert "objective-marker-alpha" in str(state[0])
            sessions = db.execute(
                "SELECT status FROM trace.investigation_sessions ORDER BY session_id"
            ).fetchall()
            assert all(
                row[0] in {"completed", "stopped", "failed"} for row in sessions
            ), sessions
            assert sum(row[0] == "failed" for row in sessions) == 1, sessions


def test_oversized_forensia_md_policy_refuses_with_reason() -> None:
    """An oversized policy refuses the run with the reason and adopts nothing."""
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
    from forensia.pipeline import UsageError, run_investigation

    with tempfile.TemporaryDirectory() as tmpdir:
        case_dir = Path(tmpdir) / "case"
        input_dir = case_dir / "input"
        input_dir.mkdir(parents=True)
        oversized = "P" * (_POLICY_BUDGET_SMALL + 50)
        (case_dir / "FORENSIA.md").write_text(oversized, encoding="utf-8")

        with (
            mock.patch(
                "forensia.investigation.case_policy.get_system_prompt_budget_chars",
                return_value=2 * _POLICY_BUDGET_SMALL,
            ),
            mock.patch(
                "forensia.llm.json_response.request_llm_json",
                side_effect=AssertionError("LLM must not be called"),
            ),
        ):
            with pytest.raises(UsageError, match="Shorten the policy"):
                run_investigation(
                    case_dir,
                    input_dir=str(input_dir),
                    llm_base_url="http://127.0.0.1:1",
                    model="offline-stub",
                )

        # An explicitly missing path fails the same explicit way.
        with pytest.raises(UsageError, match="policy file not found"):
            run_investigation(
                case_dir,
                input_dir=str(input_dir),
                llm_base_url="http://127.0.0.1:1",
                model="offline-stub",
                forensia_md=case_dir / "nope.md",
            )

        # Nothing was recorded: the unusable policy never reached the loop.
        case = Case.open(case_dir)
        with CaseDB(case) as db:
            rows = db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps WHERE phase = 'forensia-md'"
            ).fetchone()
            assert int(rows[0]) == 0, "oversized policy must not be adopted"


def test_knowledge_index_binds_to_the_run_input_not_the_process() -> None:
    """V2-08: the knowledge index is a run input, never a process-global leak.

    Two investigations in one Python process: the first adopts a knowledge
    directory whose sentinel phrase is disclosed in its plan prompt; the second
    run (no flag) must disclose nothing of the first case — the per-invocation
    reset replaces the index, so cross-case knowledge cannot leak.
    """
    from forensia.pipeline import run_investigation

    knowledge_body = (
        "---\ntype: knowledge\ntitle: Execution refutation manual\n"
        "description: host_execution_activity process execution refutation "
        "K-SOURCE-SENTINEL-42x\n---\n## Refutation for execution keypoint\n"
        "For host_execution_activity check prefetch patterns first. "
        "K-BODY-SENTINEL-42x\n"
    )

    def make_case(tmpdir: Path, name: str) -> tuple[Path, Path]:
        case_dir = tmpdir / name
        input_dir = case_dir / "input"
        input_dir.mkdir(parents=True)
        return case_dir, input_dir

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        knowledge_dir = tmp / "knowledge"
        knowledge_dir.mkdir()
        (knowledge_dir / "execution_knowledge.md").write_text(
            knowledge_body, encoding="utf-8"
        )
        case_a, input_a = make_case(tmp, "case_a")
        case_b, input_b = make_case(tmp, "case_b")

        captured: list[tuple[str, str]] = []

        def run(
            case_dir: Path, input_dir: Path, knowledge: Path | None
        ) -> list[tuple[str, str]]:
            def seed_observation(_case, db):
                db.execute(
                    "INSERT INTO prefetch_executions "
                    "(evidence_id, source_file, executable_name, exec_count) "
                    "VALUES ('prefetch-knowledge-test', 'knowledge-source', 'TEST.EXE', 1)"
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, display_path, ingest_status, row_count) "
                    "VALUES ('knowledge-source', 'prefetch', 'test.pf', 'normalized', 1)"
                )
                db.execute(
                    "INSERT INTO findings "
                    "(finding_id, rule_id, title, summary, severity, confidence, status, evidence) "
                    "VALUES ('F-knowledge', 'execution-test', 'Process execution', "
                    "'Observed execution activity', 'medium', 0.5, 'accepted', ?)",
                    [json.dumps([{"evidence_id": "prefetch-knowledge-test"}])],
                )

            first = len(captured)
            with ExitStack() as stack:
                for cm in _stub_llm(captured):
                    stack.enter_context(cm)
                run_investigation(
                    case_dir,
                    input_dir=str(input_dir),
                    llm_base_url="http://127.0.0.1:1",
                    model="offline-stub",
                    max_llm_calls=12,
                    knowledge_dir=knowledge,
                    pre_investigation=seed_observation,
                    max_iter=1,
                )
            return captured[first:]

        prompts_a = run(case_a, input_a, knowledge_dir)
        assert prompts_a, "no prompts captured for run A"
        # Run A discloses the manual: the sentinel reaches the plan prompts of
        # the investigation roles — and appears once (no duplicate injection).
        occurrences = [
            system.count("K-BODY-SENTINEL-42x")
            for (_, system) in prompts_a
            if "K-BODY-SENTINEL-42x" in system
        ]
        assert occurrences, "run A must disclose the seeded knowledge"
        assert all(count == 1 for count in occurrences), occurrences

        # Run B in the same process, with no knowledge input: the previous
        # case's knowledge index must not leak into its prompts.
        prompts_b = run(case_b, input_b, None)
        assert prompts_b, "no prompts captured for run B"
        leaks = [
            (phase, system[:120])
            for (phase, system) in prompts_b
            if "K-BODY-SENTINEL-42x" in system
            or "K-SOURCE-SENTINEL-42x" in system
            or "case_a" in system
        ]
        assert not leaks, leaks
