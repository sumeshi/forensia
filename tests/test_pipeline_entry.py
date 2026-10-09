"""Kernel entry boundary (V2-02) and the FORENSIA.md policy input seam (V2-05).

The display-agnostic pipeline entry is what both the CLI and a future TUI
import to run a case. Importing it must not require a terminal presentation
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

FORBIDDEN = ("typer", "click", "rich", "fastapi", "uvicorn")

# Investigation roles that may receive adopted policy text (V2-05). Every
# other captured role — checker, evidence, report section agents — must be
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
                _run_normalize_stage(case, db, False, {"new_files": 1}, push, None)
                _run_normalize_stage(case, db, False, {"new_files": 0}, push, None)
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
                    _run_normalize_stage(case, db, False, {"new_files": 0}, push, None)
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
                    )
                assert len(calls) == 3 and calls[-1] is None, calls


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
            phase = "section-check" if "section-check" in system_content else "other"
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
        if "section-check" in system_content:
            return {"verdict": "sufficient", "fact_updates": []}
        return {"action": "write", "enough_to_write": True}

    return (
        mock.patch(
            "forensia.ai.llm.json_response.request_llm_json", side_effect=router
        ),
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
    """V2-05 real CLI path: adoption, recording, prompt routing, gate isolation."""
    from typer.testing import CliRunner

    from forensia.ai.investigation import case_policy as case_policy_module
    from forensia.cli import app as cli_app
    from forensia.core.case import Case
    from forensia.db.database import CaseDB

    captured: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        case_dir = Path(tmpdir) / "case"
        input_dir = case_dir / "input"
        input_dir.mkdir(parents=True)
        (input_dir / "placeholder.evtx").write_bytes(b"")
        (case_dir / "FORENSIA.md").write_text(POLICY_BODY, encoding="utf-8")

        runner = CliRunner()
        with ExitStack() as stack:
            for cm in _stub_llm(captured):
                stack.enter_context(cm)
            result = runner.invoke(
                cli_app.app,
                [
                    "investigate",
                    str(case_dir),
                    str(input_dir),
                    "--llm-base-url",
                    "http://127.0.0.1:1",
                    "--model",
                    "offline-stub",
                    "--max-iter",
                    "1",
                ],
            )
        if result.exception is not None:
            raise result.exception
        assert result.exit_code == 0, result.output

        case = Case.open(case_dir)
        with CaseDB(case) as db:
            steps = db.execute(
                "SELECT output_json FROM investigation_steps WHERE phase = 'forensia-md'"
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
        assert set(phases_with_policy) <= set(_POLICY_ROLES), phases_with_policy
        assert {"plan-broad-gap", "plan-broad-draft"} <= phases_with_policy, (
            phases_with_policy
        )
        assert any(
            "GUIDANCE-SENTINEL-495a" in system
            for (phase, system) in captured
            if phase in _POLICY_ROLES
        )
        for phase, system in captured:
            if phase in _POLICY_ROLES:
                continue
            assert "CASE_INSTRUCTIONS" not in system, (phase, system[:120])


def test_resume_keeps_recorded_policy_and_explicit_path_adopts_edited_body() -> None:
    """V2-05 resume semantics on the real investigate() path with a real DB:
    recorded revision stays in force, differences surface explicitly, and an
    explicit path reload adopts the edited body without touching Case State."""
    from forensia.ai.investigation import investigator as investigator_module
    from forensia.ai.investigation.case_policy import CasePolicyInput
    from forensia.core.case import Case
    from forensia.db.database import CaseDB
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
                "forensia.ai.llm.json_response.request_llm_json", side_effect=router
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
                    "SELECT output_json FROM investigation_steps "
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

            # A large edited file cannot block a pinned resume, while an
            # explicit reload must still reject content that cannot fit.
            with mock.patch(
                "forensia.pipeline.get_system_prompt_budget_chars", return_value=10
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
                "SELECT status FROM investigation_sessions ORDER BY session_id"
            ).fetchall()
            assert all(row[0] in {"completed", "stopped"} for row in sessions), sessions


def test_oversized_forensia_md_policy_refuses_with_reason() -> None:
    """An oversized policy refuses the run with the reason and adopts nothing."""
    from typer.testing import CliRunner

    from forensia.cli import app as cli_app
    from forensia.core.case import Case
    from forensia.db.database import CaseDB

    with tempfile.TemporaryDirectory() as tmpdir:
        case_dir = Path(tmpdir) / "case"
        input_dir = case_dir / "input"
        input_dir.mkdir(parents=True)
        oversized = "P" * (_POLICY_BUDGET_SMALL + 50)
        (case_dir / "FORENSIA.md").write_text(oversized, encoding="utf-8")

        runner = CliRunner()
        with (
            mock.patch(
                "forensia.pipeline.get_system_prompt_budget_chars",
                return_value=2 * _POLICY_BUDGET_SMALL,
            ),
            mock.patch(
                "forensia.ai.llm.json_response.request_llm_json",
                side_effect=AssertionError("LLM must not be called"),
            ),
        ):
            result = runner.invoke(
                cli_app.app,
                [
                    "investigate",
                    str(case_dir),
                    str(input_dir),
                    "--llm-base-url",
                    "http://127.0.0.1:1",
                    "--model",
                    "offline-stub",
                ],
            )
        assert result.exit_code == 2, result.output
        assert "Shorten the policy" in result.output, result.output

        # An explicitly missing path fails the same explicit way.
        missing = runner.invoke(
            cli_app.app,
            [
                "investigate",
                str(case_dir),
                "--forensia-md",
                str(case_dir / "nope.md"),
            ],
        )
        assert missing.exit_code == 2, missing.output
        assert "policy file not found" in missing.output, missing.output

        # Nothing was recorded: the unusable policy never reached the loop.
        case = Case.open(case_dir)
        with CaseDB(case) as db:
            rows = db.execute(
                "SELECT COUNT(*) FROM investigation_steps WHERE phase = 'forensia-md'"
            ).fetchone()
            assert int(rows[0]) == 0, "oversized policy must not be adopted"


def test_knowledge_index_binds_to_the_run_input_not_the_process() -> None:
    """V2-08: the knowledge index is a run input, never a process-global leak.

    Two investigations in one Python process: the first adopts a ``--knowledge``
    directory whose sentinel phrase is disclosed in its plan prompt; the second
    run (no flag) must disclose nothing of the first case — the per-invocation
    reset replaces the index, so cross-case knowledge cannot leak.
    """
    from typer.testing import CliRunner

    from forensia.cli import app as cli_app

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
        (input_dir / "placeholder.evtx").write_bytes(b"")
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

        runner = CliRunner()
        captured: list[tuple[str, str]] = []

        def run(case_dir: Path, input_dir: Path, extra: list[str]) -> None:
            first = len(captured)
            with ExitStack() as stack:
                for cm in _stub_llm(captured):
                    stack.enter_context(cm)
                result = runner.invoke(
                    cli_app.app,
                    [
                        "investigate",
                        str(case_dir),
                        str(input_dir),
                        "--llm-base-url",
                        "http://127.0.0.1:1",
                        "--model",
                        "offline-stub",
                        "--max-llm-calls",
                        "12",
                        *extra,
                    ],
                )
            if result.exception is not None:
                raise result.exception
            assert result.exit_code == 0, result.output
            return captured[first:]

        prompts_a = run(case_a, input_a, ["--knowledge", str(knowledge_dir)])
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
        prompts_b = run(case_b, input_b, [])
        assert prompts_b, "no prompts captured for run B"
        leaks = [
            (phase, system[:120])
            for (phase, system) in prompts_b
            if "K-BODY-SENTINEL-42x" in system
            or "K-SOURCE-SENTINEL-42x" in system
            or "case_a" in system
        ]
        assert not leaks, leaks
