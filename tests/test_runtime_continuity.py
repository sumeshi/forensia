from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.runtime import RuntimeClient, start_runtime


class _FixedProvider(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self):
        self.request_started = threading.Event()
        self.release_request = threading.Event()
        self.request_condition = threading.Condition()
        self.requests = 0

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(size)
                with server.request_condition:
                    server.requests += 1
                    server.request_condition.notify_all()
                server.request_started.set()
                server.release_request.wait(10)
                body = json.dumps(
                    {
                        "choices": [
                            {"message": {"content": "{}"}, "finish_reason": "stop"}
                        ]
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                pass

        server = self
        super().__init__(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def close(self) -> None:
        self.release_request.set()
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)

    def wait_for_requests(self, count: int, timeout: float = 10) -> bool:
        deadline = time.monotonic() + timeout
        with self.request_condition:
            while self.requests < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.request_condition.wait(remaining)
            return True


def _cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    cli = shutil.which("forensia")
    if cli is None:
        pytest.skip("forensia console entry point is not installed in this environment")
    return subprocess.run(
        [cli, *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


def _receipt(
    client: RuntimeClient, command_id: str, operation: str, payload: dict | None = None
) -> dict:
    client.request(
        {
            "type": "command",
            "command_id": command_id,
            "operation": operation,
            "payload": payload or {},
        }
    )
    for _ in range(200):
        result = client.request(
            {
                "type": "command",
                "command_id": command_id,
                "operation": operation,
                "payload": payload or {},
            }
        )
        if result.get("status") not in {"accepted", "applying"}:
            return result
        time.sleep(0.025)
    raise AssertionError(f"Runtime did not finish {operation}: {command_id}")


def test_public_background_runtime_stop_busy_and_idle_overwrite(tmp_path):
    provider = _FixedProvider()
    case_dir = tmp_path / "case"
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    source_prefetch = (
        Path(__file__).resolve().parents[1]
        / "sample/cfreds/Prefetch/CCLEANER64.EXE-779BD542.pf"
    )
    has_prefetch = source_prefetch.is_file()
    if has_prefetch:
        shutil.copy2(source_prefetch, input_dir / source_prefetch.name)
    system_prompt = tmp_path / "FORENSIA.md"
    system_prompt.write_text(
        "# Objective\n\nInvestigate this test case carefully.\n", encoding="utf-8"
    )
    template = tmp_path / "report.md"
    template.write_text("---\ntitle: Runtime test\n---\n# Summary\n", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "LLM_BASE_URL": provider.base_url,
            "LLM_MODEL": "fixed-test-model",
            "LLM_API_KEY": "fixed-test-key",
            "LLM_MAX_CALLS": "1",
            "FORENSIA_MAX_ITERATIONS": "1",
            "LLM_OUTAGE_WALL_CLOCK_BUDGET_S": "2",
            "LLM_OUTAGE_PROBE_INTERVAL_S": "1",
        }
    )
    client = None
    try:
        started = _cli(
            "investigate",
            str(input_dir),
            "--out",
            str(case_dir),
            "--system-prompt",
            str(system_prompt),
            "--template",
            str(template),
            "--background",
            env=env,
        )
        assert started.returncode == 0, started.stdout + started.stderr
        assert provider.request_started.wait(10), (
            "initial investigation never reached provider"
        )

        client = RuntimeClient(case_dir, timeout=2)
        first_status = client.request({"type": "status"})
        assert first_status["ready"] is True
        assert client.request({"type": "snapshot"})["case_name"] == "case"
        system_prompt.unlink()
        template.unlink()

        busy = _cli(
            "investigate",
            str(input_dir),
            "--out",
            str(case_dir),
            "--overwrite",
            "--background",
            env=env,
        )
        assert busy.returncode != 0
        assert "busy" in (busy.stdout + busy.stderr).lower()

        accepted_stop = client.request(
            {"type": "command", "command_id": "public-stop-1", "operation": "stop"}
        )
        assert accepted_stop["status"] == "accepted"
        provider.release_request.set()
        stopped = _receipt(client, "public-stop-1", "stop")
        assert stopped["status"] == "applied"
        with CaseDB(Case.open(case_dir), read_only=True) as db:
            original_session_count = db.execute(
                "SELECT COUNT(*) FROM trace.investigation_sessions"
            ).fetchone()[0]
            status = db.execute(
                "SELECT status FROM trace.runtime_commands WHERE command_id = ?",
                ["public-stop-1"],
            ).fetchone()[0]
            policy_adopted = db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps "
                "WHERE phase = 'forensia-md' "
                "AND json_extract_string(input_json, '$.source_path') = ? "
                "AND output_json::VARCHAR LIKE '%Investigate this test case carefully%'",
                [str(system_prompt.resolve())],
            ).fetchone()[0]
            report_adopted = db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps "
                "WHERE phase = 'report-input' "
                "AND json_extract_string(input_json, '$.source_path') = ? "
                "AND output_json::VARCHAR LIKE '%Runtime test%'",
                [str(template.resolve())],
            ).fetchone()[0]
        assert status == "applied"
        assert policy_adopted == 1
        assert report_adopted >= 1

        direct_case = tmp_path / "direct-case"
        direct_system_prompt = tmp_path / "direct-FORENSIA.md"
        direct_system_prompt.write_text(
            "# Objective\n\nInvestigate this test case carefully.\n",
            encoding="utf-8",
        )
        direct_template = tmp_path / "direct-report.md"
        direct_template.write_text(
            "---\ntitle: Runtime test\n---\n# Summary\n", encoding="utf-8"
        )
        direct_code = """
from pathlib import Path
import sys
from forensia.pipeline import run_investigation
run_investigation(
    Path(sys.argv[1]), input_dir=sys.argv[2], llm_base_url=sys.argv[3],
    model='fixed-test-model', max_iter=1, max_llm_calls=1,
    forensia_md=sys.argv[4], report_spec=sys.argv[5],
)
"""
        if has_prefetch:
            direct = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    direct_code,
                    str(direct_case),
                    str(input_dir),
                    provider.base_url,
                    str(direct_system_prompt),
                    str(direct_template),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
                check=False,
            )
            assert direct.returncode == 0, direct.stdout + direct.stderr

        def judgments(path: Path) -> tuple[list, list, list]:
            with CaseDB(Case.open(path), read_only=True) as db:
                evidence = db.execute(
                    "SELECT executable_name, exec_count, source_file, severity "
                    "FROM prefetch_executions ORDER BY executable_name, source_file"
                ).fetchall()
                findings = db.execute(
                    "SELECT rule_id, title, severity, confidence, status "
                    "FROM findings ORDER BY rule_id, title"
                ).fetchall()
                hypotheses = db.execute(
                    "SELECT description, verdict, status FROM hypotheses "
                    "ORDER BY description"
                ).fetchall()
            return evidence, findings, hypotheses

        if has_prefetch:
            runtime_judgments = judgments(case_dir)
            assert runtime_judgments[0], (
                "CFReDS Prefetch produced no durable evidence rows"
            )
            assert runtime_judgments == judgments(direct_case)

            alternates = sorted(
                path
                for path in source_prefetch.parent.rglob("*.pf")
                if path.resolve() != source_prefetch.resolve()
            )
            if alternates:
                with CaseDB(Case.open(case_dir), read_only=True) as db:
                    before_source = db.execute(
                        "SELECT sha256, path FROM ingested_files "
                        "WHERE source_kind = 'prefetch' ORDER BY path, sha256 LIMIT 1"
                    ).fetchone()
                assert before_source is not None
                shutil.copy2(alternates[0], input_dir / source_prefetch.name)
                replace = client.request(
                    {
                        "type": "command",
                        "command_id": "public-add-prefetch-replacement",
                        "operation": "add",
                        "payload": {"input_dir": str(input_dir)},
                    }
                )
                assert replace["status"] == "accepted"
                replacement_receipt = _receipt(
                    client,
                    "public-add-prefetch-replacement",
                    "add",
                    {"input_dir": str(input_dir)},
                )
                assert replacement_receipt["status"] == "applied"
                with CaseDB(Case.open(case_dir), read_only=True) as db:
                    after_source = db.execute(
                        "SELECT sha256, path FROM ingested_files "
                        "WHERE source_kind = 'prefetch' ORDER BY path, sha256 LIMIT 1"
                    ).fetchone()
                    old_source_count = db.execute(
                        "SELECT COUNT(*) FROM evidence_sources WHERE source_id = ?",
                        [before_source[0]],
                    ).fetchone()[0]
                    old_evidence_count = db.execute(
                        "SELECT COUNT(*) FROM prefetch_executions WHERE source_file = ?",
                        [before_source[0]],
                    ).fetchone()[0]
                assert after_source is not None
                assert after_source[1] == before_source[1]
                assert after_source[0] != before_source[0]
                assert old_source_count == 0
                assert old_evidence_count == 0

        # A repeated idle stop records a receipt but does not create a session.
        assert _receipt(client, "public-stop-2", "stop")["status"] == "applied"
        with CaseDB(Case.open(case_dir), read_only=True) as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM trace.investigation_sessions"
                ).fetchone()[0]
                == original_session_count
            )

        resumed = client.request(
            {"type": "command", "command_id": "public-resume-1", "operation": "resume"}
        )
        assert resumed["status"] == "accepted"
        resume_receipt = _receipt(client, "public-resume-1", "resume")
        assert resume_receipt["status"] in {"applied", "failed"}
        with CaseDB(Case.open(case_dir), read_only=True) as db:
            resumed_session_count = db.execute(
                "SELECT COUNT(*) FROM trace.investigation_sessions"
            ).fetchone()[0]
        assert resumed_session_count > original_session_count
        assert (
            _receipt(client, "public-stop-after-resume", "stop")["status"] == "applied"
        )

        reported = client.request(
            {
                "type": "command",
                "command_id": "public-report-read",
                "operation": "report",
                "payload": {"write": False},
            }
        )
        assert reported["status"] == "accepted"
        report = _receipt(client, "public-report-read", "report", {"write": False})
        assert report["status"] == "applied"
        with CaseDB(Case.open(case_dir), read_only=True) as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM trace.investigation_sessions"
                ).fetchone()[0]
                == resumed_session_count
            )

        empty_add = tmp_path / "empty-add"
        empty_add.mkdir()
        added = client.request(
            {
                "type": "command",
                "command_id": "public-add-empty",
                "operation": "add",
                "payload": {"input_dir": str(empty_add)},
            }
        )
        assert added["status"] == "accepted"
        assert (
            _receipt(client, "public-add-empty", "add", {"input_dir": str(empty_add)})[
                "status"
            ]
            == "applied"
        )
        with CaseDB(Case.open(case_dir), read_only=True) as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM trace.investigation_sessions"
                ).fetchone()[0]
                == resumed_session_count
            )

        (case_dir / "overwrite-sentinel").write_text("replace", encoding="utf-8")
        overwritten = _cli(
            "investigate",
            str(input_dir),
            "--out",
            str(case_dir),
            "--overwrite",
            "--background",
            env=env,
        )
        assert overwritten.returncode == 0, overwritten.stdout + overwritten.stderr
        assert not (case_dir / "overwrite-sentinel").exists()
        replacement = RuntimeClient(case_dir, timeout=2)
        assert (
            replacement.request({"type": "status"})["startup_id"]
            != first_status["startup_id"]
        )
        client = replacement
    finally:
        provider.release_request.set()
        if client is not None:
            try:
                receipt = _receipt(client, "public-cleanup-stop", "stop")
                assert receipt["status"] == "applied"
                client.request({"type": "retire"})
            except OSError, RuntimeError, TimeoutError, ValueError, AssertionError:
                pass
        provider.close()


def test_runtime_process_crash_recovers_receipts_and_session_lease(tmp_path):
    provider = _FixedProvider()
    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    env = os.environ.copy()
    env.update(
        {
            "LLM_BASE_URL": provider.base_url,
            "LLM_MODEL": "fixed-test-model",
            "LLM_MAX_CALLS": "1",
            "FORENSIA_MAX_ITERATIONS": "1",
            "LLM_OUTAGE_WALL_CLOCK_BUDGET_S": "2",
            "LLM_OUTAGE_PROBE_INTERVAL_S": "1",
        }
    )
    owner = None
    replacement = None
    try:
        owner = start_runtime(case.path, env=env, timeout=10)
        first = owner.request(
            {"type": "command", "command_id": "crash-resume", "operation": "resume"}
        )
        assert first["status"] == "accepted"
        assert provider.wait_for_requests(1), "resume did not reach the fake provider"
        for _ in range(100):
            applying = owner.request(
                {"type": "command", "command_id": "crash-resume", "operation": "resume"}
            )
            if applying["status"] == "applying":
                break
            time.sleep(0.01)
        assert applying["status"] == "applying"
        queued_stop = owner.request(
            {"type": "command", "command_id": "crash-stop", "operation": "stop"}
        )
        assert queued_stop["status"] == "accepted"

        process = owner._process
        assert process is not None
        process.terminate()
        process.wait(timeout=5)
        provider.release_request.set()

        replacement = start_runtime(case.path, env=env, timeout=10)
        assert _receipt(replacement, "crash-stop", "stop")["status"] == "applied"
        with CaseDB(Case.open(case.path), read_only=True) as db:
            crashed_status = db.execute(
                "SELECT status, reason FROM trace.runtime_commands WHERE command_id = ?",
                ["crash-resume"],
            ).fetchone()
        assert crashed_status == (
            "failed",
            "Runtime exited while applying; outcome not replayed",
        )
        assert provider.requests == 1, "the interrupted resume was replayed"
        resumed = replacement.request(
            {"type": "command", "command_id": "recovered-resume", "operation": "resume"}
        )
        assert resumed["status"] == "accepted"
        recovered_receipt = _receipt(replacement, "recovered-resume", "resume")
        assert recovered_receipt["status"] == "applied", recovered_receipt["reason"]
        assert provider.wait_for_requests(2)
        with CaseDB(Case.open(case.path), read_only=True) as db:
            abandoned = db.execute(
                "SELECT COUNT(*) FROM trace.investigation_sessions WHERE status = 'abandoned'"
            ).fetchone()[0]
        assert abandoned >= 1
    finally:
        provider.release_request.set()
        if replacement is not None:
            try:
                _receipt(replacement, "recovery-cleanup-stop", "stop")
                replacement.request({"type": "retire"})
            except OSError, RuntimeError, TimeoutError, ValueError, AssertionError:
                process = replacement._process
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)
        if (
            owner is not None
            and owner._process is not None
            and owner._process.poll() is None
        ):
            owner._process.terminate()
            owner._process.wait(timeout=3)
        provider.close()
