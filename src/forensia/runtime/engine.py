from __future__ import annotations

import json
import logging
import queue
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensia.config import Settings, load_settings, settings_scope
from forensia.core.case import Case
from forensia.core.control import InvestigationStopped, stop_scope
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB, CaseDBBusyError
from forensia.db.progress import record_progress_event
from forensia.db.views import case_detail, case_events, case_snapshot
from forensia.llm.telemetry import (
    LLMTelemetry,
    reset_active_telemetry,
    set_active_telemetry,
)

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _safe_error(exc: Exception, settings: Settings) -> str:
    message = str(exc)
    if settings.llm_api_key:
        message = message.replace(settings.llm_api_key, "[redacted]")
    return message[:2000] or type(exc).__name__


class RuntimeEngine:
    """Own one case's command queue and adapt it to the existing pipeline."""

    def __init__(self, case_dir: str | Path):
        self._requested_case_dir = Path(case_dir).expanduser()
        self.case_dir = self._requested_case_dir.resolve()
        self.stop_requested = threading.Event()
        self._lock = threading.RLock()
        self._commands: queue.Queue[str | None] = queue.Queue()
        self._db: CaseDB | None = None
        self._case: Case | None = None
        self._settings = Settings()
        self._system_prompt: Path | None = None
        self._template: Path | None = None
        self._prepared = False
        self._active = False
        self._initial_pending = False
        self._applying = False
        self._retiring = False
        self._running = True
        self._resume_after: set[str] = set()
        self._pending_initial: tuple[Any, ...] | None = None
        self._runner_thread: threading.Thread | None = None

    def prepare(
        self,
        *,
        input_dir: str | Path | None = None,
        overwrite: bool = False,
        settings: dict[str, Any] | None = None,
        system_prompt: str | Path | None = None,
        template: str | Path | None = None,
        rules: str | Path | None = None,
    ) -> None:
        """Validate startup inputs and establish the case before IPC is ready."""
        if settings is not None and not isinstance(settings, dict):
            raise ValueError("settings must be an object")
        values = settings or {}
        if overwrite and self._requested_case_dir.is_symlink():
            raise ValueError("--overwrite cannot delete a symlinked case directory")
        self._settings = (
            Settings(**values)
            if values
            else load_settings(require_inference=input_dir is not None)
        )
        if input_dir is not None and not (
            self._settings.llm_base_url and self._settings.llm_model
        ):
            raise ValueError("Investigation requires LLM_BASE_URL and LLM_MODEL")
        if (
            input_dir is not None
            and (self.case_dir / "manifest.yaml").is_file()
            and not overwrite
        ):
            raise ValueError(
                "Case already exists; use add or explicitly select overwrite"
            )
        if input_dir is not None and self.case_dir.exists():
            if not self.case_dir.is_dir():
                raise ValueError("Case output path must be a directory")
            if (
                any(self.case_dir.iterdir())
                and not (self.case_dir / "manifest.yaml").is_file()
            ):
                raise ValueError(
                    "Output directory already contains data and is not a case"
                )
        self._system_prompt = Path(system_prompt).resolve() if system_prompt else None
        self._template = Path(template).resolve() if template else None

        from forensia.investigation.case_policy import validate_policy_body
        from forensia.pipeline import (
            _open_or_init_case,
            _overwrite_case,
        )
        from forensia.report.sections.report_input import sections_from_report_spec

        # Validate external files before overwrite can remove the current case.
        if self._system_prompt is not None:
            if not self._system_prompt.is_file():
                raise ValueError(
                    f"forensia_md policy file not found: {self._system_prompt}"
                )
            policy_body = self._system_prompt.read_text(encoding="utf-8").strip()
            with settings_scope(self._settings):
                validate_policy_body(policy_body)
        if self._template is not None:
            sections_from_report_spec(self._template)
        from forensia.knowledge.sigma_bundle import load_sigma_bundle

        rules_bundle = load_sigma_bundle(Path(rules)) if rules is not None else None

        if overwrite:
            _overwrite_case(
                self.case_dir,
                str(input_dir) if input_dir is not None else None,
                {
                    "template_dir": None,
                    "report_spec": self._template,
                    "knowledge_dir": None,
                    "forensia_md": self._system_prompt,
                    "rules": rules,
                },
                None,
            )
        self._case = _open_or_init_case(
            self.case_dir, str(input_dir) if input_dir is not None else None, "", None
        )
        if input_dir is None and not self._case.database_path.exists():
            raise FileNotFoundError(
                f"Case database not found: {self._case.database_path}"
            )
        with CaseDB(self._case, read_only=self._case.database_path.exists()) as db:
            db.execute("SELECT command_id FROM trace.runtime_commands LIMIT 0")
            interrupted = db.execute(
                "SELECT command_id, operation FROM trace.runtime_commands WHERE status = 'applying'"
            ).fetchall()
        from forensia.pipeline import pin_investigation_inputs

        with CaseDB(self._case) as db:
            with settings_scope(self._settings):
                pin_investigation_inputs(
                    self._case,
                    db,
                    forensia_md=self._system_prompt,
                    report_spec=self._template,
                    rules_bundle=rules_bundle,
                )
            accepted = db.execute(
                """
                SELECT c.command_id, c.operation
                FROM trace.runtime_commands c
                LEFT JOIN (
                    SELECT json_extract_string(payload, '$.command_id') AS command_id,
                           MIN(event_index) AS accepted_index
                    FROM trace.progress_events
                    WHERE kind = 'runtime.command' AND status = 'running'
                    GROUP BY 1
                ) e USING (command_id)
                WHERE c.status = 'accepted'
                ORDER BY e.accepted_index NULLS LAST, c.created_at, c.command_id
                """
            ).fetchall()
        if interrupted:
            with CaseDB(self._case) as db:
                with db.transaction():
                    for command_id, operation in interrupted:
                        db.execute(
                            "UPDATE trace.runtime_commands SET status = 'failed', reason = ?, updated_at = ? WHERE command_id = ?",
                            [
                                "Runtime exited while applying; outcome not replayed",
                                _now(),
                                command_id,
                            ],
                        )
                        record_progress_event(
                            db,
                            progress_event(
                                "runtime.command",
                                "failed",
                                severity="error",
                                reason="runtime_restarted_during_apply",
                                stage="runtime",
                                summary="Runtime command was not replayed after an interrupted apply",
                                command_id=command_id,
                                operation=operation,
                            ),
                        )
        for command_id, operation in accepted:
            self._commands.put(command_id)
        with CaseDB(self._case, read_only=True) as db:
            self._sync_stop_requested(db)
        self._pending_initial = (
            input_dir,
            overwrite,
            self._settings,
            self._system_prompt,
            self._template,
        )
        self._initial_pending = input_dir is not None
        self._prepared = True

    @contextmanager
    def _database(
        self, *, write: bool = False, nonblocking: bool = False
    ) -> Iterator[CaseDB]:
        """Open the case DB, optionally refusing contended reads immediately."""
        if not self._lock.acquire(blocking=not nonblocking):
            raise CaseDBBusyError("Case database is busy")
        try:
            case = self._case or Case.open(self.case_dir)
            if self._db is not None:
                if nonblocking:
                    with self._db.read_snapshot():
                        yield self._db
                else:
                    yield self._db
                return
            with CaseDB(case, read_only=not write, blocking=not nonblocking) as db:
                if nonblocking:
                    with db.read_snapshot():
                        yield db
                else:
                    yield db
        finally:
            self._lock.release()

    def _sync_stop_requested(self, db: CaseDB) -> None:
        pending = db.execute(
            "SELECT 1 FROM trace.runtime_commands WHERE operation = 'stop' "
            "AND status IN ('accepted', 'applying') LIMIT 1"
        ).fetchone()
        if pending:
            self.stop_requested.set()
        else:
            self.stop_requested.clear()

    def snapshot(self) -> dict[str, Any]:
        with self._database(nonblocking=True) as db:
            return case_snapshot(self._case or db.case, db, settings=self._settings)

    def events(self, *, after_index: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        with self._database(nonblocking=True) as db:
            return case_events(db, after_index, limit)

    def detail(
        self, kind: str, item_id: str, *, limit: int = 100, offset: int = 0
    ) -> dict[str, Any] | None:
        with self._database(nonblocking=True) as db:
            return case_detail(db, kind, item_id, limit, offset=offset)

    def command(
        self, command_id: str, operation: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if operation not in {"stop", "resume", "add", "report", "steer"}:
            raise ValueError("Unsupported Runtime operation")
        if not isinstance(payload, dict):
            raise ValueError("Command payload must be an object")
        allowed = {
            "stop": set(),
            "resume": set(),
            "add": {"input_dir"},
            "report": {"write", "report_spec"},
            "steer": {"text"},
        }[operation]
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(
                f"Unexpected {operation} payload fields: {sorted(unknown)}"
            )
        if operation == "add" and (
            not isinstance(payload.get("input_dir"), str)
            or not payload["input_dir"].strip()
        ):
            raise ValueError("add requires a non-empty input_dir string")
        if operation == "report":
            if "write" in payload and type(payload["write"]) is not bool:
                raise ValueError("report write must be a boolean")
            if "report_spec" in payload and not isinstance(payload["report_spec"], str):
                raise ValueError("report_spec must be a string")
        if operation == "steer" and (
            not isinstance(payload.get("text"), str) or not payload["text"].strip()
        ):
            raise ValueError("steer requires non-empty text")
        if self._retiring:
            raise RuntimeError("Runtime is retiring")
        reject_resume = operation == "resume" and self._active
        payload_json = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        duplicate: dict[str, Any] | None = None
        conflict = False
        with self._database(write=True) as db:
            with db.transaction():
                old = db.execute(
                    "SELECT operation, payload, status, reason, result FROM trace.runtime_commands WHERE command_id = ?",
                    [command_id],
                ).fetchone()
                if old:
                    old_payload = old[1]
                    if isinstance(old_payload, str):
                        old_payload = json.loads(old_payload)
                    if old[0] != operation or old_payload != payload:
                        conflict = True
                        record_progress_event(
                            db,
                            progress_event(
                                "runtime.command.rejected",
                                "skipped",
                                severity="warning",
                                reason="command_id_content_mismatch",
                                stage="runtime",
                                summary="Runtime rejected a command ID reused with different content",
                                command_id=command_id,
                                operation=operation,
                            ),
                        )
                    else:
                        duplicate = self._receipt(command_id, old)
                else:
                    now = _now()
                    db.execute(
                        "INSERT INTO trace.runtime_commands (command_id, operation, payload, status, reason, result, created_at, updated_at) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                        [
                            command_id,
                            operation,
                            payload_json,
                            "rejected" if reject_resume else "accepted",
                            "Runtime is already active" if reject_resume else None,
                            now,
                            now,
                        ],
                    )
                    record_progress_event(
                        db,
                        progress_event(
                            "runtime.command",
                            "skipped" if reject_resume else "running",
                            severity="warning" if reject_resume else "info",
                            reason="runtime_already_active" if reject_resume else None,
                            stage="runtime",
                            summary="Runtime command rejected"
                            if reject_resume
                            else "Runtime command accepted",
                            command_id=command_id,
                            operation=operation,
                        ),
                    )
            if duplicate is None and not reject_resume:
                self._sync_stop_requested(db)
        if conflict:
            raise ValueError("command_id was already used with different content")
        if duplicate is not None:
            return duplicate
        if reject_resume:
            return {
                "command_id": command_id,
                "operation": operation,
                "status": "rejected",
                "reason": "Runtime is already active",
            }
        if operation == "stop":
            self.stop_requested.set()
        elif (self._active or self._applying) and operation in {
            "add",
            "report",
            "steer",
        }:
            self.stop_requested.set()
            if operation in {"add", "report", "steer"}:
                self._resume_after.add(command_id)
        if operation == "stop":
            self._resume_after.clear()
        self._commands.put(command_id)
        return {"command_id": command_id, "operation": operation, "status": "accepted"}

    @staticmethod
    def _receipt(command_id: str, row: tuple[Any, ...]) -> dict[str, Any]:
        result = row[4]
        if isinstance(result, str):
            result = json.loads(result)
        return {
            "command_id": command_id,
            "operation": row[0],
            "status": row[2],
            "reason": row[3],
            "result": result,
        }

    def run(
        self,
        input_dir: str | Path | None = None,
        overwrite: bool = False,
        settings: dict[str, Any] | Settings | None = None,
        system_prompt: str | Path | None = None,
        template: str | Path | None = None,
        rules: str | Path | None = None,
    ) -> None:
        self._runner_thread = threading.current_thread()
        if not self._prepared:
            self.prepare(
                input_dir=input_dir,
                overwrite=overwrite,
                settings=asdict(settings)
                if isinstance(settings, Settings)
                else settings,
                system_prompt=system_prompt,
                template=template,
                rules=rules,
            )
        initial = self._pending_initial
        self._pending_initial = None
        if initial and initial[0] is not None:
            try:
                self._investigate(initial[0], initial[2], None, None)
            except InvestigationStopped:
                self._record_runtime_interrupted()
            except Exception as exc:
                self._record_runtime_failure(exc)
                logger.error(
                    "Initial Runtime investigation failed (%s)", type(exc).__name__
                )
            finally:
                self._system_prompt = None
                self._template = None
        while self._running:
            command_id = self._commands.get()
            if command_id is None:
                break
            try:
                self._apply_command(command_id)
            except Exception as exc:
                logger.error(
                    "Runtime command failed before its terminal receipt (%s)",
                    type(exc).__name__,
                )
                try:
                    with self._database(write=True) as db:
                        with db.transaction():
                            db.execute(
                                "UPDATE trace.runtime_commands SET status = 'failed', reason = ?, updated_at = ? WHERE command_id = ?",
                                [_safe_error(exc, self._settings), _now(), command_id],
                            )
                except Exception:
                    logger.error("Could not persist Runtime command failure receipt")
        self._close_active_db()

    def _open_active_db(self) -> CaseDB:
        with self._lock:
            if self._db is None:
                self._db = CaseDB(self._case or Case.open(self.case_dir))
            return self._db

    def _close_active_db(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _record_runtime_failure(self, exc: Exception) -> None:
        message = _safe_error(exc, self._settings)
        try:
            with self._database(write=True) as db:
                with db.transaction():
                    record_progress_event(
                        db,
                        progress_event(
                            "runtime.investigation",
                            "failed",
                            severity="error",
                            reason="pipeline_exception",
                            stage="runtime",
                            summary="Investigation stopped after a pipeline error",
                            error_type=type(exc).__name__,
                            error=message,
                        ),
                    )
        except Exception:
            logger.error("Could not persist Runtime investigation failure event")

    def _record_runtime_interrupted(self) -> None:
        try:
            with self._database(write=True) as db:
                with db.transaction():
                    record_progress_event(
                        db,
                        progress_event(
                            "runtime.investigation",
                            "interrupted",
                            severity="warning",
                            reason="operator_requested_stop",
                            stage="runtime",
                            summary="Investigation stopped at an operational boundary",
                        ),
                    )
        except Exception:
            logger.error("Could not persist Runtime interruption event")

    def _investigate(
        self,
        input_dir: str | Path | None,
        settings: Settings,
        system_prompt: Path | None,
        template: Path | None,
        *,
        manual_resume: bool = False,
    ) -> None:
        with self._lock:
            self._active = True
            self._initial_pending = False
        try:
            from forensia.pipeline import run_investigation

            db = self._open_active_db()
            db.runtime_owned = True
            with settings_scope(settings):
                run_investigation(
                    self.case_dir,
                    input_dir=str(input_dir) if input_dir is not None else None,
                    db=db,
                    stop_requested=self.stop_requested,
                    forensia_md=system_prompt,
                    report_spec=template,
                    llm_base_url=settings.llm_base_url,
                    model=settings.llm_model,
                    manual_resume=manual_resume,
                )
        finally:
            with self._lock:
                self._active = False
            self._close_active_db()

    def _apply_command(self, command_id: str) -> None:
        self._applying = True
        try:
            self._apply_command_inner(command_id)
        finally:
            self._applying = False

    def _apply_command_inner(self, command_id: str) -> None:
        with self._database(write=True) as db:
            row = db.execute(
                "SELECT operation, payload FROM trace.runtime_commands WHERE command_id = ?",
                [command_id],
            ).fetchone()
            if row is None:
                return
            operation, payload = row
            if isinstance(payload, str):
                payload = json.loads(payload)
            with db.transaction():
                db.execute(
                    "UPDATE trace.runtime_commands SET status = 'applying', updated_at = ? WHERE command_id = ?",
                    [_now(), command_id],
                )
            self._sync_stop_requested(db)
        result: Any = None
        reason = None
        status = "applied"
        try:
            if operation == "resume":
                self._investigate(
                    None, self._resume_settings(), None, None, manual_resume=True
                )
            elif operation == "add":
                input_dir = payload.get("input_dir")
                if not isinstance(input_dir, str) or not input_dir:
                    raise ValueError("add requires input_dir")
                from forensia.pipeline import run_add

                db = self._open_active_db()
                self._active = True
                try:
                    with settings_scope(self._settings):
                        result = run_add(
                            self.case_dir,
                            input_dir,
                            db=db,
                            stop_requested=self.stop_requested,
                        )
                finally:
                    self._active = False
                    self._close_active_db()
            elif operation == "steer":
                from forensia.investigation.intervention import apply_intervention

                text = payload.get("text")
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("steer requires text")
                db = self._open_active_db()
                self._active = True
                session_id = f"steer-{command_id}"
                telemetry_token = None
                session_status = "failed"
                session_reason = "intervention raised"
                try:
                    with db.transaction():
                        db.execute(
                            "INSERT INTO trace.investigation_sessions "
                            "(session_id, started_at, status, owner_id, heartbeat_at, "
                            "phase, status_reason) VALUES (?, ?, 'running', ?, ?, ?, ?)",
                            [
                                session_id,
                                _now(),
                                "runtime",
                                _now(),
                                "human_intervention",
                                "accepted Runtime steer command",
                            ],
                        )
                    telemetry_token = set_active_telemetry(
                        LLMTelemetry(
                            db,
                            session_id,
                            max_logical_calls=self._settings.max_llm_calls,
                        )
                    )
                    with (
                        settings_scope(self._settings),
                        stop_scope(self.stop_requested),
                    ):
                        result = apply_intervention(
                            self._case or Case.open(self.case_dir),
                            db,
                            text,
                            base_url=self._settings.llm_base_url,
                            model=self._settings.llm_model,
                            session_id=session_id,
                            settings=self._settings,
                            command_id=command_id,
                        )
                    result_status = (
                        str(result.get("status"))
                        if isinstance(result, dict)
                        else "failed"
                    )
                    if result_status in {"applied", "rejected"}:
                        session_status = "completed"
                        session_reason = str(
                            result.get("reason") or f"Intervention {result_status}"
                        )
                    else:
                        session_reason = str(
                            result.get("reason") or "Intervention did not complete"
                        )
                except InvestigationStopped:
                    session_status = "stopped"
                    session_reason = "Operator requested a safe stop"
                    raise
                except Exception as exc:
                    session_reason = _safe_error(exc, self._settings)
                    raise
                finally:
                    if telemetry_token is not None:
                        reset_active_telemetry(telemetry_token)
                    with db.transaction():
                        db.execute(
                            "UPDATE trace.investigation_sessions SET finished_at = ?, "
                            "status = ?, status_reason = ?, terminal_reason = ? "
                            "WHERE session_id = ?",
                            [
                                _now(),
                                session_status,
                                session_reason,
                                session_reason,
                                session_id,
                            ],
                        )
                    self._active = False
                    self._close_active_db()
            elif operation == "report":
                from forensia.pipeline import run_report

                db = self._open_active_db()
                self._active = True
                try:
                    report_settings = (
                        self._resume_settings()
                        if payload.get("write")
                        else self._settings
                    )
                    with settings_scope(report_settings):
                        result = run_report(
                            self.case_dir,
                            db=db,
                            write=bool(payload.get("write", False)),
                            report_spec=payload.get("report_spec"),
                            template_dir=None,
                            llm_base_url=report_settings.llm_base_url,
                            model=report_settings.llm_model,
                            stop_requested=self.stop_requested,
                        )
                finally:
                    self._active = False
                    self._close_active_db()
            elif operation == "stop":
                pass
            else:
                raise ValueError(f"Unsupported Runtime operation: {operation}")
        except InvestigationStopped:
            status, reason = "interrupted", "Operator requested a safe stop"
        except Exception as exc:
            status, reason = "failed", _safe_error(exc, self._settings)
        if isinstance(result, dict) and result.get("status") == "rejected":
            status, reason = (
                "rejected",
                str(result.get("reason") or "Operation rejected"),
            )
        with self._database(write=True) as db:
            with db.transaction():
                db.execute(
                    "UPDATE trace.runtime_commands SET status = ?, reason = ?, result = ?, updated_at = ? WHERE command_id = ?",
                    [
                        status,
                        reason,
                        json.dumps(result, default=str) if result is not None else None,
                        _now(),
                        command_id,
                    ],
                )
                record_progress_event(
                    db,
                    progress_event(
                        "runtime.command",
                        {
                            "applied": "completed",
                            "rejected": "skipped",
                            "failed": "failed",
                            "interrupted": "interrupted",
                        }[status],
                        severity="success" if status == "applied" else "warning",
                        reason=reason,
                        stage="runtime",
                        summary=f"Runtime command {status}",
                        command_id=command_id,
                        operation=operation,
                    ),
                )
            self._sync_stop_requested(db)
        if command_id in self._resume_after:
            self._resume_after.discard(command_id)
            if status == "applied":
                try:
                    self._investigate(
                        None,
                        self._resume_settings(),
                        None,
                        None,
                        manual_resume=True,
                    )
                except InvestigationStopped:
                    self._record_runtime_interrupted()
                except Exception as exc:
                    self._record_runtime_failure(exc)

    def _resume_settings(self) -> Settings:
        self._settings = load_settings(require_inference=True)
        return self._settings

    def retire_if_idle(self) -> bool:
        """Stop an idle owner so an explicit overwrite can start a fresh case."""
        with self._lock:
            if (
                self._active
                or self._applying
                or self._initial_pending
                or not self._commands.empty()
            ):
                return False
            self._retiring = True
            self._running = False
            self._commands.put(None)
            return True

    def close(self) -> None:
        self._running = False
        self.stop_requested.set()
        self._commands.put(None)
        if (
            self._runner_thread is not None
            and self._runner_thread is not threading.current_thread()
        ):
            self._runner_thread.join()
        self._close_active_db()
