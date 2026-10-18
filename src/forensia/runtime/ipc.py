from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import time
import uuid
from multiprocessing import AuthenticationError
from multiprocessing.connection import (
    Client,
    Connection,
    Listener,
    answer_challenge,
    deliver_challenge,
)
from pathlib import Path
from typing import Any

from forensia.core.ownership import (
    CaseLock,
    _case_key,
    control_dir,
    controller_lock_path,
)
from forensia.db.database import CaseDBBusyError
from forensia.db.views import DETAIL_KINDS

_MAX_MESSAGE = 1_048_576


def runtime_address(case_dir: str | Path) -> str:
    name = _case_key(case_dir)
    return (
        str(control_dir() / f"{name}.sock")
        if os.name == "posix"
        else rf"\\.\pipe\forensia-{name}"
    )


def _key_path(case_dir: str | Path) -> Path:
    return control_dir() / f"{_case_key(case_dir)}.key"


class RuntimeClient:
    def __init__(self, case_dir: str | Path, *, timeout: float = 5.0):
        self.case_dir = Path(case_dir).expanduser().resolve()
        self.timeout = timeout
        self._controller: str | None = None
        self._controller_lock: CaseLock | None = None
        self._process: subprocess.Popen[bytes] | None = None

    def request(self, request: dict[str, Any]) -> Any:
        kind = request.get("type") if isinstance(request, dict) else None
        if kind not in {
            "snapshot",
            "events",
            "detail",
            "command",
            "status",
            "claim",
            "release",
            "retire",
            "kill",
        }:
            raise ValueError("Unsupported Runtime request")
        if kind in {"command", "kill"} and self._controller:
            request = {**request, "client_id": self._controller}
        payload = json.dumps(
            request, ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(payload) > _MAX_MESSAGE:
            raise ValueError("Runtime request is too large")
        key = _key_path(self.case_dir).read_bytes()
        if os.name == "posix":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            conn = None
            try:
                sock.connect(runtime_address(self.case_dir))
                sock.setblocking(True)
                conn = Connection(sock.detach())
                answer_challenge(conn, key)
                deliver_challenge(conn, key)
            except BaseException:
                if conn is not None:
                    conn.close()
                else:
                    sock.close()
                raise
        else:
            try:
                conn = Client(
                    runtime_address(self.case_dir),
                    family="AF_PIPE" if os.name == "nt" else "AF_UNIX",
                    authkey=key,
                )
            except OSError as exc:
                # Windows reports named-pipe contention as OSError.
                if getattr(exc, "winerror", None) in {121, 231}:
                    raise TimeoutError("Runtime pipe remained busy") from exc
                raise
        try:
            conn.send_bytes(payload)
            if not conn.poll(self.timeout):
                raise TimeoutError("Runtime did not answer before the request timeout")
            response = json.loads(conn.recv_bytes(_MAX_MESSAGE))
        finally:
            conn.close()
        if not isinstance(response, dict):
            raise ValueError("Runtime returned an invalid response")
        if not response.get("ok"):
            if response.get("code") == "case_busy":
                raise CaseDBBusyError(response.get("error", "Case database is busy"))
            raise RuntimeError(response.get("error", "Runtime request failed"))
        return response.get("result")

    def claim_control(self) -> None:
        if self._controller:
            return
        lock = CaseLock(self.case_dir)
        lock.path = controller_lock_path(self.case_dir)
        lock.acquire()
        client_id = uuid.uuid4().hex
        try:
            self.request({"type": "claim", "client_id": client_id})
        except Exception:
            lock.release()
            raise
        self._controller, self._controller_lock = client_id, lock

    def release_control(self) -> None:
        if not self._controller:
            return
        try:
            self.request({"type": "release", "client_id": self._controller})
        finally:
            self._controller = None
            if self._controller_lock:
                self._controller_lock.release()
                self._controller_lock = None

    def shutdown(self, *, force: bool = False, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        startup_id = self.request({"type": "status"})["startup_id"]
        if force:
            self.request({"type": "kill", "startup_id": startup_id})
        else:
            self.request(
                {
                    "type": "command",
                    "operation": "stop",
                    "command_id": f"quit-{uuid.uuid4().hex}",
                    "startup_id": startup_id,
                }
            )
        retired = force
        while True:
            if not retired:
                retired = (
                    self.request({"type": "retire", "startup_id": startup_id}).get(
                        "retired"
                    )
                    is True
                )
            try:
                with CaseLock(self.case_dir):
                    return
            except RuntimeError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Investigation process is still stopping; "
                    "use /kill to force termination or /detach to close only the TUI"
                )
            time.sleep(0.05)

    def __enter__(self) -> RuntimeClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release_control()


def probe_runtime(case_dir: str | Path) -> bool:
    try:
        return (
            RuntimeClient(case_dir, timeout=1).request({"type": "status"}).get("ready")
            is True
        )
    except EOFError, OSError, RuntimeError, ValueError, AttributeError:
        return False


def start_runtime(
    case_dir: str | Path,
    *,
    input_dir: str | Path | None = None,
    overwrite: bool = False,
    settings: dict[str, Any] | None = None,
    system_prompt: str | Path | None = None,
    template: str | Path | None = None,
    rules: str | Path | None = None,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> RuntimeClient:
    requested_case = Path(case_dir).expanduser()
    if overwrite and (requested_case.is_symlink() or requested_case.is_junction()):
        raise ValueError(
            "--overwrite cannot delete a symlinked case directory or junction"
        )
    case = requested_case.resolve()
    if (
        overwrite
        and rules is not None
        and Path(rules).expanduser().resolve().is_relative_to(case)
    ):
        raise ValueError("--rules must be outside the case being overwritten")
    if input_dir is not None and case.exists():
        if not case.is_dir():
            raise ValueError(f"Case output path must be a directory: {case}")
        if (case / "manifest.yaml").is_file() and not overwrite:
            raise ValueError(f"Case already exists at {case}; use overwrite explicitly")
        if any(case.iterdir()) and not (case / "manifest.yaml").is_file():
            raise ValueError(
                f"Output directory already contains data and is not a case: {case}"
            )
    # Acquisition and conversion can outlast the IPC startup deadline.
    # Finish before spawning, and validate before any case overwrite.
    rules_bundle = None
    if input_dir is not None:
        from forensia.knowledge.sigma.setup import prepare_rule_bundle

        rules_bundle = prepare_rule_bundle(Path(rules) if rules is not None else None)
    if probe_runtime(case):
        if not overwrite:
            raise RuntimeError(f"Runtime is already active for {case}")
        if (
            not RuntimeClient(case, timeout=1)
            .request({"type": "retire"})
            .get("retired")
        ):
            raise RuntimeError(f"Runtime is busy and cannot be overwritten: {case}")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not probe_runtime(case):
                try:
                    with CaseLock(case):
                        break
                except RuntimeError:
                    pass
            time.sleep(0.05)
        else:
            raise TimeoutError(f"Runtime did not retire for overwrite: {case}")
    startup_id = uuid.uuid4().hex
    args = [sys.executable, "-m", "forensia.runtime", str(case)]
    args.extend(("--startup-id", startup_id))
    for name, value in (
        ("input-dir", input_dir),
        ("system-prompt", system_prompt),
        ("template", template),
        ("rules", rules_bundle),
    ):
        if value is not None:
            args.extend((f"--{name}", str(Path(value).expanduser().resolve())))
    if overwrite:
        args.append("--overwrite")
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    options: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
        "cwd": str(cwd) if cwd else None,
        "env": child_env,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        ) | getattr(subprocess, "DETACHED_PROCESS", 0)
    else:
        options["start_new_session"] = True
    process = subprocess.Popen(args, **options)
    try:
        startup = json.dumps(settings or {}, separators=(",", ":")).encode()
        if len(startup) > _MAX_MESSAGE:
            raise ValueError("Runtime settings are too large")
        assert process.stdin is not None
        process.stdin.write(startup)
        process.stdin.close()
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    client = RuntimeClient(case)
    client._process = process
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            error = (
                process.stderr.read(4096).decode(errors="replace").strip()
                if process.stderr
                else ""
            )
            raise RuntimeError(
                error or f"Runtime exited during startup ({process.returncode})"
            )
        if probe_runtime(case):
            if client.request({"type": "status"}).get("startup_id") == startup_id:
                if process.stderr:
                    process.stderr.close()
                return client
            process.terminate()
            process.wait(timeout=2)
            raise RuntimeError(f"Another Runtime won startup for {case}")
        time.sleep(0.1)
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    error = (
        process.stderr.read(4096).decode(errors="replace").strip()
        if process.stderr
        else ""
    )
    raise TimeoutError(error or f"Runtime did not become ready for {case}")


class RuntimeServer:
    """Local JSON IPC front end; all case semantics belong to RuntimeEngine."""

    def __init__(
        self,
        case_dir: str | Path,
        engine: Any,
        lock: CaseLock,
        startup_id: str | None = None,
    ):
        self.case_dir = Path(case_dir).resolve()
        self.engine = engine
        self.lock = lock
        self.startup_id = startup_id or secrets.token_hex(16)
        self.controller_id: str | None = None
        self._running = True

    def serve_forever(self) -> None:
        address = runtime_address(self.case_dir)
        key_path = _key_path(self.case_dir)
        key = secrets.token_bytes(32)
        key_path.write_bytes(key)
        if os.name == "posix":
            key_path.chmod(0o600)
            Path(address).unlink(missing_ok=True)
        listener = Listener(
            address, family="AF_PIPE" if os.name == "nt" else "AF_UNIX", authkey=key
        )
        if os.name == "posix":
            Path(address).chmod(0o600)
        null_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_fd, 2)
        os.close(null_fd)
        try:
            while self._running:
                try:
                    conn = listener.accept()
                except AuthenticationError, OSError, EOFError:
                    continue
                with conn:
                    retire = False
                    kill = False
                    try:
                        if not conn.poll(10):
                            continue
                        request = json.loads(conn.recv_bytes(_MAX_MESSAGE))
                        result = self._dispatch(request)
                        retire = (
                            isinstance(request, dict)
                            and request.get("type") == "retire"
                            and result.get("retired") is True
                        )
                        kill = request.get("type") == "kill"
                        response = {"ok": True, "result": result}
                    except CaseDBBusyError as exc:
                        response = {"ok": False, "code": "case_busy", "error": str(exc)}
                    except Exception as exc:
                        response = {"ok": False, "error": str(exc)}
                    encoded = json.dumps(
                        response, ensure_ascii=False, separators=(",", ":")
                    ).encode()
                    if len(encoded) > _MAX_MESSAGE:
                        encoded = json.dumps(
                            {"ok": False, "error": "Runtime response is too large"}
                        ).encode()
                    try:
                        conn.send_bytes(encoded)
                    except OSError:
                        pass
                    if kill:
                        # An explicit kill must not wait for the worker or DB lock.
                        os._exit(1)
                    if retire:
                        self._running = False
        finally:
            listener.close()
            if os.name == "posix":
                Path(address).unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)
            self.engine.close()
            self.lock.release()

    def _dispatch(self, req: Any) -> Any:
        if not isinstance(req, dict):
            raise ValueError("Request must be an object")
        if req.get("startup_id") is not None and req["startup_id"] != self.startup_id:
            raise RuntimeError(
                "Runtime was replaced; reconnect before sending commands"
            )
        kind = req.get("type")
        if kind == "claim":
            client_id = req.get("client_id")
            if not isinstance(client_id, str) or len(client_id) != 32:
                raise ValueError("Invalid controller ID")
            self.controller_id = client_id
            return {"claimed": True}
        if kind == "release":
            if req.get("client_id") != self.controller_id:
                raise ValueError("Runtime controller mismatch")
            self.controller_id = None
            return {"released": True}
        if kind == "status":
            return {"ready": True, "startup_id": self.startup_id}
        if kind == "retire":
            return {"retired": bool(self.engine.retire_if_idle())}
        if kind == "kill":
            if (
                self.controller_id is not None
                and req.get("client_id") != self.controller_id
            ):
                raise RuntimeError("Another TUI currently controls this Runtime")
            return {"killed": True}
        if kind == "snapshot":
            return self.engine.snapshot()
        if kind == "events":
            after_index, limit = req.get("after_index", 0), req.get("limit", 100)
            if (
                type(after_index) is not int
                or type(limit) is not int
                or after_index < 0
                or not 1 <= limit <= 100
            ):
                raise ValueError("Invalid event page")
            return self.engine.events(after_index=after_index, limit=limit)
        if kind == "detail":
            detail_kind, item_id, limit, offset = (
                req.get("kind"),
                req.get("id"),
                req.get("limit", 100),
                req.get("offset", 0),
            )
            if (
                detail_kind not in DETAIL_KINDS
                or not isinstance(item_id, str)
                or not item_id
                or len(item_id) > 256
                or type(limit) is not int
                or not 1 <= limit <= 100
                or type(offset) is not int
                or offset < 0
            ):
                raise ValueError("Invalid detail request")
            return self.engine.detail(detail_kind, item_id, limit=limit, offset=offset)
        if kind == "command":
            if (
                self.controller_id is not None
                and req.get("client_id") != self.controller_id
            ):
                raise RuntimeError("Another TUI currently controls this Runtime")
            command_id, operation, payload = (
                req.get("command_id"),
                req.get("operation"),
                req.get("payload", {}),
            )
            if (
                not isinstance(command_id, str)
                or not command_id
                or len(command_id) > 128
                or operation not in {"stop", "resume", "add", "report", "steer"}
                or not isinstance(payload, dict)
            ):
                raise ValueError("Invalid command")
            return self.engine.command(command_id, operation, payload)
        raise ValueError("Unsupported Runtime request")
