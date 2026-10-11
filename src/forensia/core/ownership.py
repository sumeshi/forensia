"""Per-case OS ownership locks kept outside the case tree."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


def control_dir() -> Path:
    """Private per-user control directory, outside every case directory."""
    uid = (
        str(os.getuid())
        if hasattr(os, "getuid")
        else os.environ.get("USERNAME", "user")
    )
    path = Path(tempfile.gettempdir()) / f"forensia-{uid}"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)
    return path


def _case_key(case_dir: str | Path) -> str:
    return hashlib.sha256(
        os.fsencode(Path(case_dir).expanduser().resolve())
    ).hexdigest()


def lock_path(case_dir: str | Path) -> Path:
    return control_dir() / f"{_case_key(case_dir)}.lock"


def controller_lock_path(case_dir: str | Path) -> Path:
    return control_dir() / f"{_case_key(case_dir)}.controller.lock"


class CaseLock:
    """OS-held per-case lock. The lock file is deliberately outside the case."""

    def __init__(self, case_dir: str | Path):
        self.path = lock_path(case_dir)
        self._file = None

    def acquire(self, *, blocking: bool = False) -> CaseLock:
        if self._file is not None:
            return self
        self._file = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self._file.seek(0)
                if self._file.read(1) == b"":
                    self._file.write(b"\0")
                    self._file.flush()
                self._file.seek(0)
                mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
                msvcrt.locking(self._file.fileno(), mode, 1)
            else:
                import fcntl

                mode = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
                fcntl.flock(self._file.fileno(), mode)
        except OSError, BlockingIOError:
            self._file.close()
            self._file = None
            raise RuntimeError(
                f"Case already has a Runtime owner: {self.path.stem}"
            ) from None
        return self

    def release(self) -> None:
        if self._file is not None:
            if os.name == "nt":
                import msvcrt

                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()
            self._file = None

    def __enter__(self) -> CaseLock:
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()


def case_lock(case_dir: str | Path) -> CaseLock:
    return CaseLock(case_dir)
