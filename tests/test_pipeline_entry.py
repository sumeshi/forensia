"""Kernel entry boundary (V2-02).

The display-agnostic pipeline entry is what both the CLI and a future TUI
import to run a case. Importing it must not require a terminal presentation
library or an HTTP server: those belong to the display adapters.
"""

from __future__ import annotations

import os
import subprocess
import sys

FORBIDDEN = ("typer", "click", "rich", "fastapi", "uvicorn")


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
