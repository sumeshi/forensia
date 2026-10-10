"""Preview the planned investigation TUI from a closed case database.

Run ``uv run python scripts/v2_tui_preview.py CASE_DIR`` after investigation
has finished. This preview opens DuckDB read-only and has no Runtime controls.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensia.core.case import Case
from forensia.db.database import CaseDB

EVENT_LIMIT = 40


def load_projection(case_path: Path) -> tuple[dict, list[dict]]:
    case = Case.open(case_path)
    try:
        with CaseDB(case, read_only=True) as db:
            counts = {
                "findings": int(
                    db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                ),
                "hypotheses": int(
                    db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
                ),
                "open_tasks": int(
                    db.execute(
                        "SELECT COUNT(*) FROM investigation_tasks WHERE status = 'open'"
                    ).fetchone()[0]
                ),
            }
            session = db.execute(
                "SELECT session_id, status, iterations, terminal_reason "
                "FROM trace.investigation_sessions ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
            events = db.execute(
                "SELECT event_index, session_id, kind, status, severity, reason, refs, "
                "iteration, summary, created_at FROM trace.progress_events "
                "ORDER BY event_index DESC LIMIT ?",
                [EVENT_LIMIT],
            ).fetchall()
            event_columns = [column[0] for column in db.conn.description]
    except Exception as exc:
        if "lock" in str(exc).lower():
            raise RuntimeError(
                "Case database is locked; close its writer and retry."
            ) from exc
        raise

    try:
        manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError, OSError:
        manifest = {}
    if not isinstance(manifest, dict):
        manifest = {}
    snapshot = {
        "case_name": manifest.get("case_name") or case.path.name,
        "status": session[1] if session else "no session",
        "iteration": session[2] if session and session[2] is not None else "—",
        "session_id": session[0] if session else "none",
        "terminal_reason": session[3] if session else None,
        **counts,
    }
    return snapshot, [
        dict(zip(event_columns, row, strict=True)) for row in reversed(events)
    ]


def build_preview(
    snapshot: dict, events: list[dict], console_height: int = 25
) -> Layout:
    visible_events = events[-max(1, min(EVENT_LIMIT, console_height - 13)) :]
    header = Table.grid(expand=True)
    header.add_column()
    header.add_row(Text(f"FORENSIA  ·  {snapshot['case_name']}", style="bold cyan"))
    header.add_row(
        Text(
            f"{snapshot['status']}  ·  cycle {snapshot['iteration']}  ·  "
            f"session {str(snapshot['session_id'])[:16]}",
            style="bold",
        )
    )
    header.add_row(
        Text(
            f"Findings {snapshot['findings']} · hypotheses {snapshot['hypotheses']} "
            f"· open tasks {snapshot['open_tasks']}",
            style="bold",
        )
    )
    if snapshot["terminal_reason"]:
        end_reason = str(snapshot["terminal_reason"])
        if len(end_reason) > 54:
            end_reason = end_reason[:51] + "..."
        header.add_row(Text(f"End: {end_reason}", style="dim", no_wrap=True))

    log = Table.grid(padding=(0, 1), expand=True)
    log.add_column(style="dim", width=8, no_wrap=True, overflow="ellipsis")
    log.add_column(style="cyan", width=23, no_wrap=True, overflow="ellipsis")
    log.add_column(width=10, no_wrap=True, overflow="ellipsis")
    log.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
    for event in visible_events:
        created_at = event["created_at"]
        timestamp = created_at.strftime("%H:%M:%S") if created_at else "—"
        refs = event["refs"]
        if isinstance(refs, str):
            refs = yaml.safe_load(refs)
        ref_text = " ".join(f"{key}={value}" for key, value in (refs or {}).items())
        detail = " · ".join(filter(None, [event["summary"], event["reason"], ref_text]))
        severity_style = {
            "success": "green",
            "warning": "yellow",
            "error": "red",
        }.get(event["severity"], "dim")
        log.add_row(
            timestamp,
            event["kind"],
            Text(str(event["status"]), style=severity_style),
            detail,
        )

    prompt = Group(
        Text("Prompt  ·  natural language or /command", style="bold"),
        Text(
            "Disabled in this read-only preview. Runtime controls are not connected.",
            style="dim",
        ),
    )
    layout = Layout()
    layout.split_column(
        Layout(Panel(header, border_style="cyan"), name="header", size=6),
        Layout(
            Panel(
                log,
                title=f"Investigation Log · last {len(visible_events)} events",
                border_style="blue",
            ),
            name="log",
        ),
        Layout(Panel(prompt, border_style="green"), name="prompt", size=5),
    )
    return layout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path, help="closed case directory")
    args = parser.parse_args()
    snapshot, events = load_projection(args.case_dir)
    console = Console()
    console.print(build_preview(snapshot, events, console.height))


if __name__ == "__main__":
    main()
