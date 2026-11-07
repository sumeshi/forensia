"""Textual client for a single case Runtime."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from multiprocessing import AuthenticationError
from pathlib import Path
from typing import Any

from rich.style import Style
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, RichLog, Rule, Static

from forensia.core.case import Case
from forensia.core.ownership import CaseLock, controller_lock_path
from forensia.db.database import CaseDB, CaseDBBusyError
from forensia.db.views import DETAIL_KINDS, case_detail, case_events, case_snapshot
from forensia.runtime import RuntimeClient, probe_runtime, start_runtime

_PAGE_SIZE = 40
_SEVERITY_COLORS = {
    "info": "#67e8f9",
    "success": "#86efac",
    "warning": "#fbbf24",
    "error": "#f87171",
}
_HELP = """Commands

Natural language          Steer the investigation
/stop                    Stop the investigation
/resume                  Resume a stopped investigation
/add PATH                Add acquired evidence
/report                  Export accepted report sections
/report --write          Update and export the report
/detail KIND ID          Open a record (e.g. finding, hypothesis, evidence)
/detail event INDEX      Open a log event and its references
/trace HYPOTHESIS_ID      Follow plans, execution, checks and decisions
/activity                Show investigation activity (default)
/logs                    Show compact log events
/more                    Read the next detail page
/older, /newer           Browse earlier events / follow current events
/detach                  Close the TUI; keep the Runtime alive
/quit                    Stop the investigation and exit (Ctrl+Q)
/kill                    Force termination; interrupt unfinished work

Click a timestamp or record reference to inspect the saved record.
Details offer Back and Raw/Summary; /trace includes previous sessions.
F1 opens Help. Escape closes this window.
"""


def _read(
    case: Case, client: RuntimeClient | None, after_index: int | None, limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if client is not None:
        snapshot = client.request({"type": "snapshot"})
        if after_index is None:
            after_index = max(0, snapshot["event_highwater"] - limit)
        return snapshot, client.request(
            {"type": "events", "after_index": after_index, "limit": limit}
        )
    with CaseDB(case, read_only=True) as db:
        snapshot = case_snapshot(case, db)
        if after_index is None:
            after_index = max(0, snapshot["event_highwater"] - limit)
        return snapshot, case_events(db, after_index, limit)


def _read_detail(
    case: Case, client: RuntimeClient | None, kind: str, item_id: str, offset: int = 0
) -> Any:
    if client is not None:
        return client.request(
            {
                "type": "detail",
                "kind": kind,
                "id": item_id,
                "limit": 50,
                "offset": offset,
            }
        )
    with CaseDB(case, read_only=True) as db:
        return case_detail(db, kind, item_id, 50, offset=offset)


def _command(value: str) -> tuple[str, dict[str, Any]]:
    if not value.startswith("/"):
        return "steer", {"text": value}
    stripped = value.strip()
    if stripped.lower().startswith("/add "):
        input_dir = stripped[5:].strip()
        if input_dir:
            return "add", {"input_dir": input_dir}
    parts = value.strip().split(maxsplit=2)
    command = parts[0].lower()
    if command == "/help":
        return "help", {}
    if command == "/detail" and len(parts) == 3:
        return "detail", {"kind": parts[1], "id": parts[2]}
    if command == "/detail" and len(parts) == 1:
        return "detail_close", {}
    if command == "/trace" and len(parts) == 2:
        return "detail", {"kind": "timeline", "id": parts[1]}
    if command in {"/activity", "/logs"} and len(parts) == 1:
        return command[1:], {}
    if command in {"/older", "/newer", "/more"} and len(parts) == 1:
        return command[1:], {}
    if command in {"/stop", "/resume"} and stripped.lower() == command:
        return command[1:], {}
    if (
        command == "/report"
        and len(parts) <= 2
        and (len(parts) == 1 or parts[1] == "--write")
    ):
        return "report", {"write": len(parts) == 2}
    if command in {"/detach", "/quit", "/kill"} and stripped.lower() == command:
        return command[1:], {}
    raise ValueError("Use /help to see supported commands")


def _case_status(snapshot: dict[str, Any]) -> str:
    session = snapshot.get("session") or {}
    state = snapshot.get("state") or {}
    work = snapshot.get("current_work") or {}
    if work.get("status") == "running":
        return "running"
    pipeline = snapshot.get("pipeline") or {}
    return (
        pipeline.get("status")
        or session.get("status")
        or state.get("status")
        or "unknown"
    )


def _format_header(snapshot: dict[str, Any]) -> Text:
    status = _case_status(snapshot)
    session = snapshot.get("session") or {}
    work = snapshot.get("current_work") or snapshot.get("pipeline") or session
    elapsed = snapshot.get("elapsed_seconds")
    duration = "—"
    if elapsed is not None:
        hours, seconds = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(seconds, 60)
        duration = f"{hours:02}:{minutes:02}:{seconds:02}"
    text = Text(snapshot.get("case_name", "case"), style="bold cyan")
    text.append("  ·  ")
    text.append(
        status,
        style=_SEVERITY_COLORS[
            "error"
            if status == "failed"
            else "success"
            if status in {"running", "completed"}
            else "warning"
        ],
    )
    if work:
        text.append(f" / {work.get('stage') or work.get('phase') or 'working'}")
    provider_wait = session.get("provider_wait") or {}
    if provider_wait.get("stop_requested"):
        text.append(
            " · stop accepted; waiting for provider"
            if provider_wait.get("waiting")
            else " · stop accepted",
            style="yellow",
        )
    elif provider_wait.get("waiting"):
        text.append(" · waiting for provider", style="yellow")
    text.append(f"  ·  elapsed {duration}", style="white")
    return text


def _format_sidebar(snapshot: dict[str, Any]) -> Text:
    counts = snapshot.get("counts") or {}
    usage = snapshot.get("budget_usage") or {}
    remaining = snapshot.get("budget_remaining_llm_calls")
    limit = snapshot.get("budget_limit_llm_calls")
    text = Text()
    text.append("INVESTIGATION\n", style="bold cyan")
    for label, key in (
        ("Findings", "findings"),
        ("Hypotheses", "hypotheses"),
        ("Open tasks", "open_tasks"),
    ):
        count = counts.get(key)
        text.append(f"{label:<12} ", style="white")
        text.append(f"{count:,}\n" if count is not None else "—\n", style="bold")
    for status, count in (counts.get("hypothesis_statuses") or {}).items():
        text.append(f"  {status}: {count:,}\n", style="dim")
    text.append("\nLLM\n", style="bold cyan")
    text.append(f"Calls        {usage.get('logical_call_count', '—')}\n", style="white")
    text.append(
        f"{remaining} calls remaining"
        if remaining is not None
        else ("Unlimited calls" if limit == 0 else "Call budget unknown"),
        style="dim",
    )
    for label, prefix in (("Actual", "actual"), ("Estimate", "estimated")):
        values = [
            usage.get(f"{prefix}_{direction}_tokens")
            for direction in ("input", "output")
        ]
        if label == "Actual" or any(value is not None for value in values):
            tokens = " / ".join(
                f"{value:,}" if value is not None else "?" for value in values
            )
            text.append(f"\n{label} tokens\n  {tokens} (in / out)", style="white")
    if usage.get("unknown_input_usage_attempts") or usage.get(
        "unknown_output_usage_attempts"
    ):
        text.append("\nSome usage unknown", style="yellow")
    if _case_status(snapshot) != "running":
        session = snapshot.get("session") or {}
        state = snapshot.get("state") or {}
        pipeline = snapshot.get("pipeline")
        reason = (
            pipeline.get("reason")
            if pipeline
            else (session.get("terminal_reason") or state.get("stop_reason"))
        )
        if reason:
            text.append(f"\n\nReason: {reason}", style="yellow")
    return text


def _local_time(value: Any) -> str:
    if not value:
        return "—"
    instant = datetime.fromisoformat(str(value))
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return instant.astimezone().strftime("%H:%M:%S")


def _format_event(event: dict[str, Any]) -> Text:
    color = _SEVERITY_COLORS.get(event.get("severity"), "white")
    text = Text()
    text.append(
        _local_time(event.get("created_at")),
        style=Style(
            color="#9ca3af",
            underline=True,
            meta={"@click": f"app.show_event({event['event_index']})"},
        ),
    )
    text.append(f"  {event.get('status', ''):<11}", style=color)
    text.append(f" {event.get('kind', 'event')}  ", style="dim")
    summary = " ".join(str(event.get("summary") or event.get("reason") or "").split())
    text.append(summary[:180] + ("…" if len(summary) > 180 else ""), style=color)
    return text


def _record_link(kind: str, item_id: Any, label: str) -> Text:
    """Use literal action arguments; record content is never Rich markup."""
    text = Text(label)
    if kind in DETAIL_KINDS and item_id is not None:
        text.stylize(
            Style(
                color="#67e8f9",
                underline=True,
                meta={"@click": f"app.show_record({kind!r}, {str(item_id)!r})"},
            )
        )
    return text


def _short(value: Any, limit: int = 500) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    value = " ".join(str(value).split())
    return value[:limit] + (
        "… (open record for full text)" if len(value) > limit else ""
    )


def _format_activity(event: dict[str, Any]) -> Text:
    """Present recorded intent and host outcomes without inventing narration."""
    text = _format_event(event)
    refs = event.get("refs") or {}
    payload = event.get("payload") or event.get("attributes") or {}
    audit = payload.get("audit") or {}
    if not isinstance(audit, dict):
        audit = {}
    if hypothesis_id := refs.get("hypothesis_id"):
        text.append("\n  ")
        text.append(_record_link("timeline", hypothesis_id, f"Trace {hypothesis_id}"))
    if event.get("session_id"):
        text.append(f"  session {_short(event['session_id'], 100)}", style="dim")
    if audit.get("origin"):
        text.append(f"\n  Recorded by: {_short(audit['origin'])}", style="dim")
    for key, label in (
        ("purpose", "Purpose"),
        ("test_intent", "Verification intent"),
        ("fallback_phase", "Fallback search"),
        ("source_rule_id", "Source rule"),
        ("returned_count", "Rows returned"),
        ("retrieval_outcome", "Retrieval assessment"),
        ("truncated", "Truncated"),
        ("proposed_verdict", "Checker proposal"),
        ("report_text", "Check explanation"),
        ("role", "Evidence role"),
        ("matched_conditions", "Matched conditions"),
        ("machine_status", "Evidence sufficiency"),
        ("reasons", "Sufficiency reasons"),
        ("missing_requirements", "Missing requirements"),
        ("human_review_required", "Human review required"),
        ("verdict", "Host verdict"),
        ("allowed", "Settlement allowed"),
        ("gates_passed", "Passed conditions"),
        ("gates_failed", "Unmet conditions"),
        ("reason", "Reason"),
    ):
        if key in audit:
            value = "unknown" if audit[key] is None else _short(audit[key])
            text.append(f"\n  {label}: {value}")
    if event.get("reason") and event["reason"] != audit.get("reason"):
        text.append(f"\n  Reason: {_short(event['reason'])}")
    for key, kind, label in (
        ("plan_step_id", "step", "Plan"),
        ("execution_step_id", "step", "Execution start"),
        ("receipt_id", "query_receipt", "Query result"),
        ("check_step_id", "step", "Check"),
        ("assessment_id", "assessment", "Evidence assessment"),
        ("sufficiency_step_id", "step", "Sufficiency"),
        ("settlement_ref", "step", "Settlement"),
    ):
        if refs.get(key):
            text.append("\n  ")
            text.append(_record_link(kind, refs[key], label))
    if refs.get("step_id") and refs["step_id"] not in {
        refs.get(key)
        for key in (
            "plan_step_id",
            "execution_step_id",
            "check_step_id",
            "sufficiency_step_id",
            "settlement_ref",
        )
    }:
        text.append("\n  ")
        text.append(_record_link("step", refs["step_id"], "Stage details"))
    return text


def _format_detail(detail: Any, *, raw: bool = False) -> Text:
    if not isinstance(detail, dict):
        return Text(json.dumps(detail, ensure_ascii=False, indent=2, default=str))
    text = Text()
    if detail.get("kind") == "timeline" and not raw:
        text.append(f"Investigation trace · {detail['id']}\n", style="bold cyan")
        text.append(
            "Saved history; past decisions may have been superseded.\n", style="dim"
        )
        text.append(
            f"Records {detail['offset'] + 1 if detail['items'] else 0}–"
            f"{detail['offset'] + len(detail['items'])} of {detail['total_items']}\n"
        )
        for item in detail["items"]:
            text.append(
                f"\n{item.get('created_at') or 'unknown time'} UTC"
                f" · session {item.get('session_id') or 'unknown'}\n",
                style="dim",
            )
            text.append(
                _record_link(
                    item["kind"], item["id"], item.get("phase") or item["kind"]
                )
            )
            text.append(f"  {item.get('summary') or ''}\n")
            _append_related(text, item.get("related_records") or [])
    elif "total_chars" in detail:
        text.append(detail["text"])
    elif not raw and "event_index" in detail:
        text.append(_format_activity(detail))
        text.append(f"\n\nSaved summary: {detail.get('summary') or 'none recorded'}")
    elif (
        not raw
        and "step_id" in detail
        and isinstance(detail.get("input_json"), dict)
        and isinstance(detail.get("output_json"), dict)
        and (
            detail.get("phase")
            in {
                "plan-hypothesis",
                "query-execution",
                "do",
                "check",
                "sufficiency",
                "settlement",
            }
            or "tool_receipt" in detail["output_json"]
        )
    ):
        text.append(
            f"Saved {detail.get('phase') or 'query'} record\n", style="bold cyan"
        )
        text.append(
            f"Session: {detail.get('session_id') or 'unknown'}\n"
            f"Hypothesis: {detail.get('hypothesis_id') or 'case-wide'}\n"
            f"Recorded: {detail.get('created_at') or 'unknown'} UTC\n",
            style="dim",
        )
        step_input = detail.get("input_json") or {}
        step_output = detail.get("output_json") or {}
        query = (
            step_output.get("materialized_query")
            or step_input.get("planned_query")
            or {}
        )
        if detail.get("phase") == "query-execution":
            text.append(
                "\nExecution was about to start. Open the related result to establish its outcome.\n",
                style="dim",
            )
        if plan_status := step_output.get("_plan_status"):
            text.append(
                f"\nQuery admitted: {plan_status.get('query_materialized', 'unknown')}\n"
            )
            if plan_status.get("stop_reason"):
                text.append(f"Plan stopped: {plan_status['stop_reason']}\n")
        for key, label in (
            ("purpose", "Purpose"),
            ("test_intent", "Verification intent"),
        ):
            if query.get(key):
                text.append(f"\n{label}: {query[key]}\n")
        if receipt := step_output.get("tool_receipt"):
            text.append("\nRecorded execution result\n", style="bold")
            text.append(json.dumps(receipt, ensure_ascii=False, indent=2, default=str))
            text.append(
                "\nEvidence links open current case records. Historical receipts preserve the original references.\n",
                style="dim",
            )
        if "check_verdict" in step_output:
            text.append(
                f"\nChecker proposal: {step_output['check_verdict']}\n", style="bold"
            )
            text.append(
                str(step_output.get("check_summary") or "No explanation recorded")
            )
        if assessment := step_output.get("assessment"):
            text.append("\n\nEvidence assessment\n", style="bold")
            text.append(
                json.dumps(assessment, ensure_ascii=False, indent=2, default=str)
            )
        if settlement := step_output.get("settlement"):
            text.append("\nHost settlement\n", style="bold")
            for key in ("verdict", "allowed", "reason", "gates_passed", "gates_failed"):
                if key in settlement:
                    text.append(f"{key.replace('_', ' ')}: {settlement[key]}\n")
        if "machine_status" in step_output:
            text.append("\nEvidence sufficiency\n", style="bold")
            text.append(
                json.dumps(step_output, ensure_ascii=False, indent=2, default=str)
            )
        receipt = step_output.get("tool_receipt") or {}
        executed_sql = step_input.get("host_executed_sql") or (
            receipt.get("arguments") or {}
        ).get("host_executed_sql")
        if executed_sql:
            text.append("\n\nSQL submitted for execution\n", style="bold")
            text.append(str(executed_sql))
        elif query.get("sql"):
            text.append("\n\nPlanned SQL\n", style="bold")
            text.append(str(query["sql"]))
        text.append("\n\nRaw / Summary opens the complete saved fields.", style="dim")
    else:
        text.append(json.dumps(detail, ensure_ascii=False, indent=2, default=str))
    if detail.get("related_records"):
        text.append("\n\nRelated records\n", style="bold cyan")
        _append_related(text, detail["related_records"])
    return text


def _append_related(text: Text, records: list[dict[str, Any]]) -> None:
    for record in records:
        text.append("  ")
        text.append(
            _record_link(
                record["kind"],
                record["id"],
                f"{record['label']}: {record['id']}"
                if record.get("label")
                else record["id"],
            )
        )
        text.append("\n")


class InfoWindow(ModalScreen[None]):
    BINDINGS = [("escape", "dismiss", "Close")]
    DEFAULT_CSS = """
    InfoWindow { align: center middle; background: $background 75%; }
    #info-window { width: 85%; height: 85%; border: round cyan; padding: 1; background: $surface; }
    #info-scroll { height: 1fr; }
    #info-content { height: auto; }
    #info-buttons { height: 3; align-horizontal: right; }
    #info-buttons Button { margin-left: 1; min-width: 8; width: auto; }
    """

    def __init__(self, title: str, content: Text, more: bool = False):
        super().__init__()
        self._window_title = title
        self._content = content
        self._more = more

    def compose(self) -> ComposeResult:
        with Vertical(id="info-window"):
            with VerticalScroll(id="info-scroll"):
                yield Static(self._content, id="info-content")
            with Horizontal(id="info-buttons"):
                yield Button("Back", id="info-back")
                yield Button("Raw / Summary", id="info-raw")
                yield Button("More", id="info-more")
                yield Button("Close", id="info-close", variant="primary")

    def on_mount(self) -> None:
        self.set_content(self._window_title, self._content, self._more)

    def set_content(self, title: str, content: Text, more: bool = False) -> None:
        self.query_one("#info-window").border_title = title
        self.query_one("#info-content", Static).update(content)
        self.query_one("#info-scroll", VerticalScroll).scroll_home(animate=False)
        self.query_one("#info-more", Button).display = more
        self.query_one("#info-back", Button).display = (
            bool(self.app._detail_history) and title != "Help"
        )
        self.query_one("#info-raw", Button).display = title != "Help"

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "info-more":
            await self.app._more_detail()
        elif event.button.id == "info-back":
            self.app._back_detail()
        elif event.button.id == "info-raw":
            self.app._detail_raw = not self.app._detail_raw
            self.app._show_detail()
        else:
            self.dismiss()


class CaseApp(App[None]):
    CSS = """
    Screen { layout: vertical; }
    #case-state { height: 3; padding: 0 1; border-bottom: solid cyan; content-align: left middle; }
    #body { height: 1fr; }
    #sidebar { width: 30; height: 1fr; padding: 1; border-left: solid $primary-darken-2; overflow-y: auto; }
    #investigation-state, #connections { height: auto; }
    #event-log { width: 1fr; height: 1fr; padding: 0 1; border: round $primary-darken-2; }
    #prompt { height: 3; }
    .narrow #body { layout: vertical; }
    .narrow #sidebar { width: 1fr; height: auto; max-height: 12; border-left: none; border-top: solid $primary-darken-2; }
    """
    TITLE = "FORENSIA"
    BINDINGS = [
        ("f1", "help", "Help"),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]
    HORIZONTAL_BREAKPOINTS = [(0, "narrow"), (90, "wide")]

    def __init__(self, case: Case):
        super().__init__()
        self.case = case
        self.client: RuntimeClient | None = (
            RuntimeClient(case.path) if probe_runtime(case.path) else None
        )
        self._stopped_lock: CaseLock | None = None
        self._runtime_lost = False
        self._events: list[dict[str, Any]] = []
        self._highwater = 0
        self._cursor = 0
        self._following = True
        self._detail: Any = None
        self._detail_location: tuple[str, str, int] | None = None
        self._detail_history: list[tuple[tuple[str, str, int], Any]] = []
        self._detail_raw = False
        self._activity = True
        self._pending_commands: set[str] = set()
        self._rendered_event_indexes: tuple[int, ...] | None = None
        self._log_width = 0
        self._last_read_error: tuple[type[Exception], str] | None = None
        self._last_view_at: str | None = None
        self._closed = False
        self._owns_control = False

    def compose(self) -> ComposeResult:
        self._header = Static("Opening case…", id="case-state")
        self._sidebar = Static("", id="investigation-state")
        self._connections = Static("Opening database…", id="connections")
        self._log = RichLog(
            id="event-log",
            min_width=1,
            wrap=True,
            markup=False,
            highlight=False,
            max_lines=4000,
        )
        self._prompt = Input(
            placeholder="Command or steering instruction · F1 Help", id="prompt"
        )
        yield self._header
        with Horizontal(id="body"):
            yield self._log
            with Vertical(id="sidebar"):
                yield self._sidebar
                yield Rule()
                yield self._connections
        yield self._prompt
        yield Footer()

    def _notice(self, message: str, severity: str = "info") -> None:
        text = Text(datetime.now().strftime("%H:%M:%S"), style="dim")
        text.append(f"  UI  {message}", style=_SEVERITY_COLORS[severity])
        self._log.write(text)

    def _connection_state(
        self, read_status: str = "OK", *, severity: str = "success"
    ) -> None:
        text = Text()
        text.append("CONNECTION\n", style="bold cyan")
        runtime = (
            "unavailable"
            if self._runtime_lost
            else ("attached" if self.client else "saved case")
        )
        text.append(
            f"Runtime  {runtime}\n", style="yellow" if self._runtime_lost else "white"
        )
        text.append("DB       DuckDB\n", style="white")
        if read_status != "OK":
            read_status += " (stale)" if self._last_view_at else " (no view)"
        text.append(f"Read     {read_status}\n", style=_SEVERITY_COLORS[severity])
        text.append(
            str(self.case.database_path.relative_to(self.case.path)), style="dim"
        )
        if self._last_view_at:
            text.append(f"\nUpdated  {_local_time(self._last_view_at)}", style="dim")
        self._connections.update(text)
        self._connections.tooltip = str(self.case.database_path)

    def _open_window(self, title: str, content: Text, more: bool = False) -> None:
        if isinstance(self.screen, InfoWindow):
            self.screen.set_content(title, content, more)
        else:
            self.push_screen(InfoWindow(title, content, more))

    def action_help(self) -> None:
        self._open_window("Help", Text(_HELP))

    async def action_quit(self) -> None:
        await self._quit()

    async def _quit(self, *, force: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        if self.client is not None and self._owns_control:
            self._notice(
                "Terminating investigation…" if force else "Stopping investigation…"
            )
            try:
                await asyncio.to_thread(self.client.shutdown, force=force)
            except Exception as exc:
                self._closed = False
                self._notice(f"Unable to exit: {exc}", "error")
                return
        elif self._owns_control:
            try:
                with CaseLock(self.case.path):
                    pass
            except RuntimeError:
                self._closed = False
                self._notice(
                    "Process exit is unconfirmed: Runtime is unavailable. "
                    "Reconnect with attach or use /detach to close only the TUI.",
                    "error",
                )
                return
        self.exit()

    def _show_detail(self) -> None:
        if self._detail is None:
            self._notice("No matching detail", "warning")
            return
        more = (
            isinstance(self._detail, dict)
            and self._detail.get("next_offset") is not None
        )
        title = "Detail"
        if self._detail_location:
            title += f" · {self._detail_location[0]} · {self._detail_location[1]}"
        self._open_window(
            title, _format_detail(self._detail, raw=self._detail_raw), more
        )

    async def action_show_record(self, kind: str, item_id: str) -> None:
        try:
            detail = await asyncio.to_thread(
                _read_detail, self.case, self.client, kind, item_id
            )
            if detail is None:
                self._notice("No matching saved record", "warning")
                return
            if self._detail_location is not None:
                self._detail_history.append((self._detail_location, self._detail))
                self._detail_history = self._detail_history[-50:]
            self._detail_location = (kind, item_id, 0)
            self._detail = detail
            self._detail_raw = False
            self._show_detail()
        except Exception as exc:
            self._notice(f"Unable to read detail: {exc}", "error")

    def _back_detail(self) -> None:
        if self._detail_history:
            self._detail_location, self._detail = self._detail_history.pop()
            self._detail_raw = False
            self._show_detail()

    async def _more_detail(self) -> None:
        if (
            not isinstance(self._detail, dict)
            or self._detail.get("next_offset") is None
        ):
            self._notice("No further detail page", "warning")
            return
        try:
            detail = await asyncio.to_thread(
                _read_detail,
                self.case,
                self.client,
                self._detail["kind"],
                self._detail["id"],
                self._detail["next_offset"],
            )
            if self._detail_location is not None:
                self._detail_history.append((self._detail_location, self._detail))
                self._detail_history = self._detail_history[-50:]
            self._detail_location = (
                self._detail["kind"],
                self._detail["id"],
                self._detail["next_offset"],
            )
            self._detail = detail
            self._show_detail()
        except Exception as exc:
            self._notice(f"Unable to read detail: {exc}", "error")

    async def action_show_event(self, event_index: int) -> None:
        await self.action_show_record("event", str(event_index))

    async def on_mount(self) -> None:
        try:
            if self.client:
                await asyncio.to_thread(self.client.claim_control)
            else:
                lock = CaseLock(self.case.path)
                lock.path = controller_lock_path(self.case.path)
                await asyncio.to_thread(lock.acquire)
                self._stopped_lock = lock
            self._owns_control = True
        except Exception as exc:
            self._notice(f"Unable to control this case: {exc}", "error")
            self._header.update(
                Text(f"{self.case.path.name} · control unavailable", style="red")
            )
            self._connection_state("unavailable", severity="error")
            self._prompt.disabled = True
            return
        await self._refresh()
        self.set_interval(0.5, self._tick)
        self._prompt.focus()

    async def _tick(self) -> None:
        if not self._closed:
            await self._refresh()

    async def _refresh(self) -> None:
        try:
            after = (
                self._events[-1]["event_index"]
                if self._following and self._events
                else (self._highwater or None)
            )
            snapshot, latest = await asyncio.to_thread(
                _read, self.case, self.client, after, _PAGE_SIZE
            )
            notices = []
            if self._pending_commands and self.client:
                for command_id in tuple(self._pending_commands):
                    receipt = await asyncio.to_thread(
                        self.client.request,
                        {
                            "type": "detail",
                            "kind": "command_receipt",
                            "id": command_id,
                            "limit": 10,
                        },
                    )
                    if receipt and receipt.get("status") in {
                        "applied",
                        "failed",
                        "rejected",
                        "interrupted",
                    }:
                        severity = (
                            "success" if receipt["status"] == "applied" else "warning"
                        )
                        if receipt["status"] == "failed":
                            severity = "error"
                        notices.append(
                            (
                                f"Command {receipt['status']}: {receipt.get('reason') or receipt.get('operation')}",
                                severity,
                            )
                        )
                        self._pending_commands.discard(command_id)
        except Exception as exc:
            read_status, severity = "unavailable", "error"
            if isinstance(exc, CaseDBBusyError):
                read_status, severity = "busy", "warning"
            elif isinstance(exc, TimeoutError):
                read_status, severity = "timeout", "warning"
            elif self.client is not None and isinstance(
                exc, (EOFError, OSError, AuthenticationError)
            ):
                self._runtime_lost = True
                try:
                    await asyncio.to_thread(self.client.release_control)
                except Exception:
                    pass
                self.client = None
            self._connection_state(read_status, severity=severity)
            error = (type(exc), str(exc))
            if error != self._last_read_error:
                self._notice(
                    f"Read {read_status}; retaining last view: {exc}", severity
                )
            self._last_read_error = error
            return
        self._last_read_error = None
        self._highwater = int(snapshot.get("event_highwater") or self._highwater)
        if self._following:
            self._events.extend(latest)
            self._events = self._events[-_PAGE_SIZE:]
        self._header.update(_format_header(snapshot))
        self._sidebar.update(_format_sidebar(snapshot))
        self._last_view_at = snapshot.get("generated_at")
        self._connection_state()
        width = self._log.scrollable_content_region.width
        if width != self._log_width:
            self._rendered_event_indexes = None
            self._log_width = width
        event_indexes = tuple(int(event["event_index"]) for event in self._events)
        if event_indexes != self._rendered_event_indexes:
            previous = self._rendered_event_indexes
            if (
                previous is None
                or not self._following
                or (event_indexes and previous and event_indexes[-1] < previous[-1])
            ):
                self._log.clear()
                events = self._events
            else:
                last = previous[-1] if previous else 0
                events = [
                    event for event in self._events if event["event_index"] > last
                ]
            for event in events:
                self._log.write(
                    _format_activity(event) if self._activity else _format_event(event)
                )
            self._rendered_event_indexes = event_indexes
        title = "Activity" if self._activity else "Log"
        self._log.border_title = title if self._following else f"{title} · history"
        for message, severity in notices:
            self._notice(message, severity)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        event.input.value = ""
        if not value:
            return
        try:
            operation, payload = _command(value)
            if operation == "help":
                self.action_help()
            elif operation == "detach":
                self.exit()
                return
            elif operation in {"quit", "kill"}:
                await self._quit(force=operation == "kill")
                return
            elif operation == "detail":
                await self.action_show_record(payload["kind"], payload["id"])
            elif operation in {"activity", "logs"}:
                self._activity = operation == "activity"
                self._rendered_event_indexes = None
            elif operation == "detail_close":
                self._detail = None
                self._detail_location = None
                self._detail_history.clear()
                if isinstance(self.screen, InfoWindow):
                    self.screen.dismiss()
            elif operation == "more":
                await self._more_detail()
            elif operation == "older":
                before = int(self._events[0]["event_index"]) if self._events else 1
                if before <= 1:
                    self._notice("No earlier events")
                    return
                self._cursor = max(0, before - _PAGE_SIZE - 1)
                _, self._events = await asyncio.to_thread(
                    _read,
                    self.case,
                    self.client,
                    self._cursor,
                    min(_PAGE_SIZE, before - 1),
                )
                self._following = False
                self._rendered_event_indexes = None
            elif operation == "newer":
                after = (
                    int(self._events[-1]["event_index"])
                    if self._events
                    else self._cursor
                )
                _, self._events = await asyncio.to_thread(
                    _read, self.case, self.client, after, _PAGE_SIZE
                )
                self._following = True
                self._rendered_event_indexes = None
            else:
                if self._runtime_lost:
                    raise RuntimeError(
                        "Runtime was lost; reconnect with attach before sending commands"
                    )
                if self.client is None:
                    if operation == "stop":
                        self._notice("Case already stopped", "warning")
                        await self._refresh()
                        return
                    if self._stopped_lock:
                        await asyncio.to_thread(self._stopped_lock.release)
                        self._stopped_lock = None
                    self.client = await asyncio.to_thread(start_runtime, self.case.path)
                    await asyncio.to_thread(self.client.claim_control)
                command_id = f"tui-{time.time_ns()}"
                accepted = await asyncio.to_thread(
                    self.client.request,
                    {
                        "type": "command",
                        "operation": operation,
                        "payload": payload,
                        "command_id": command_id,
                        "client_id": self.client._controller,
                    },
                )
                self._pending_commands.add(command_id)
                if len(self._pending_commands) > 20:
                    self._pending_commands.pop()
                self._notice(
                    f"{operation} accepted; waiting for receipt ({accepted.get('status', 'unknown')})"
                )
        except Exception as exc:
            self._notice(f"Failed: {exc}", "error")
        await self._refresh()

    async def on_unmount(self) -> None:
        self._closed = True
        if self.client:
            try:
                await asyncio.to_thread(self.client.release_control)
            except Exception:
                pass
        if self._stopped_lock:
            await asyncio.to_thread(self._stopped_lock.release)


def run_tui(case_path: str | Path) -> None:
    CaseApp(Case.open(case_path)).run()
