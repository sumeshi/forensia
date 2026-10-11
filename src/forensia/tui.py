"""Textual client for a single case Runtime."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Header, Input, RichLog, Static

from forensia.core.case import Case
from forensia.core.ownership import CaseLock, controller_lock_path
from forensia.db.database import CaseDB
from forensia.db.views import case_detail, case_events, case_snapshot
from forensia.runtime import RuntimeClient, probe_runtime, start_runtime

_PAGE_SIZE = 40


def _read(
    case: Case, client: RuntimeClient | None, after_index: int, limit: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if client is not None:
        return (
            client.request({"type": "snapshot"}),
            client.request(
                {"type": "events", "after_index": after_index, "limit": limit}
            ),
        )
    with CaseDB(case, read_only=True) as db:
        return case_snapshot(case, db), case_events(db, after_index, limit)


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


def _command(value: str) -> tuple[str, dict[str, Any]] | None:
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
    if command == "/detach" and stripped.lower() == command:
        return "detach", {}
    raise ValueError("Use /help to see supported commands")


def _format_header(snapshot: dict[str, Any]) -> str:
    counts = snapshot.get("counts") or {}
    session = snapshot.get("session") or {}
    state = snapshot.get("state") or {}
    usage = snapshot.get("budget_usage")
    remaining = snapshot.get("budget_remaining_llm_calls")
    limit = snapshot.get("budget_limit_llm_calls")
    status = session.get("status") or state.get("status") or "unknown"
    work = snapshot.get("current_work")
    active_ingest = bool(
        work
        and work.get("status") == "running"
        and work.get("stage") in {"ingest", "normalize", "analyze"}
    )
    if active_ingest:
        status = "running"
    elapsed = snapshot.get("elapsed_seconds")
    seconds = f"{elapsed}s" if elapsed is not None else "unknown"
    budget = (
        f"{remaining} calls remaining"
        if remaining is not None
        else ("unlimited calls" if limit == 0 else "call budget unknown")
    )
    lines = [
        f"{snapshot.get('case_name', 'case')} · {status} · elapsed {seconds}",
        f"Findings {counts.get('findings', '—')} · Hypotheses {counts.get('hypotheses', '—')} {counts.get('hypothesis_statuses', {})} · Open tasks {counts.get('open_tasks', '—')}",
        f"LLM usage {usage if usage is not None else 'unknown'} · {budget}",
        f"Current work: {work.get('summary') or work.get('phase') or work if work else 'idle'}",
    ]
    reason = (
        None
        if active_ingest
        else (session.get("terminal_reason") or state.get("stop_reason"))
    )
    if reason:
        lines.append(f"Reason: {reason}")
    return "\n".join(lines)


class CaseApp(App[None]):
    CSS = """
    Screen { layout: vertical; }
    #case-state { height: auto; min-height: 5; max-height: 8; padding: 0 1; border: round cyan; }
    #event-log { height: 1fr; border: round blue; }
    #detail { height: 8; display: none; border: round yellow; overflow-y: auto; }
    #prompt { height: 3; }
    """
    TITLE = "FORENSIA"

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
        self._pending_commands: set[str] = set()
        self._rendered_event_indexes: tuple[int, ...] | None = None
        self._message = "Ready · /help for commands"
        self._closed = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("Opening case…", id="case-state")
            yield RichLog(id="event-log", wrap=True, markup=False, highlight=False)
            yield Static("", id="detail")
            yield Input(
                placeholder="Command or steering instruction · /help", id="prompt"
            )
        yield Footer()

    async def on_mount(self) -> None:
        try:
            if self.client:
                await asyncio.to_thread(self.client.claim_control)
            else:
                lock = CaseLock(self.case.path)
                lock.path = controller_lock_path(self.case.path)
                await asyncio.to_thread(lock.acquire)
                self._stopped_lock = lock
            await self._refresh()
            self.set_interval(0.5, self._tick)
            self.query_one("#prompt", Input).focus()
        except Exception as exc:
            self._message = f"Unable to control this case: {exc}"
            self.query_one("#case-state", Static).update(self._message)
            self.query_one("#prompt", Input).disabled = True

    async def _tick(self) -> None:
        if not self._closed:
            await self._refresh()

    async def _refresh(self) -> None:
        try:
            after = (
                self._events[-1]["event_index"]
                if self._following and self._events
                else self._highwater
            )
            snapshot, latest = await asyncio.to_thread(
                _read, self.case, self.client, after, _PAGE_SIZE
            )
            self._highwater = int(snapshot.get("event_highwater") or self._highwater)
            if self._following:
                self._events.extend(latest)
                self._events = self._events[-_PAGE_SIZE:]
            self.query_one("#case-state", Static).update(_format_header(snapshot))
            log = self.query_one("#event-log", RichLog)
            event_indexes = tuple(int(event["event_index"]) for event in self._events)
            if event_indexes != self._rendered_event_indexes:
                log.clear()
                for event in self._events:
                    refs = event.get("refs") or {}
                    summary = event.get("summary") or event.get("reason") or ""
                    ref_text = (
                        " ".join(f"{key}={value}" for key, value in refs.items())
                        if isinstance(refs, dict)
                        else str(refs)
                    )
                    log.write(
                        Text(
                            f"{event.get('event_index', '')} · {event.get('kind', 'event')} · {event.get('status', '')} · {summary} {ref_text}"
                        )
                    )
                self._rendered_event_indexes = event_indexes
            log.border_title = (
                f"Investigation log · {len(self._events)} events · /older /newer"
            )
            if self._detail is not None:
                detail = self.query_one("#detail", Static)
                if isinstance(self._detail, dict) and "total_chars" in self._detail:
                    text = self._detail["text"]
                    if self._detail.get("next_offset") is not None:
                        text += "\n\n/more to read the next page"
                    detail.update(Text(text))
                else:
                    detail.update(
                        Text(
                            json.dumps(
                                self._detail, ensure_ascii=False, indent=2, default=str
                            )
                        )
                    )
                detail.display = True
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
                        self._message = f"Command {receipt['status']}: {receipt.get('reason') or receipt.get('operation')}"
                        self._pending_commands.discard(command_id)
            self.title = f"FORENSIA · {self.case.path.name}"
            self.sub_title = self._message
        except Exception as exc:
            if self.client is not None:
                self._runtime_lost = True
                try:
                    await asyncio.to_thread(self.client.release_control)
                except Exception:
                    pass
                self.client = None
            self._message = f"Runtime unavailable; showing saved case state: {exc}"

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        event.input.value = ""
        if not value:
            return
        try:
            parsed = _command(value)
            if parsed is None:
                return
            operation, payload = parsed
            if operation == "help":
                self._message = "Commands: /detail [KIND ID], /more, /older, /newer, /stop, /resume, /add PATH, /report [--write], /detach"
            elif operation == "detach":
                self.exit()
                return
            elif operation == "detail":
                self._detail = await asyncio.to_thread(
                    _read_detail, self.case, self.client, payload["kind"], payload["id"]
                )
                self._message = (
                    "Detail loaded"
                    if self._detail is not None
                    else "No matching detail"
                )
            elif operation == "detail_close":
                self._detail = None
                self.query_one("#detail", Static).display = False
                self._message = "Detail closed"
            elif operation == "more":
                if (
                    not isinstance(self._detail, dict)
                    or self._detail.get("next_offset") is None
                ):
                    self._message = "No further detail page"
                else:
                    self._detail = await asyncio.to_thread(
                        _read_detail,
                        self.case,
                        self.client,
                        self._detail["kind"],
                        self._detail["id"],
                        self._detail["next_offset"],
                    )
                    self._message = "Next detail page loaded"
            elif operation == "older":
                before = int(self._events[0]["event_index"]) if self._events else 1
                self._cursor = max(0, before - _PAGE_SIZE - 1)
                _, self._events = await asyncio.to_thread(
                    _read, self.case, self.client, self._cursor, _PAGE_SIZE
                )
                self._following = False
                self._message = "Older events loaded"
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
                self._message = "Following current events"
            else:
                if self._runtime_lost:
                    raise RuntimeError(
                        "Runtime was lost; reconnect with attach before sending commands"
                    )
                if self.client is None:
                    if operation == "stop":
                        self._message = "Case already stopped"
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
                self._message = f"{operation} accepted; waiting for receipt ({accepted.get('status', 'unknown')})"
        except Exception as exc:
            self._message = f"Failed: {exc}"
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
