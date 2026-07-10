from __future__ import annotations

import asyncio
import json
import re
from html import escape as html_escape
from pathlib import Path
from typing import Annotated

import duckdb
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from forensia.api.cache import load_snapshot, write_api_snapshots
from forensia.api.dto import (
    AIReviewDTO,
    AttackCoverageRowDTO,
    CaseDTO,
    CaseStatsDTO,
    ClaimDTO,
    EntityCardDTO,
    EventVolumePointDTO,
    EvidenceRecordDTO,
    FindingDTO,
    HypothesesResponseDTO,
    HypothesisReasoningEntryDTO,
    InvestigationStepDTO,
    MftTimelineDTO,
    ProgressEventDTO,
    ReportSectionDTO,
    RuntimeConfigDTO,
    SessionDTO,
)
from forensia.api.progress import list_progress_events
from forensia.api.service import (
    aggregate_event_volume,
    get_case_dto,
    get_case_stats_dto,
    get_evidence_record_dto,
    get_finding_dto,
    get_runtime_config_dto,
    list_ai_reviews_dto,
    list_attack_coverage_dto,
    list_claims_dto,
    list_entity_cards_dto,
    list_event_volume_dto,
    list_findings_dto,
    list_hypotheses_dto,
    list_hypothesis_reasoning_dto,
    list_latest_hypothesis_reasoning_dto,
    list_mft_timeline_dto,
    list_report_sections_dto,
    list_sessions_dto,
    list_steps_dto,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.html import render_html_report
from forensia.report.section_store import set_report_section_status
from forensia.report.writer import (
    build_report_markdown_from_db,
)

load_dotenv()


# Token regex for server-side JSON syntax highlighting. Strings (and the key
# variant followed by a colon), numbers, and literals are wrapped in colored
# spans; structural punctuation passes through untouched (and is safe — it never
# contains <, >, or &).
_JSON_TOKEN_RE = re.compile(
    r'(?P<str>"(?:\\.|[^"\\])*")(?P<colon>\s*:)?'
    r"|(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    r"|(?P<lit>\btrue\b|\bfalse\b|\bnull\b)"
)


def _json_to_colored_html(obj: object) -> str:
    """Pretty-print a value as JSON with syntax-highlight spans (HTML-escaped)."""
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)

    def _repl(match: re.Match[str]) -> str:
        if match.group("str") is not None:
            token = html_escape(match.group("str"))
            if match.group("colon"):
                return f'<span class="j-key">{token}</span>{match.group("colon")}'
            return f'<span class="j-str">{token}</span>'
        if match.group("num") is not None:
            return f'<span class="j-num">{match.group("num")}</span>'
        return f'<span class="j-lit">{match.group("lit")}</span>'

    return _JSON_TOKEN_RE.sub(_repl, text)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_spa_dir() -> Path | None:
    """Locate the SPA build directory, checking common locations."""
    candidates = [
        _repo_root() / "web_ui" / "dist",
        Path(__file__).resolve().parent / "static",
    ]
    for candidate in candidates:
        if candidate.exists() and (candidate / "index.html").exists():
            return candidate
    return None


def _resolve_ui_origins() -> list[str]:
    """Resolve allowed CORS origins from env or return development defaults."""
    from forensia.config import settings

    raw = settings.forensia_ui_origins
    if raw.strip():
        origins = [item.strip() for item in raw.split(",") if item.strip()]
        if origins:
            return origins
    return ["http://127.0.0.1:5173", "http://localhost:5173"]


# ── Domain route builders ────────────────────────────────────────────────


def _register_case_routes(app: FastAPI, case: Case, cached):
    @app.get("/api/case", response_model=CaseDTO)
    def api_case() -> CaseDTO:
        snapshot = cached("case.json")
        if snapshot is not None:
            return CaseDTO.model_validate(snapshot)
        return get_case_dto(case)

    @app.get("/api/config", response_model=RuntimeConfigDTO)
    def api_config() -> RuntimeConfigDTO:
        return get_runtime_config_dto()

    @app.get("/api/stats", response_model=CaseStatsDTO)
    def api_stats() -> CaseStatsDTO:
        snapshot = cached("stats.json")
        if snapshot is not None:
            return CaseStatsDTO.model_validate(snapshot)
        with CaseDB(case) as db:
            return get_case_stats_dto(db)


def _register_finding_routes(app: FastAPI, case: Case, cached):
    @app.get("/api/findings", response_model=list[FindingDTO])
    def api_findings(
        status: str | None = None,
        severity: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[FindingDTO]:
        snapshot = cached("findings.json")
        if snapshot is not None:
            rows = [FindingDTO.model_validate(item) for item in snapshot]
            if status:
                rows = [row for row in rows if row.status == status]
            if severity:
                rows = [row for row in rows if row.severity == severity]
            return rows[offset : offset + limit]
        with CaseDB(case) as db:
            return list_findings_dto(
                db, status=status, severity=severity, limit=limit, offset=offset
            )

    @app.get("/api/findings/{finding_id}", response_model=FindingDTO)
    def api_finding(finding_id: str) -> FindingDTO:
        snapshot = cached("findings.json")
        if snapshot is not None:
            for item in snapshot:
                if item.get("finding_id") == finding_id:
                    return FindingDTO.model_validate(item)
            raise HTTPException(
                status_code=404, detail=f"finding not found: {finding_id}"
            )
        with CaseDB(case) as db:
            finding = get_finding_dto(db, finding_id)
        if finding is None:
            raise HTTPException(
                status_code=404, detail=f"finding not found: {finding_id}"
            )
        return finding


def _register_hypothesis_routes(app: FastAPI, case: Case, cached):
    @app.get("/api/hypotheses", response_model=HypothesesResponseDTO)
    def api_hypotheses() -> HypothesesResponseDTO:
        snapshot = cached("hypotheses.json")
        if snapshot is not None:
            return HypothesesResponseDTO.model_validate(snapshot)
        with CaseDB(case) as db:
            return list_hypotheses_dto(db)

    @app.get(
        "/api/hypotheses/{hypothesis_id}/reasoning",
        response_model=list[HypothesisReasoningEntryDTO],
    )
    def api_hypothesis_reasoning(
        hypothesis_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
    ) -> list[HypothesisReasoningEntryDTO]:
        snapshot = cached("hypothesis_reasoning.json")
        if snapshot is not None:
            rows = snapshot.get(hypothesis_id, []) if isinstance(snapshot, dict) else []
            return [
                HypothesisReasoningEntryDTO.model_validate(item)
                for item in rows[:limit]
            ]
        with CaseDB(case) as db:
            return list_hypothesis_reasoning_dto(db, hypothesis_id, limit=limit)

    @app.get(
        "/api/hypotheses-reasoning", response_model=list[HypothesisReasoningEntryDTO]
    )
    def api_hypotheses_reasoning(
        since: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[HypothesisReasoningEntryDTO]:
        snapshot = cached("hypotheses_reasoning_latest.json")
        if snapshot is not None:
            rows = [
                HypothesisReasoningEntryDTO.model_validate(item) for item in snapshot
            ]
            if since:
                for index, item in enumerate(rows):
                    if item.entry_id == since:
                        return rows[:index]
            return rows[:limit]
        with CaseDB(case) as db:
            return list_latest_hypothesis_reasoning_dto(db, since=since, limit=limit)


def _register_session_routes(app: FastAPI, case: Case, cached):
    @app.get("/api/sessions", response_model=list[SessionDTO])
    def api_sessions() -> list[SessionDTO]:
        snapshot = cached("sessions.json")
        if snapshot is not None:
            return [SessionDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_sessions_dto(db)

    @app.get(
        "/api/sessions/{session_id}/steps", response_model=list[InvestigationStepDTO]
    )
    def api_session_steps(session_id: str) -> list[InvestigationStepDTO]:
        snapshot = cached("session_steps.json")
        if snapshot is not None:
            return [
                InvestigationStepDTO.model_validate(item)
                for item in snapshot.get(session_id, [])
            ]
        with CaseDB(case) as db:
            return list_steps_dto(db, session_id)


def _register_report_routes(app: FastAPI, case: Case, cached):
    @app.get("/api/report-sections", response_model=list[ReportSectionDTO])
    def api_report_sections() -> list[ReportSectionDTO]:
        snapshot = cached("report_sections.json")
        if snapshot is not None:
            return [ReportSectionDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_report_sections_dto(db)

    @app.get("/api/report-markdown")
    def api_report_markdown() -> Response:
        report_path = case.reports_dir / "report.md"
        if report_path.exists():
            return Response(
                content=report_path.read_text(encoding="utf-8"),
                media_type="text/markdown; charset=utf-8",
            )
        with CaseDB(case) as db:
            markdown = build_report_markdown_from_db(db, case=case)
            # Read-only GET: build the references in memory, never write
            # reports/ artifacts from an API request.
            from forensia.report.evidence_map import (
                build_evidence_map,
                render_evidence_references,
            )

            ref_section = render_evidence_references(build_evidence_map(db, markdown))
            if ref_section:
                markdown = markdown.rstrip() + "\n\n" + ref_section + "\n"
        return Response(content=markdown, media_type="text/markdown; charset=utf-8")

    @app.get("/api/report-html", response_class=HTMLResponse)
    def api_report_html() -> HTMLResponse:
        report_path = case.reports_dir / "report.html"
        if report_path.exists():
            return HTMLResponse(report_path.read_text(encoding="utf-8"))
        with CaseDB(case) as db:
            rendered_path = render_html_report(case, db)
        return HTMLResponse(rendered_path.read_text(encoding="utf-8"))

    @app.post(
        "/api/report-sections/{section_key}/status", response_model=ReportSectionDTO
    )
    def api_update_report_section_status(
        section_key: str, status: str
    ) -> ReportSectionDTO:
        with CaseDB(case) as db:
            try:
                set_report_section_status(db, section_key, status)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            rows = [
                item
                for item in list_report_sections_dto(db)
                if item.section_key == section_key
            ]
            if not rows:
                raise HTTPException(
                    status_code=404, detail=f"report section not found: {section_key}"
                )
            write_api_snapshots(case, db)
            return rows[0]

    @app.get("/api/claims", response_model=list[ClaimDTO])
    def api_claims(section_key: str | None = None) -> list[ClaimDTO]:
        snapshot = cached("claims.json")
        if snapshot is not None and section_key is None:
            return [ClaimDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_claims_dto(db, section_key=section_key)


def _register_evidence_record_routes(app: FastAPI, case: Case):
    def _lookup_resilient(evidence_id: str) -> tuple[str, EvidenceRecordDTO | None]:
        """Live DB lookup; while an investigation holds the DuckDB write lock
        (single-writer), report it as 'locked' instead of failing with 500."""
        try:
            with CaseDB(case) as db:
                return "ok", get_evidence_record_dto(db, evidence_id)
        except duckdb.Error:
            return "locked", None

    def _evidence_map_summary(evidence_id: str) -> dict | None:
        path = case.reports_dir / "evidence_map.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError, OSError:
            return None
        entry = data.get(evidence_id) if isinstance(data, dict) else None
        return entry if isinstance(entry, dict) else None

    @app.get("/api/evidence/{evidence_id}", response_model=EvidenceRecordDTO)
    def api_evidence_record(evidence_id: str) -> EvidenceRecordDTO:
        status, dto = _lookup_resilient(evidence_id)
        if status == "locked":
            raise HTTPException(
                status_code=503,
                detail="Case database is locked by a running investigation; retry after the run (or see reports/evidence_map.json for the summary).",
                headers={"Retry-After": "30"},
            )
        if dto is None:
            raise HTTPException(
                status_code=404, detail=f"Evidence record not found: {evidence_id}"
            )
        return dto

    @app.get("/evidence/{evidence_id}", response_class=HTMLResponse)
    def evidence_record_page(evidence_id: str) -> HTMLResponse:
        # Forensic artifact content (and the URL path) is untrusted input —
        # escape everything interpolated into this page.
        safe_id = html_escape(evidence_id)
        status, dto = _lookup_resilient(evidence_id)
        if status == "locked":
            summary = _evidence_map_summary(evidence_id)
            summary_html = ""
            if summary:
                line = " · ".join(
                    html_escape(str(part))
                    for part in (
                        summary.get("timestamp"),
                        summary.get("source"),
                        summary.get("summary"),
                    )
                    if part
                )
                summary_html = f"<pre>{line}</pre>"
            return HTMLResponse(
                '<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">'
                '<meta http-equiv="refresh" content="30">'
                f"<title>{safe_id} — Forensia Evidence</title>"
                "<style>body { font-family: monospace; background: #1e1e2e; color: #cdd6f4; padding: 24px; }"
                " h1 { font-size: 18px; color: #b4befe; } .meta { color: #a6adc8; font-size: 13px; }"
                " pre { background: #181825; padding: 16px; border-radius: 8px; white-space: pre-wrap; }</style></head>"
                f"<body><h1>{safe_id}</h1>"
                '<p class="meta">The database is locked while an investigation is running. The full content will be available after the run completes (this page auto-retries every 30 seconds).</p>'
                f"{summary_html}</body></html>",
                status_code=503,
            )
        if dto is None:
            return HTMLResponse(
                f"<!DOCTYPE html><html><body><h1>404 - Not Found</h1><p>Evidence ID: {safe_id}</p></body></html>",
                status_code=404,
            )
        # Show just the raw artifact content (parsed raw_json) when present,
        # falling back to the full normalized record when raw is empty/missing.
        raw = dto.record.get("raw") if isinstance(dto.record, dict) else None
        colored_json = _json_to_colored_html(raw if raw else dto.record)
        return HTMLResponse(
            f"""<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8"><title>{safe_id} — Forensia Evidence</title>
<style>
  body {{ font-family: "JetBrains Mono", "IBM Plex Mono", "SFMono-Regular", monospace; background: #0a0a0d; color: #e8e8ef; padding: 20px; margin: 0; }}
  .id {{ font-size: 12px; color: #62626e; margin: 0 0 12px; }}
  pre {{ background: #18181f; border: 1px solid #2c2c38; padding: 16px; border-radius: 12px; overflow-x: auto; font-size: 13px; line-height: 1.65; white-space: pre-wrap; word-break: break-all; margin: 0; }}
  .j-key {{ color: #89b4fa; }}
  .j-str {{ color: #a6e3a1; }}
  .j-num {{ color: #fab387; }}
  .j-lit {{ color: #cba6f7; }}
</style></head>
<body>
  <div class="id">{safe_id}</div>
  <pre>{colored_json}</pre>
</body></html>"""
        )


def _register_evidence_routes(
    app: FastAPI, case: Case, cached, aggregate_event_volume_func
):
    @app.get("/api/mft-timeline", response_model=list[MftTimelineDTO])
    def api_mft_timeline(
        from_timestamp: Annotated[str | None, Query(alias="from")] = None,
        to_timestamp: Annotated[str | None, Query(alias="to")] = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    ) -> list[MftTimelineDTO]:
        snapshot = cached("mft_timeline.json")
        if snapshot is not None:
            rows = [MftTimelineDTO.model_validate(item) for item in snapshot]
            if from_timestamp:
                rows = [row for row in rows if (row.timestamp or "") >= from_timestamp]
            if to_timestamp:
                rows = [row for row in rows if (row.timestamp or "") <= to_timestamp]
            return rows[:limit]
        with CaseDB(case) as db:
            return list_mft_timeline_dto(
                db,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
                limit=limit,
            )

    @app.get("/api/entities", response_model=list[EntityCardDTO])
    def api_entities() -> list[EntityCardDTO]:
        snapshot = cached("entities.json")
        if snapshot is not None:
            return [EntityCardDTO.model_validate(item) for item in snapshot]
        return list_entity_cards_dto(case)

    @app.get("/api/attack-coverage", response_model=list[AttackCoverageRowDTO])
    def api_attack_coverage() -> list[AttackCoverageRowDTO]:
        snapshot = cached("attack_coverage.json")
        if snapshot is not None:
            return [AttackCoverageRowDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_attack_coverage_dto(db)

    @app.get("/api/event-volume", response_model=list[EventVolumePointDTO])
    def api_event_volume(
        bucket: Annotated[str, Query(pattern="^(year|month|day|hour)$")] = "day",
        source: Annotated[str, Query(pattern="^(all|detected)$")] = "all",
        start: str | None = None,
        end: str | None = None,
    ) -> list[EventVolumePointDTO]:
        if not start and not end:
            snapshot = cached(f"event_volume_{bucket}_{source}.json")
            if snapshot is not None:
                return [EventVolumePointDTO.model_validate(item) for item in snapshot]
        try:
            with CaseDB(case) as db:
                return list_event_volume_dto(
                    db, bucket=bucket, source=source, start=start, end=end
                )
        except Exception:
            pass
        for finer in ("hour", "day"):
            if finer == bucket:
                continue
            src = cached(f"event_volume_{finer}_{source}.json")
            if src is None:
                continue
            items = [EventVolumePointDTO.model_validate(item) for item in src]
            return aggregate_event_volume_func(items, bucket, start=start, end=end)
        return []

    @app.get("/api/ai-reviews", response_model=list[AIReviewDTO])
    def api_ai_reviews(
        finding_id: str | None = None, hypothesis_id: str | None = None
    ) -> list[AIReviewDTO]:
        snapshot = cached("ai_reviews.json")
        if snapshot is not None:
            rows = [AIReviewDTO.model_validate(item) for item in snapshot]
            if finding_id:
                rows = [row for row in rows if row.finding_id == finding_id]
            if hypothesis_id:
                rows = [
                    row
                    for row in rows
                    if row.finding_id == f"hypothesis:{hypothesis_id}"
                ]
            return rows
        with CaseDB(case) as db:
            return list_ai_reviews_dto(
                db, finding_id=finding_id, hypothesis_id=hypothesis_id
            )


def _register_stream_routes(app: FastAPI, case: Case):
    @app.get("/api/stream")
    async def api_stream(
        after: Annotated[int, Query(ge=0)] = 0,
        once: bool = False,
    ) -> StreamingResponse:
        def cached(name: str):
            return load_snapshot(case, name)

        async def event_source() -> str:
            last_index = after
            while True:
                snapshot = cached("progress_events.json")
                if snapshot is not None:
                    events = [
                        item
                        for item in snapshot
                        if int(item.get("event_index", 0)) > last_index
                    ][:100]
                else:
                    with CaseDB(case) as db:
                        events = list_progress_events(
                            db, after_index=last_index, limit=100
                        )
                if events:
                    for event in events:
                        dto = ProgressEventDTO.model_validate(event)
                        last_index = dto.event_index
                        yield (
                            f"id: {dto.event_index}\n"
                            "event: progress\n"
                            f"data: {dto.model_dump_json()}\n\n"
                        )
                    if once:
                        break
                else:
                    if once:
                        break
                    yield ": keepalive\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(event_source(), media_type="text/event-stream")


def _register_spa_routes(app: FastAPI, spa_dir: Path | None):
    if spa_dir is None:
        message = (
            "web_ui/dist not found."
            " Run `cd web_ui && npx pnpm install && npx pnpm build` first."
        )

        @app.get("/", response_class=HTMLResponse)
        def missing_index() -> HTMLResponse:
            return HTMLResponse(message, status_code=503)

        @app.get("/{full_path:path}", response_class=HTMLResponse)
        def missing_paths(full_path: str) -> HTMLResponse:
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404)
            return HTMLResponse(message, status_code=503)

        return

    app.mount("/", StaticFiles(directory=str(spa_dir), html=True), name="spa")


# ── Application factory ──────────────────────────────────────────────────


def create_app(case: Case) -> FastAPI:
    """Create a FastAPI application with all API routes and error handlers for the given case.

    Routes fall back from cached snapshots to live database queries for performance.
    """
    app = FastAPI(title=f"forensia {case.path.name}")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_ui_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(duckdb.IOException)
    async def duckdb_lock_handler(
        request: Request, exc: duckdb.IOException
    ) -> JSONResponse:
        """Return 503 when DuckDB is locked by an ongoing investigation."""
        return JSONResponse(
            status_code=503,
            content={
                "detail": "database locked by investigation process — retry after run completes"
            },
        )

    spa_dir = _resolve_spa_dir()

    def cached(name: str):
        return load_snapshot(case, name)

    _register_case_routes(app, case, cached)
    _register_finding_routes(app, case, cached)
    _register_hypothesis_routes(app, case, cached)
    _register_session_routes(app, case, cached)
    _register_report_routes(app, case, cached)
    _register_evidence_routes(app, case, cached, aggregate_event_volume)
    _register_evidence_record_routes(app, case)
    _register_stream_routes(app, case)
    _register_spa_routes(app, spa_dir)

    return app
