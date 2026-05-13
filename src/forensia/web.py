from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from forensia.api.cache import load_snapshot, write_api_snapshots
from forensia.api.dto import (
    AIReviewDTO,
    CaseDTO,
    CaseStatsDTO,
    ClaimDTO,
    EventVolumePointDTO,
    FindingDTO,
    HypothesesResponseDTO,
    HypothesisReasoningEntryDTO,
    InvestigationStepDTO,
    MftTimelineDTO,
    ProgressEventDTO,
    ReportSectionDTO,
    SessionDTO,
)
from forensia.api.progress import list_progress_events
from forensia.api.service import (
    get_case_dto,
    get_case_stats_dto,
    get_finding_dto,
    list_event_volume_dto,
    list_ai_reviews_dto,
    list_claims_dto,
    list_findings_dto,
    list_latest_hypothesis_reasoning_dto,
    list_hypothesis_reasoning_dto,
    list_hypotheses_dto,
    list_mft_timeline_dto,
    list_report_sections_dto,
    list_sessions_dto,
    list_steps_dto,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.writer import set_report_section_status


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_spa_dir() -> Path | None:
    candidates = [
        _repo_root() / "web_ui" / "dist",
        Path(__file__).resolve().parent / "static",
    ]
    for candidate in candidates:
        if candidate.exists() and (candidate / "index.html").exists():
            return candidate
    return None


def create_app(case: Case) -> FastAPI:
    app = FastAPI(title=f"forensia {case.path.name}")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    spa_dir = _resolve_spa_dir()

    def cached(name: str):
        return load_snapshot(case, name)

    @app.get("/api/case", response_model=CaseDTO)
    def api_case() -> CaseDTO:
        snapshot = cached("case.json")
        if snapshot is not None:
            return CaseDTO.model_validate(snapshot)
        return get_case_dto(case)

    @app.get("/api/stats", response_model=CaseStatsDTO)
    def api_stats() -> CaseStatsDTO:
        snapshot = cached("stats.json")
        if snapshot is not None:
            return CaseStatsDTO.model_validate(snapshot)
        with CaseDB(case) as db:
            return get_case_stats_dto(db)

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
            return list_findings_dto(db, status=status, severity=severity, limit=limit, offset=offset)

    @app.get("/api/findings/{finding_id}", response_model=FindingDTO)
    def api_finding(finding_id: str) -> FindingDTO:
        snapshot = cached("findings.json")
        if snapshot is not None:
            for item in snapshot:
                if item.get("finding_id") == finding_id:
                    return FindingDTO.model_validate(item)
            raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
        with CaseDB(case) as db:
            finding = get_finding_dto(db, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
        return finding

    @app.get("/api/hypotheses", response_model=HypothesesResponseDTO)
    def api_hypotheses() -> HypothesesResponseDTO:
        snapshot = cached("hypotheses.json")
        if snapshot is not None:
            return HypothesesResponseDTO.model_validate(snapshot)
        with CaseDB(case) as db:
            return list_hypotheses_dto(db)

    @app.get("/api/hypotheses/{hypothesis_id}/reasoning", response_model=list[HypothesisReasoningEntryDTO])
    def api_hypothesis_reasoning(
        hypothesis_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
    ) -> list[HypothesisReasoningEntryDTO]:
        snapshot = cached("hypothesis_reasoning.json")
        if snapshot is not None:
            rows = snapshot.get(hypothesis_id, []) if isinstance(snapshot, dict) else []
            return [HypothesisReasoningEntryDTO.model_validate(item) for item in rows[:limit]]
        with CaseDB(case) as db:
            return list_hypothesis_reasoning_dto(db, hypothesis_id, limit=limit)

    @app.get("/api/hypotheses-reasoning", response_model=list[HypothesisReasoningEntryDTO])
    def api_hypotheses_reasoning(
        since: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[HypothesisReasoningEntryDTO]:
        snapshot = cached("hypotheses_reasoning_latest.json")
        if snapshot is not None:
            rows = [HypothesisReasoningEntryDTO.model_validate(item) for item in snapshot]
            if since:
                for index, item in enumerate(rows):
                    if item.entry_id == since:
                        return rows[:index]
            return rows[:limit]
        with CaseDB(case) as db:
            return list_latest_hypothesis_reasoning_dto(db, since=since, limit=limit)

    @app.get("/api/sessions", response_model=list[SessionDTO])
    def api_sessions() -> list[SessionDTO]:
        snapshot = cached("sessions.json")
        if snapshot is not None:
            return [SessionDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_sessions_dto(db)

    @app.get("/api/sessions/{session_id}/steps", response_model=list[InvestigationStepDTO])
    def api_session_steps(session_id: str) -> list[InvestigationStepDTO]:
        snapshot = cached("session_steps.json")
        if snapshot is not None:
            return [InvestigationStepDTO.model_validate(item) for item in snapshot.get(session_id, [])]
        with CaseDB(case) as db:
            return list_steps_dto(db, session_id)

    @app.get("/api/report-sections", response_model=list[ReportSectionDTO])
    def api_report_sections() -> list[ReportSectionDTO]:
        snapshot = cached("report_sections.json")
        if snapshot is not None:
            return [ReportSectionDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_report_sections_dto(db)

    @app.post("/api/report-sections/{section_key}/status", response_model=ReportSectionDTO)
    def api_update_report_section_status(section_key: str, status: str) -> ReportSectionDTO:
        with CaseDB(case) as db:
            try:
                set_report_section_status(db, section_key, status)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            rows = [item for item in list_report_sections_dto(db) if item.section_key == section_key]
            if not rows:
                raise HTTPException(status_code=404, detail=f"report section not found: {section_key}")
            write_api_snapshots(case, db)
            return rows[0]

    @app.get("/api/claims", response_model=list[ClaimDTO])
    def api_claims(section_key: str | None = None) -> list[ClaimDTO]:
        snapshot = cached("claims.json")
        if snapshot is not None and section_key is None:
            return [ClaimDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_claims_dto(db, section_key=section_key)

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
            return list_mft_timeline_dto(db, from_timestamp=from_timestamp, to_timestamp=to_timestamp, limit=limit)

    @app.get("/api/event-volume", response_model=list[EventVolumePointDTO])
    def api_event_volume(
        bucket: Annotated[str, Query(pattern="^(hour|day)$")] = "hour",
        source: Annotated[str, Query(pattern="^(all|detected)$")] = "all",
    ) -> list[EventVolumePointDTO]:
        snapshot = cached(f"event_volume_{bucket}_{source}.json")
        if snapshot is not None:
            return [EventVolumePointDTO.model_validate(item) for item in snapshot]
        with CaseDB(case) as db:
            return list_event_volume_dto(db, bucket=bucket, source=source)

    @app.get("/api/ai-reviews", response_model=list[AIReviewDTO])
    def api_ai_reviews(finding_id: str | None = None, hypothesis_id: str | None = None) -> list[AIReviewDTO]:
        snapshot = cached("ai_reviews.json")
        if snapshot is not None:
            rows = [AIReviewDTO.model_validate(item) for item in snapshot]
            if finding_id:
                rows = [row for row in rows if row.finding_id == finding_id]
            if hypothesis_id:
                rows = [row for row in rows if row.finding_id == f"hypothesis:{hypothesis_id}"]
            return rows
        with CaseDB(case) as db:
            return list_ai_reviews_dto(db, finding_id=finding_id, hypothesis_id=hypothesis_id)

    @app.get("/api/stream")
    async def api_stream(
        after: Annotated[int, Query(ge=0)] = 0,
        once: bool = False,
    ) -> StreamingResponse:
        async def event_source() -> str:
            last_index = after
            while True:
                snapshot = cached("progress_events.json")
                if snapshot is not None:
                    events = [item for item in snapshot if int(item.get("event_index", 0)) > last_index][:100]
                else:
                    with CaseDB(case) as db:
                        events = list_progress_events(db, after_index=last_index, limit=100)
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

    if spa_dir is None:
        message = (
            "web_ui/dist が見つかりません。"
            " `cd web_ui && npx pnpm install && npx pnpm build` を実行してください。"
        )

        @app.get("/", response_class=HTMLResponse)
        def missing_index() -> HTMLResponse:
            return HTMLResponse(message, status_code=503)

        @app.get("/{full_path:path}", response_class=HTMLResponse)
        def missing_paths(full_path: str) -> HTMLResponse:
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404)
            return HTMLResponse(message, status_code=503)

        return app

    app.mount("/", StaticFiles(directory=str(spa_dir), html=True), name="spa")
    return app
