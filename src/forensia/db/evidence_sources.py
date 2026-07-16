"""Evidence source registration and tracking in the case database.

This module lives in the platform (db) layer so it can be imported by both
the evidence and knowledge layers without violating the dependency direction.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)


def register_evidence_source(
    db: CaseDB,
    *,
    source_id: str,
    artifact_family: str,
    display_path: str,
    ingest_status: str,
    parser_name: str = "",
    parser_version: str = "",
    row_count: int = 0,
    channel: str = "",
    hosts: list[str] | None = None,
    volume_id: str = "",
    min_time: datetime | None = None,
    max_time: datetime | None = None,
    error_code: str = "",
    error_summary: str = "",
) -> None:
    """Register or update an evidence source record."""
    now = datetime.now(UTC)
    db.execute(
        """
        INSERT INTO evidence_sources (
            source_id, artifact_family, display_path, ingest_status,
            parser_name, parser_version, row_count, channel,
            hosts, volume_id, min_time, max_time,
            error_code, error_summary, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (source_id) DO UPDATE SET
            artifact_family = EXCLUDED.artifact_family,
            display_path = CASE WHEN EXCLUDED.display_path = '' THEN evidence_sources.display_path ELSE EXCLUDED.display_path END,
            ingest_status = EXCLUDED.ingest_status,
            parser_name = CASE WHEN EXCLUDED.parser_name = '' THEN evidence_sources.parser_name ELSE EXCLUDED.parser_name END,
            parser_version = CASE WHEN EXCLUDED.parser_version = '' THEN evidence_sources.parser_version ELSE EXCLUDED.parser_version END,
            row_count = EXCLUDED.row_count,
            channel = CASE WHEN EXCLUDED.channel = '' THEN evidence_sources.channel ELSE EXCLUDED.channel END,
            hosts = EXCLUDED.hosts,
            volume_id = CASE WHEN EXCLUDED.volume_id = '' THEN evidence_sources.volume_id ELSE EXCLUDED.volume_id END,
            min_time = EXCLUDED.min_time,
            max_time = EXCLUDED.max_time,
            error_code = EXCLUDED.error_code,
            error_summary = EXCLUDED.error_summary,
            updated_at = EXCLUDED.updated_at
        """,
        [
            source_id, artifact_family, display_path, ingest_status,
            parser_name, parser_version, row_count, channel,
            hosts or [], volume_id, min_time, max_time,
            error_code, error_summary, now, now,
        ],
    )
