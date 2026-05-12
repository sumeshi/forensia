from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from forensia.api.progress import record_progress_event
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.web import create_app


class WebApiTests(unittest.TestCase):
    def test_api_endpoints_and_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence, status,
                        tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "F-1",
                        "rule-1",
                        "Suspicious service install",
                        "Service was installed after a remote logon.",
                        "high",
                        0.9,
                        "accepted",
                        '["svc"]',
                        '["T1543"]',
                        '[{"service_name":"evilsvc"}]',
                        "Likely persistence",
                        "[]",
                        now,
                    ),
                )
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("H-1", "Investigate service persistence", "active", None, "", "broad_plan", "S-1", None, now, now),
                )
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("1_overview", "Overview", "Body", 0.8, "draft", 2, '["gap"]', "S-1", now),
                )
                db.execute(
                    """
                    INSERT INTO investigation_sessions (
                        session_id, started_at, finished_at, iterations, status
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    ("S-1", now, now, 1, "completed"),
                )
                db.execute(
                    """
                    INSERT INTO investigation_steps (
                        step_id, session_id, iteration, phase, input_json, output_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("S-1-01-plan", "S-1", 1, "plan", "{}", "{}", now),
                )
                db.execute(
                    """
                    INSERT INTO ai_reviews (
                        review_id, finding_id, verdict, report_text, missing_checks,
                        confidence_adjustment, notes, raw_response, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("R-1", "F-1", "confirmed", "Confirmed", "[]", 0.0, "", "{}", now),
                )
                db.execute(
                    """
                    INSERT INTO mft_timeline (
                        timeline_id, evidence_id, record_number, file_path, timestamp,
                        timestamp_type, description, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("T-1", "mft-1", 1, "C:/Temp/a.exe", now, "fn_created", "Created", "[]"),
                )
                record_progress_event(
                    db,
                    {
                        "stage": "investigate/report-section",
                        "status": "running",
                        "iteration": 1,
                        "summary": "[report] 1_overview writing...",
                        "report_sections": {"items": [], "current_section": "1_overview"},
                    },
                )

            client = TestClient(create_app(case))

            self.assertEqual(200, client.get("/api/case").status_code)
            self.assertEqual(1, client.get("/api/stats").json()["findings_accepted"])
            self.assertEqual(1, len(client.get("/api/findings").json()))
            self.assertEqual("F-1", client.get("/api/findings/F-1").json()["finding_id"])
            self.assertEqual(1, len(client.get("/api/hypotheses").json()["active"]))
            self.assertEqual(1, len(client.get("/api/sessions").json()))
            self.assertEqual(1, len(client.get("/api/sessions/S-1/steps").json()))
            self.assertEqual(1, len(client.get("/api/report-sections").json()))
            report_section = client.get("/api/report-sections").json()[0]
            self.assertEqual("draft", report_section["status"])
            self.assertEqual(2, report_section["update_count"])
            self.assertEqual(1, len(client.get("/api/mft-timeline").json()))
            self.assertEqual(1, len(client.get("/api/event-volume?bucket=hour&source=all").json()))
            self.assertEqual(1, len(client.get("/api/event-volume?bucket=hour&source=detected").json()))
            self.assertEqual(1, len(client.get("/api/ai-reviews").json()))
            stats_payload = client.get("/api/stats").json()
            self.assertEqual(1, stats_payload["total_iterations"])
            self.assertEqual(1, stats_payload["session_count"])

            with client.stream("GET", "/api/stream?once=true") as response:
                body = b"".join(response.iter_bytes())

            self.assertEqual(200, response.status_code)
            self.assertIn(b"event: progress", body)
            self.assertIn(b"1_overview", body)


if __name__ == "__main__":
    unittest.main()
