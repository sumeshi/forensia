"""L5 reproduction: does an open durable Gap/Task block "completed"?

Builds a temp Case DB holding one open durable `report_gaps` row, then calls
_check_termination with the completion inputs the investigator loop passes
(broad-plan stop, no active hypotheses).

- B0 (rev 242ca6a): ("completed", ..., "no_gaps_no_hypotheses") although a
  durable open gap row remains — the gate only read the section-level
  `total_gaps` prose aggregate (recorded in git revision `68b2ba6:docs/round-b0-baseline.md`, section 4).
- M0 (T05): completion reads the durable `report_gaps`/`investigation_tasks`
  unresolved counts passed by the loop; with durable work open the gate falls
  through to the no-progress machinery, and only truly drained work completes.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from forensia.ai.investigation.investigator import (
    _check_termination,
    _durable_open_work_counts,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(Path(tmpdir) / "case")
        with CaseDB(case) as db:
            db.execute(
                """
                INSERT INTO report_gaps (
                    gap_id, section_key, description, kind, status, origin,
                    created_at, updated_at
                ) VALUES (
                    'G-001', 'evidence', 'unexplained service install',
                    'missing_evidence', 'open', 'termination',
                    now(), now()
                )
                """
            )
            durable_open_gaps, durable_open_tasks = _durable_open_work_counts(db)
            terminal_status, no_progress, reason = _check_termination(
                report_only=False,
                broad_plan_stop=True,
                active_hypotheses=[],
                durable_open_gaps=durable_open_gaps,
                durable_open_tasks=durable_open_tasks,
                no_progress_count=0,
                no_progress_limit=3,
                cycle_progress=True,
            )
            print(
                json.dumps(
                    {
                        "durable_open_gaps": durable_open_gaps,
                        "durable_open_tasks": durable_open_tasks,
                        "terminal_status": terminal_status,
                        "stop_reason": reason,
                        "no_progress_count": no_progress,
                    },
                    sort_keys=True,
                )
            )
            db.execute(
                "UPDATE report_gaps SET status = 'resolved' WHERE gap_id = 'G-001'"
            )
            drained_gaps, drained_tasks = _durable_open_work_counts(db)
            drained_status, _, drained_reason = _check_termination(
                report_only=False,
                broad_plan_stop=True,
                active_hypotheses=[],
                durable_open_gaps=drained_gaps,
                durable_open_tasks=drained_tasks,
                no_progress_count=0,
                no_progress_limit=3,
                cycle_progress=True,
            )
            print(
                json.dumps(
                    {
                        "durable_open_gaps_after_resolution": drained_gaps,
                        "terminal_status_after_resolution": drained_status,
                        "stop_reason_after_resolution": drained_reason,
                    },
                    sort_keys=True,
                )
            )


if __name__ == "__main__":
    main()
