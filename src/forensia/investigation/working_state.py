"""Bounded Case/Trace working context, assembled on demand."""

from __future__ import annotations

from typing import Any

from forensia.db.database import CaseDB
from forensia.investigation.work_judgment import open_work_refs, work_context_snapshot


def build_working_state(
    db: CaseDB,
    *,
    hypothesis_id: str | None = None,
    max_work: int = 8,
) -> dict[str, Any]:
    """Project open work and current evidence refs without Markdown or cache."""
    work: list[dict[str, Any]] = []
    for ref in open_work_refs(db):
        if hypothesis_id and hypothesis_id not in ref.hypothesis_ids:
            continue
        if len(work) >= max_work:
            break
        item: dict[str, Any] = {}
        if ref.hypothesis_ids:
            ids = list(ref.hypothesis_ids)
            rows = db.execute(
                "SELECT hypothesis_id, description, status FROM hypotheses "
                f"WHERE hypothesis_id IN ({', '.join('?' for _ in ids)}) "
                "ORDER BY hypothesis_id",
                ids,
            ).fetchall()
            item["hypotheses"] = [
                {
                    "id": str(r[0]),
                    "description": str(r[1] or "")[:200],
                    "status": str(r[2] or ""),
                }
                for r in rows
            ]
        if ref.task_ids:
            ids = list(ref.task_ids)
            rows = db.execute(
                "SELECT task_id, kind, description, reason, retry_condition "
                f"FROM investigation_tasks WHERE task_id IN ({', '.join('?' for _ in ids)}) "
                "ORDER BY task_id",
                ids,
            ).fetchall()
            item["tasks"] = [
                {
                    "id": str(r[0]),
                    "kind": str(r[1] or ""),
                    "description": str(r[2] or "")[:200],
                    "reason": str(r[3] or "")[:160],
                    "retry_condition": str(r[4] or ""),
                }
                for r in rows
            ]
        if ref.gap_ids:
            ids = list(ref.gap_ids)
            rows = db.execute(
                "SELECT gap_id, description, kind, coverage_reason FROM report_gaps "
                f"WHERE gap_id IN ({', '.join('?' for _ in ids)}) ORDER BY gap_id",
                ids,
            ).fetchall()
            item["gaps"] = [
                {
                    "id": str(r[0]),
                    "description": str(r[1] or "")[:200],
                    "kind": str(r[2] or ""),
                    "reason": str(r[3] or "")[:160],
                }
                for r in rows
            ]
        work.append(item)

    return {
        "current": work_context_snapshot(db, hypothesis_id) if hypothesis_id else None,
        "work": work,
    }


def render_working_state(state: dict[str, Any]) -> str:
    """Render bounded state units and their stable Case/Trace refs."""
    lines = ["<WORKING_STATE source=case_trace>"]
    current = state.get("current")
    current_hypothesis_id = current.hypothesis_id if current is not None else None
    work = state.get("work", [])
    detailed_gaps = {row["id"] for item in work for row in item.get("gaps", [])}
    detailed_tasks = {row["id"] for item in work for row in item.get("tasks", [])}
    if current is not None:
        lines.extend(
            [f"current hypothesis={current.hypothesis_id} status={current.status}"]
        )
        lines.extend(f"required capability={x}" for x in current.capabilities)
        lines.extend(f"unready capability={x}" for x in current.unready_capabilities)
        lines.extend(f"unmet condition={x}" for x in current.unmet_conditions)
        lines.extend(f"current support={x}" for x in current.support_roots)
        lines.extend(f"current contradiction={x}" for x in current.contradiction_roots)
        lines.extend(
            f"historical reevaluation required={x}"
            for x in current.reevaluation_required
        )
        lines.extend(
            f"open requirement={x}"
            for x in current.requirements
            if not (
                (x.startswith("gap=") and x.removeprefix("gap=") in detailed_gaps)
                or (x.startswith("task=") and x.removeprefix("task=") in detailed_tasks)
            )
        )
    for item in work:
        for row in item.get("hypotheses", []):
            if row["id"] == current_hypothesis_id:
                continue
            lines.append(
                f"open hypothesis={row['id']} status={row['status']} {row['description']}"
            )
        for row in item.get("gaps", []):
            lines.append(
                f"open gap={row['id']} kind={row['kind']} {row['description']} {row['reason']}"
            )
        for row in item.get("tasks", []):
            lines.append(
                f"open task={row['id']} kind={row['kind']} retry={row['retry_condition']} "
                f"{row['description']} {row['reason']}"
            )
    lines.append("</WORKING_STATE>")
    return "\n".join(lines)
