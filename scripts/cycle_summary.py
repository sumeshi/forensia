#!/usr/bin/env python3
"""Cycle summary: extract per-cycle deltas from a forensia case directory.

Usage:
    python scripts/cycle_summary.py <case_dir>

Outputs a Markdown table with cycle, new_hyp, resolved, refuted,
llm_calls, queries_run, and benchmark_progress.
"""

import argparse
import json
import sys
from pathlib import Path


def _load_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _count_by_field(events: list[dict], field: str, pattern: str) -> int:
    return sum(1 for e in events if str(e.get(field, "")).strip() == pattern)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cycle delta summary for forensia cases"
    )
    parser.add_argument("case_dir", type=str, help="Path to forensia case directory")
    args = parser.parse_args()

    case_path = Path(args.case_dir).resolve()
    progress_path = case_path / "progress_events.json"
    db_path = case_path / "db" / "case.duckdb"

    if not progress_path.exists():
        print(f"progress_events.json not found at {progress_path}")
        sys.exit(1)

    events = _load_json(progress_path)
    if not events:
        print("No progress events found.")
        sys.exit(0)

    cycle_events: dict[int, list[dict]] = {}
    for event in events:
        iteration = event.get("iteration")
        if iteration is not None:
            key = int(iteration)
            cycle_events.setdefault(key, []).append(event)

    print(
        "| Cycle | New Hyp | Resolved | Refuted | LLM Calls | Queries Run | Benchmark Progress |"
    )
    print("|---|---|---|---|---|---|---|")

    for cycle in sorted(cycle_events):
        evts = cycle_events[cycle]

        hypothesis_reasoning_events = [
            e for e in evts if e.get("stage") == "hypothesis_reasoning"
        ]
        new_hyp = _count_by_field(
            hypothesis_reasoning_events, "hypothesis_status", "new"
        )
        resolved = _count_by_field(
            hypothesis_reasoning_events, "hypothesis_status", "resolved"
        )
        refuted = _count_by_field(
            hypothesis_reasoning_events, "hypothesis_status", "refuted"
        )

        section_events = [
            e
            for e in evts
            if e.get("stage", "").startswith("investigate/report-section")
        ]
        benchmark_events = [
            e
            for e in section_events
            if "appendix" in str(e.get("current_report_section", "")).lower()
        ]
        benchmark_done = len(benchmark_events)

        llm_calls = 0
        queries_run = 0
        for e in evts:
            summary = str(e.get("summary", ""))
            if "llm" in summary.lower():
                llm_calls += 1
            if "query" in summary.lower():
                queries_run += 1

        if db_path.exists():
            import duckdb

            try:
                conn = duckdb.connect(str(db_path), read_only=True)
                row = conn.execute(
                    "SELECT COUNT(*) FROM section_runs WHERE section_key LIKE '6_appendix' AND phase = 'check'"
                ).fetchone()
                benchmark_progress = row[0] if row else 0
                conn.close()
            except Exception:
                benchmark_progress = benchmark_done
        else:
            benchmark_progress = benchmark_done

        print(
            f"| {cycle} | {new_hyp} | {resolved} | {refuted} | {llm_calls} | {queries_run} | {benchmark_progress} |"
        )


if __name__ == "__main__":
    main()
