#!/usr/bin/env python3
"""Print cycle measurements extracted from a read-only case database."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from run import extract_cycles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_dir", type=Path, help="forensia case directory")
    args = parser.parse_args()
    data = extract_cycles(args.case_dir)

    if data["reader_status"] != "complete":
        print(
            json.dumps(
                {"status": data["reader_status"], "reason": data["reason"]},
                ensure_ascii=False,
            )
        )
        return 2
    cycles = data["cycles"]
    if not cycles:
        print("No per-iteration records are present in the current case database.")
        return 0

    print(
        "| Allocation | Session | Iteration / phase | Reasoning entries | Verdict entries | Logical calls | Provider attempts |"
    )
    print("|---|---|---|---:|---|---:|---:|")
    for cycle in cycles:
        allocation = cycle.get("allocation", "cycle")
        iteration = (
            cycle.get("phase", "unknown")
            if allocation == "unassigned"
            else cycle["iteration"]
        )
        print(
            f"| {allocation} | {cycle['session_id']} | {iteration} | {cycle['reasoning_entries']} | "
            f"{json.dumps(cycle['reasoning_verdicts'], ensure_ascii=False)} | "
            f"{cycle['logical_calls']} | {cycle['provider_attempts']} |"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
