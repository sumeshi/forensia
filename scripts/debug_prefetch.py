#!/usr/bin/env python3
"""Debug prefetch2es parsing on a single .pf file.

Usage: python scripts/debug_prefetch.py /path/to/file.pf
"""

from __future__ import annotations

import sys
from pathlib import Path

from prefetch2es.models.Prefetch2es import Prefetch2es


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/debug_prefetch.py /path/to/file.pf")
        sys.exit(1)

    pf = Path(sys.argv[1])
    if not pf.exists():
        print(f"File not found: {pf}")
        sys.exit(1)

    print(f"File: {pf} ({pf.stat().st_size} bytes)")

    parser = Prefetch2es(pf)
    total_records = total_executions = 0
    for chunk in parser.gen_records(multiprocess=False, chunk_size=500):
        for record in chunk:
            total_records += 1
            total_executions += len(record["last_exec_times"])
            if total_records <= 2:
                print(f"  sample: {record}")
    print(
        f"gen_records: {total_records} entries, {total_executions} derived executions"
    )


if __name__ == "__main__":
    main()
