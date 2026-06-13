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
    chunks = list(parser.gen_records(multiprocess=False, chunk_size=500))
    total_records = sum(len(c) for c in chunks)
    print(f"gen_records: {len(chunks)} chunks, {total_records} total records")
    if chunks:
        for r in chunks[0][:2]:
            print(f"  sample: {r}")

    tl_parser = Prefetch2es(pf)
    tl_chunks = list(tl_parser.gen_timeline_records(multiprocess=False, chunk_size=500))
    total_tl = sum(len(c) for c in tl_chunks)
    print(f"gen_timeline_records: {len(tl_chunks)} chunks, {total_tl} total records")
    if tl_chunks:
        for r in tl_chunks[0][:2]:
            print(f"  sample: {r}")


if __name__ == "__main__":
    main()
