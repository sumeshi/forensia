from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

from forensia.core.ownership import case_lock

from .ipc import RuntimeServer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--system-prompt", type=Path)
    parser.add_argument("--template", type=Path)
    parser.add_argument("--startup-id", required=True)
    args = parser.parse_args()

    lock = case_lock(args.case_dir).acquire()
    try:
        from .engine import RuntimeEngine

        engine = RuntimeEngine(args.case_dir)
        settings = json.loads(sys.stdin.buffer.read() or b"{}")
        engine.prepare(
            input_dir=args.input_dir,
            overwrite=args.overwrite,
            settings=settings,
            system_prompt=args.system_prompt,
            template=args.template,
        )
        worker = threading.Thread(
            target=engine.run,
            kwargs={
                "input_dir": args.input_dir,
                "overwrite": args.overwrite,
                "settings": settings,
                "system_prompt": args.system_prompt,
                "template": args.template,
            },
            name="forensia-engine",
            daemon=False,
        )
        worker.start()
        RuntimeServer(args.case_dir, engine, lock, args.startup_id).serve_forever()
    except BaseException:
        lock.release()
        raise


if __name__ == "__main__":
    main()
