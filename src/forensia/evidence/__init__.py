"""Evidence layer: artifact ingest (raw -> JSONL) and normalize (JSONL -> DB).

One module per artifact family (evtx/mft/prefetch); artifacts.py is the
adapter registry, ingest.py/normalize.py drive all registered adapters.
"""
