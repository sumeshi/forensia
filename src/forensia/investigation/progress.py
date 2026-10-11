"""Per-hypothesis consecutive retrieval feedback."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from sqlglot import parse_one
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

logger = logging.getLogger(__name__)


def query_fingerprint(sql: str | None) -> str:
    """Generate a fingerprint for a query to detect duplicates.

    Hashes the whole normalized SQL, ignoring formatting and unquoted
    identifier case while retaining predicates, literals, projections and aliases.
    """
    sql = (sql or "").strip()
    if not sql:
        return "generic"

    try:
        expression = parse_one(sql, read="duckdb")
    except Exception:
        try:
            expression = parse_one(sql)
        except Exception:
            return hashlib.sha256(f"raw:{sql}".encode()).hexdigest()

    try:
        try:
            expression = normalize_identifiers(expression, dialect="duckdb")
        except Exception:
            logger.debug(
                "Failed to normalize SQL identifiers for fingerprint", exc_info=True
            )
        canonical_sql = expression.sql(dialect="duckdb", pretty=False)
        return hashlib.sha256(f"sql:{canonical_sql}".encode()).hexdigest()
    except Exception:
        return hashlib.sha256(f"raw:{sql}".encode()).hexdigest()


@dataclass(slots=True)
class HypothesisProgressTracker:
    """Track feedback consumed by the settlement gate."""

    zero_row_inconclusive_count: int = 0
    _last_missing_signature: str = ""
    consecutive_same_missing: int = 0

    def record(self, verdict: str, row_count: int) -> None:
        """Record a retrieval result for zero-row settlement feedback."""
        if verdict == "inconclusive" and row_count == 0:
            self.zero_row_inconclusive_count += 1
        else:
            self.zero_row_inconclusive_count = 0

    def register_check(self, verdict: str, missing_signature: str = "") -> None:
        """Track consecutive same-missing checks for auto-refute detection."""
        if verdict == "inconclusive" and missing_signature:
            if missing_signature == self._last_missing_signature:
                self.consecutive_same_missing += 1
            else:
                self.consecutive_same_missing = 1
            self._last_missing_signature = missing_signature
        elif verdict != "inconclusive":
            self.consecutive_same_missing = 0
            self._last_missing_signature = ""
