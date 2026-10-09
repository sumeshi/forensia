"""Per-hypothesis query fingerprints and consecutive retrieval feedback."""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlglot import exp, parse_one
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

logger = logging.getLogger(__name__)


def query_fingerprint(sql: str | None) -> str:
    """Generate a fingerprint for a query to detect duplicates.

    Uses sqlglot AST normalization so semantically equivalent
    queries produce the same fingerprint regardless of formatting or aliasing.
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
            return hashlib.sha1(f"raw:{sql.lower()}".encode()).hexdigest()[:8]

    try:
        try:
            expression = normalize_identifiers(expression, dialect="duckdb")
        except Exception:
            logger.debug(
                "Failed to normalize SQL identifiers for fingerprint", exc_info=True
            )

        def _column_name(node: Any) -> str | None:
            if isinstance(node, exp.Column):
                return node.name.lower()
            if isinstance(node, exp.Identifier):
                return node.name.lower()
            return None

        def _literal_value(node: Any) -> str | None:
            if isinstance(node, exp.Literal):
                value = str(node.this)
                if node.is_string:
                    return value.lower()
                try:
                    return str(int(value))
                except ValueError:
                    return value.lower()
            if isinstance(node, exp.Cast):
                return _literal_value(node.this)
            if isinstance(node, exp.Paren):
                return _literal_value(node.this)
            if isinstance(node, exp.Neg):
                inner = _literal_value(node.this)
                return f"-{inner}" if inner is not None else None
            return None

        def _collect_terms(predicate: Any, column_name: str) -> list[str]:
            values: list[str] = []
            if isinstance(predicate, exp.EQ):
                left = _column_name(predicate.this)
                right = _column_name(predicate.expression)
                if left == column_name:
                    value = _literal_value(predicate.expression)
                    if value is not None:
                        values.append(value)
                elif right == column_name:
                    value = _literal_value(predicate.this)
                    if value is not None:
                        values.append(value)
            elif (
                isinstance(predicate, exp.In)
                and _column_name(predicate.this) == column_name
            ):
                for item in predicate.expressions:
                    value = _literal_value(item)
                    if value is not None:
                        values.append(value)
            return values

        event_ids: set[str] = set()
        computers: set[str] = set()
        for predicate in expression.find_all((exp.EQ, exp.In)):
            event_ids.update(_collect_terms(predicate, "event_id"))
            computers.update(_collect_terms(predicate, "computer"))

        parts: list[str] = []
        if event_ids:
            parts.append("ev:" + ",".join(sorted(event_ids)))
        if computers:
            parts.append("host:" + ",".join(sorted(computers)))
        if parts:
            return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:8]

        canonical_sql = expression.sql(dialect="duckdb", pretty=False)
        return hashlib.sha1(f"sql:{canonical_sql}".encode()).hexdigest()[:8]
    except Exception:
        return hashlib.sha1(f"raw:{sql.lower()}".encode()).hexdigest()[:8]


@dataclass(slots=True)
class HypothesisProgressTracker:
    """Track duplicate queries and feedback consumed by the settlement gate."""

    zero_row_inconclusive_count: int = 0
    query_fingerprints: list[str] = field(default_factory=list)
    _last_missing_signature: str = ""
    consecutive_same_missing: int = 0

    def record(self, query_fingerprint: str, verdict: str, row_count: int) -> None:
        """Record a query execution result."""
        self.query_fingerprints.append(query_fingerprint)
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

    def should_pivot(self, threshold: int = 2) -> bool:
        """Detect if any query fingerprint appears >= threshold times."""
        fp_counts = Counter(self.query_fingerprints)
        most_common = fp_counts.most_common(1)
        if most_common and most_common[0][1] >= threshold:
            return True
        return False
