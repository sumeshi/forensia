from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

try:
    from sqlglot import exp, parse_one
    from sqlglot.optimizer.normalize_identifiers import normalize_identifiers
except ImportError:  # pragma: no cover - optional until dependency is installed
    exp = None
    parse_one = None
    normalize_identifiers = None

from forensia.ai.checker import _co_observation_satisfied


def _query_fingerprint(sql: str | None) -> str:
    """Generate a fingerprint for a query to detect duplicates.

    Uses sqlglot AST normalization when available so semantically equivalent
    queries produce the same fingerprint regardless of formatting or aliasing.
    """
    sql = (sql or "").strip()
    if not sql:
        return "generic"

    if parse_one is None or exp is None:
        return hashlib.sha1(f"raw:{sql.lower()}".encode()).hexdigest()[:8]

    try:
        expression = parse_one(sql, read="duckdb")
    except Exception:
        try:
            expression = parse_one(sql)
        except Exception:
            return hashlib.sha1(f"raw:{sql.lower()}".encode()).hexdigest()[:8]

    try:
        if normalize_identifiers is not None:
            try:
                expression = normalize_identifiers(expression, dialect="duckdb")
            except Exception:
                pass

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
    """Tracks hypothesis investigation progress for auto-refute/auto-confirm decisions."""

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

    def register_check(
        self, verdict: str, row_count: int, missing_signature: str = ""
    ) -> None:
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

    def should_auto_refute_due_to_unobserved_events(self, threshold: int = 3) -> bool:
        """Return True after threshold consecutive same-missing inconclusive results."""
        return self.consecutive_same_missing >= threshold

    def should_auto_refute(self, consecutive_threshold: int = 3) -> bool:
        """Return True after consecutive_threshold consecutive 0-row inconclusive results."""
        return self.zero_row_inconclusive_count >= consecutive_threshold

    def should_pivot(self, threshold: int = 2) -> bool:
        """Detect if any query fingerprint appears >= threshold times."""
        fp_counts = Counter(self.query_fingerprints)
        most_common = fp_counts.most_common(1)
        if most_common and most_common[0][1] >= threshold:
            return True
        return False

    @staticmethod
    def _extract_observed_event_ids(rows: list[dict[str, Any]]) -> set[int]:
        """Extract unique event_ids from query result rows."""
        observed: set[int] = set()
        for row in rows:
            event_id = row.get("event_id")
            if event_id is not None:
                try:
                    observed.add(int(event_id))
                except TypeError, ValueError:
                    pass
        return observed

    def _confirm_set_from(self, rule_context: Any, hypothesis: Any = None) -> set[int]:
        """Pull co_observed_event_ids from rule_context first, falling back to the
        hypothesis itself (broad_plan-derived hypotheses have no rule_context)."""
        confirm_when = None
        if rule_context is not None:
            confirm_when = getattr(rule_context, "confirm_when", None)
        if not confirm_when and hypothesis is not None:
            confirm_when = getattr(hypothesis, "confirm_when", None)
        if not confirm_when:
            return set()
        required_event_ids = (
            confirm_when.get("co_observed_event_ids")
            if isinstance(confirm_when, dict)
            else None
        )
        if not required_event_ids:
            return set()
        out: set[int] = set()
        for eid in required_event_ids:
            try:
                out.add(int(str(eid).strip()))
            except TypeError, ValueError:
                continue
        return out

    def should_auto_confirm(
        self, rule_context: Any, rows: list[dict[str, Any]], hypothesis: Any = None
    ) -> bool:
        """Return True if all co-observation constraints are satisfied.

        Uses _co_observation_satisfied to check co_observed_event_ids along
        with same_host and within_minutes correlation constraints.
        """
        confirm_when = None
        if rule_context is not None:
            confirm_when = getattr(rule_context, "confirm_when", None)
        if not confirm_when and hypothesis is not None:
            confirm_when = getattr(hypothesis, "confirm_when", None)
        if not confirm_when or not isinstance(confirm_when, dict):
            return False
        satisfied, _ = _co_observation_satisfied(confirm_when, rows)
        return satisfied

    def has_partial_confirm_signal(
        self, rule_context: Any, rows: list[dict[str, Any]], hypothesis: Any = None
    ) -> bool:
        """Return True when some, but not all, confirm_when event IDs are present."""
        required_set = self._confirm_set_from(rule_context, hypothesis)
        if not required_set:
            return False
        observed_event_ids = self._extract_observed_event_ids(rows)
        return bool(required_set & observed_event_ids) and not required_set.issubset(
            observed_event_ids
        )
