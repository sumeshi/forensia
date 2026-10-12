"""Single read-side judgment of work readiness (V2-03; R04/R06 unification).

Selection eligibility, stop classification, and reopen previously interpreted
Coverage and retry state with three different predicates.  All readers now
derive from this one judgment, read on demand from existing Case State
(``hypotheses``, ``investigation_tasks``, ``hypothesis_relations``,
``evidence_coverage``) and session Trace work-progress receipts.  It is a pure
read result: no Agenda table, cache, or status write is created; write owners
stay in ``work_state.py`` (``classify_active_hypotheses_on_stop``,
``reopen_retryable_work``).

Shared availability rule (the one interpretation of Coverage): a required
capability is **ready** when any ``evidence_coverage`` row for it reports
state ``available`` or ``partial``; ``unavailable``/``degraded`` rows, or no
row, are not ready.  Retrieval eligibility and absence certification remain
deliberately different questions: running a retrieval over partial Coverage
is allowed, but whether an empty result may certify absence is owned by the
settlement gate (``checking/settlement.py``) on the observed retrieval scope
and is never fused into this readiness boolean.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from forensia.core.verification import EVALUABLE_CONDITION_KEYS
from forensia.db.database import CaseDB
from forensia.db.query import normalize_value
from forensia.evidence.links import (
    EvidenceLink,
    evidence_link_currentness,
    load_evidence_links,
)
from forensia.investigation.verification.sufficiency import (
    derivation_root_key,
)
from forensia.knowledge.coverage import (
    derive_required_capabilities,
    disclosure_tables_for_spec,
    verification_feasibility_error,
)

#: Coverage states from which a retrieval may run.  Selection, stop, and
#: reopen all read this set, so the same work cannot flip between readers.
READY_COVERAGE_STATES = frozenset({"available", "partial"})

#: Task kinds whose open Task blocks a linked hypothesis from running.
EXTERNAL_TASK_KINDS = frozenset(
    {"human_decision", "external_lookup", "evidence_acquisition"}
)

_SELECTION_RETRY_BUDGET = 8
_SELECTION_INCONCLUSIVE_LIMIT = 4

_BLOCKER_MESSAGES = {
    "status": "status={owner}",
    "blocked_until": "blocked until {owner}",
    "blocked": "blocked: {owner}",
    "retry_budget": "retry budget exhausted",
    "inconclusive_limit": "repeated inconclusive limit",
    "work_exhausted": "previous attempt made no semantic progress: {owner}",
    "planner_exhausted": "query planning exhausted: {owner}",
    "no_eligible_capability": "no declared search family for this work",
    "prerequisite": "waiting for prerequisite {owner}",
    "external_task": "waiting for external investigation task",
    "capability_unavailable": "required evidence capability unavailable",
    "required_entity_unobservable": (
        "required entities are absent from the query family schema: {owner}"
    ),
    "observation_min_count_exceeds_current_family_count": (
        "typed observation needs more evidence: {owner}"
    ),
}

VERIFICATION_INFEASIBLE_CODES = frozenset(
    {
        "required_entity_unobservable",
        "observation_min_count_exceeds_current_family_count",
    }
)


@dataclass(frozen=True)
class Blocker:
    """A current reason the work is not runnable, carrying its owner.

    ``owner`` names the entity holding the condition — a required capability,
    an open external Task, a prerequisite hypothesis, stalled hypothesis work,
    or the persisted reason — so selection can cite the same owner.
    """

    code: str
    owner: str = ""


@dataclass(frozen=True)
class WorkJudgment:
    """One read result for one hypothesis work ref, recomputed on demand."""

    hypothesis_id: str
    capabilities: tuple[str, ...]
    unavailable_capabilities: tuple[str, ...]
    external_task_ids: tuple[str, ...]
    blockers: tuple[Blocker, ...]

    @property
    def runnable(self) -> bool:
        return not self.blockers

    @property
    def retry_condition(self) -> str:
        """Derived reopen condition while this work cannot run.

        Uses the persisted retry-condition vocabulary so reopen can read the
        judgment and the stored value against each other.
        """
        if self.external_task_ids:
            return "human_or_external_result"
        if any(
            blocker.code == "required_entity_unobservable" for blocker in self.blockers
        ):
            return "human_or_external_result"
        if self.unavailable_capabilities:
            return "required_capability_available"
        if any(
            blocker.code == "observation_min_count_exceeds_current_family_count"
            for blocker in self.blockers
        ):
            return "new_evidence_or_coverage"
        return ""


def blocker_message(judgment: WorkJudgment) -> str:
    """Render the judgment's blockers as one user-visible block reason."""
    parts: list[str] = []
    capabilities = list(judgment.unavailable_capabilities)
    if capabilities:
        parts.append(
            "required evidence capability unavailable: " + ", ".join(capabilities)
        )
    for blocker in judgment.blockers:
        if blocker.code == "capability_unavailable":
            continue
        parts.append(
            _BLOCKER_MESSAGES.get(blocker.code, blocker.code).format(
                owner=blocker.owner
            )
        )
    return "; ".join(parts)


def spec_capabilities(spec: Any, *, hypothesis_id: str = "") -> list[str]:
    """Derive required capabilities from a canonical VerificationSpec.

    One owner for both direct row readers: a declared
    ``required_capabilities`` list wins, otherwise structured support
    conditions map through the shared artifact catalog.  A missing or
    unparsable spec is an explicit failure, never text inference.
    """
    if isinstance(spec, str):
        try:
            spec = json.loads(spec)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"hypothesis {hypothesis_id} has an unparsable verification_spec: {exc}"
            ) from exc
    if not isinstance(spec, dict) or not spec:
        raise ValueError(
            f"hypothesis {hypothesis_id} has no canonical verification_spec; "
            "the case database does not match the current format "
            "(preserve the case and ingest into a new case directory)"
        )
    return derive_required_capabilities(
        spec.get("required_capabilities") or [],
        spec.get("support_conditions"),
    )


def coverage_readiness(
    db: CaseDB, capabilities: list[str]
) -> tuple[list[str], set[str]]:
    """Split required capabilities into not-ready ones and source families.

    Applies the shared readiness rule (module docstring).  Returns
    ``(not_ready_capabilities, observed_source_families)``.
    """
    if not capabilities:
        return [], set()
    placeholders = ", ".join("?" for _ in capabilities)
    rows = db.execute(
        f"SELECT capability, state, source_family FROM evidence_coverage "
        f"WHERE capability IN ({placeholders})",
        capabilities,
    ).fetchall()
    states: dict[str, list[str]] = {capability: [] for capability in capabilities}
    families: dict[str, set[str]] = {capability: set() for capability in capabilities}
    for capability, state, family in rows:
        key = str(capability)
        states.setdefault(key, []).append(str(state or "unknown"))
        if family:
            families.setdefault(key, set()).add(str(family))
    not_ready = [
        capability
        for capability in capabilities
        if not states.get(capability)
        or all(state not in READY_COVERAGE_STATES for state in states[capability])
    ]
    contributing = sorted(
        {family for capability in capabilities for family in families[capability]}
    )
    return not_ready, contributing


def count_consecutive_inconclusive(db: CaseDB, hypothesis_id: str) -> int:
    """Count consecutive inconclusive verdicts from recent reasoning."""
    rows = db.execute(
        "SELECT verdict FROM trace.hypothesis_reasoning "
        "WHERE hypothesis_id = ? AND phase = 'settlement' "
        "ORDER BY created_at DESC LIMIT 10",
        [hypothesis_id],
    ).fetchall()
    if not rows:
        rows = db.execute(
            "SELECT verdict FROM trace.hypothesis_reasoning "
            "WHERE hypothesis_id = ? AND phase = 'check' "
            "ORDER BY created_at DESC LIMIT 10",
            [hypothesis_id],
        ).fetchall()
    count = 0
    for row in rows:
        if row[0] == "inconclusive":
            count += 1
        else:
            break
    return count


def judge_work(
    db: CaseDB,
    hypothesis_ids: list[str],
    *,
    selection_gate: bool = False,
    now: datetime | None = None,
    session_id: str = "",
    case_snapshot: dict[str, Any] | None = None,
) -> dict[str, WorkJudgment]:
    """Judge work refs from Case State on demand.

    Every reader asks the same question of the same rows, so selection
    eligibility, stop classification, and reopen observe identical ready /
    not-ready capabilities and blocker owners for one Case State.
    ``selection_gate=True`` adds the candidate-flow-only conditions (active
    status, cooldown, retry budget, unconfirmed prerequisite, repeated
    inconclusive, and same-session semantic exhaustion) that answer "may this
    be selected next"; stop and reopen do not ask that question and therefore
    never carry those blockers.

    Hypothesis ids without a persisted row are dropped: a judgment is only
    defined for Case State that exists.
    """
    ids = sorted({str(item) for item in hypothesis_ids if item})
    if not ids:
        return {}
    now = (now or datetime.now(UTC)).replace(tzinfo=None)
    placeholders = ", ".join("?" for _ in ids)
    rows = db.execute(
        f"SELECT hypothesis_id, status, blocked_reason, next_eligible_at, "
        f"selection_count, verification_spec, required_entities FROM hypotheses "
        f"WHERE hypothesis_id IN ({placeholders})",
        ids,
    ).fetchall()
    by_id = {str(row[0]): row for row in rows}

    external_task_ids = {
        str(task_id)
        for task_id, kind in db.execute(
            "SELECT task_id, kind FROM investigation_tasks "
            "WHERE status IN ('open', 'in_progress')"
        ).fetchall()
        if str(kind or "") in EXTERNAL_TASK_KINDS
    }
    tasks: dict[str, set[str]] = defaultdict(set)
    wanted_ids = set(ids)
    if external_task_ids:
        for ref in open_work_refs(db):
            external_in_ref = external_task_ids.intersection(ref.task_ids)
            for hypothesis_id in ref.hypothesis_ids:
                if hypothesis_id in wanted_ids:
                    tasks[hypothesis_id].update(external_in_ref)

    statuses: dict[str, str] = {}
    prerequisites: dict[str, list[str]] = {}
    if selection_gate:
        statuses = {
            str(row[0]): str(row[1] or "active")
            for row in db.execute(
                "SELECT hypothesis_id, status FROM hypotheses"
            ).fetchall()
        }
        for source_id, target_id in db.execute(
            "SELECT from_hypothesis_id, to_hypothesis_id FROM hypothesis_relations "
            "WHERE relation_type = 'prerequisite_for'"
        ).fetchall():
            prerequisites.setdefault(str(target_id), []).append(str(source_id))
        if session_id and case_snapshot is None:
            from forensia.investigation.report_gap import evaluation_snapshot

            case_snapshot = evaluation_snapshot(db)

    judgments: dict[str, WorkJudgment] = {}
    family_counts: dict[str, int] = {}
    for hid in ids:
        row = by_id.get(hid)
        if row is None:
            continue
        (
            _hid,
            status,
            blocked_reason,
            next_eligible_at,
            selection_count,
            raw_spec,
            raw_entities,
        ) = row
        capabilities = tuple(spec_capabilities(raw_spec, hypothesis_id=hid))
        spec_payload = json.loads(raw_spec) if isinstance(raw_spec, str) else raw_spec
        support = spec_payload.get("support_conditions") or {}
        feasibility_reason = (
            verification_feasibility_error(
                db,
                support,
                json.loads(raw_entities)
                if isinstance(raw_entities, str)
                else raw_entities,
                family_counts,
            )
            if isinstance(support, dict)
            else None
        )
        not_ready, _ = coverage_readiness(db, list(capabilities))
        not_ready_in_cap_order = [cap for cap in capabilities if cap in not_ready]
        external = tuple(sorted(tasks.get(hid, ())))
        blockers: list[Blocker] = [
            Blocker("capability_unavailable", cap) for cap in not_ready_in_cap_order
        ]
        if (capabilities or support) and not disclosure_tables_for_spec(spec_payload)[
            0
        ]:
            blockers.append(Blocker("no_eligible_capability", hid))
        persisted_reason = str(blocked_reason or "").strip()
        if persisted_reason:
            blockers.append(Blocker("blocked", persisted_reason))
        if feasibility_reason:
            blockers.append(Blocker(*feasibility_reason))
        blockers.extend(Blocker("external_task", task_id) for task_id in external)
        if selection_gate:
            gate_blockers: list[Blocker] = []
            if str(status or "") != "active":
                gate_blockers.append(Blocker("status", str(status or "")))
            if isinstance(next_eligible_at, str):
                try:
                    next_eligible_at = datetime.fromisoformat(next_eligible_at)
                except ValueError:
                    next_eligible_at = None
            if isinstance(next_eligible_at, datetime):
                if next_eligible_at.tzinfo is not None:
                    next_eligible_at = next_eligible_at.replace(tzinfo=None)
                if now < next_eligible_at:
                    gate_blockers.append(
                        Blocker("blocked_until", str(next_eligible_at))
                    )
            if int(selection_count or 0) >= _SELECTION_RETRY_BUDGET:
                gate_blockers.append(
                    Blocker("retry_budget", str(int(selection_count or 0)))
                )
            if count_consecutive_inconclusive(db, hid) >= _SELECTION_INCONCLUSIVE_LIMIT:
                gate_blockers.append(Blocker("inconclusive_limit", ""))
            for prerequisite in prerequisites.get(hid, ()):
                if statuses.get(prerequisite) != "confirmed":
                    gate_blockers.append(Blocker("prerequisite", prerequisite))
            if session_id and work_progress_exhausted(
                db,
                session_id,
                hid,
                current=work_progress_snapshot(
                    db,
                    hid,
                    case_snapshot=case_snapshot,
                ),
            ):
                gate_blockers.append(Blocker("work_exhausted", hid))
            if session_id:
                latest_plan = db.execute(
                    "SELECT output_json FROM trace.investigation_steps WHERE "
                    "session_id = ? AND hypothesis_id = ? AND phase = 'plan-hypothesis' "
                    "ORDER BY created_at DESC, step_id DESC LIMIT 1",
                    [session_id, hid],
                ).fetchone()
                if latest_plan:
                    output = normalize_value(latest_plan[0])
                    plan = (
                        output.get("_plan_status", {})
                        if isinstance(output, dict)
                        else {}
                    )
                    current_work = work_progress_snapshot(
                        db, hid, case_snapshot=case_snapshot
                    )
                    if (
                        plan.get("stop_reason")
                        and plan.get("retry_available") is False
                        and current_work is not None
                        and plan.get("work_identity") == current_work["identity"]
                    ):
                        gate_blockers.append(Blocker("planner_exhausted", hid))
            blockers = [*gate_blockers, *blockers]
        judgments[hid] = WorkJudgment(
            hypothesis_id=hid,
            capabilities=capabilities,
            unavailable_capabilities=tuple(not_ready_in_cap_order),
            external_task_ids=external,
            blockers=tuple(blockers),
        )
    return judgments


@dataclass(frozen=True)
class WorkRef:
    """One unresolved work item: a hypothesis plus its linked Gap/Task rows.

    Linked rows describe one piece of work and are never counted separately
    (V2-03).  The links are the existing ``report_gaps.task_id`` /
    ``report_gaps.hypothesis_id``, ``investigation_tasks.gap_id`` /
    ``investigation_tasks.hypothesis_id``, and ``hypotheses.source_gap_id``
    columns.
    """

    hypothesis_ids: tuple[str, ...]
    gap_ids: tuple[str, ...]
    task_ids: tuple[str, ...]

    @property
    def ref_id(self) -> str:
        """Canonical id of the work item (hypothesis first, then rows)."""
        if self.hypothesis_ids:
            return self.hypothesis_ids[0]
        return self.gap_ids[0] if self.gap_ids else self.task_ids[0]


def open_work_refs(db: CaseDB) -> list[WorkRef]:
    """Merge currently unresolved Gaps/Tasks/Hypotheses into one item per work.

    Statuses mirror the durable completion gate: gaps in
    ``open``/``in_progress``/``needs_review``, tasks in
    ``open``/``in_progress``, hypotheses in the unresolved set.  Only rows
    linked through the existing columns merge; orphan rows stay their own ref.
    This read result is the Agenda: it exists only while the call holds and is
    never persisted, cached, or given its own table or status.
    """
    gap_rows = [
        (str(row[0]), str(row[1] or ""), str(row[2] or ""))
        for row in db.execute(
            "SELECT gap_id, task_id, hypothesis_id FROM report_gaps "
            "WHERE status IN ('open', 'in_progress', 'needs_review')"
        ).fetchall()
    ]
    task_rows = [
        (str(row[0]), str(row[1] or ""), str(row[2] or ""))
        for row in db.execute(
            "SELECT task_id, gap_id, hypothesis_id FROM investigation_tasks "
            "WHERE status IN ('open', 'in_progress')"
        ).fetchall()
    ]
    hypothesis_rows = [
        (str(row[0]), str(row[1] or ""))
        for row in db.execute(
            "SELECT hypothesis_id, source_gap_id FROM hypotheses "
            "WHERE status IN "
            "('active', 'deferred', 'blocked', 'needs_review', 'untestable')"
        ).fetchall()
    ]
    open_gaps = {gap_id for gap_id, _, _ in gap_rows}
    open_tasks = {task_id for task_id, _, _ in task_rows}

    parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(node: tuple[str, str]) -> tuple[str, str]:
        parent.setdefault(node, node)
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != root:
            parent[node], node = root, parent[node]
        return root

    def union(left: tuple[str, str], right: tuple[str, str]) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    def link(left: tuple[str, str], right: tuple[str, str]) -> None:
        if left and right:
            union(find(left), find(right))

    for gap_id, task_id, hypothesis_id in gap_rows:
        find(("gap", gap_id))
        if task_id and task_id in open_tasks:
            link(("gap", gap_id), ("task", task_id))
        if hypothesis_id:
            link(("gap", gap_id), ("hyp", hypothesis_id))
    for task_id, gap_id, hypothesis_id in task_rows:
        find(("task", task_id))
        if gap_id and gap_id in open_gaps:
            link(("task", task_id), ("gap", gap_id))
        if hypothesis_id:
            link(("task", task_id), ("hyp", hypothesis_id))
    for hypothesis_id, source_gap_id in hypothesis_rows:
        find(("hyp", hypothesis_id))
        if source_gap_id in open_gaps:
            link(("hyp", hypothesis_id), ("gap", source_gap_id))

    clusters: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(
        lambda: {"hyp": [], "gap": [], "task": []}
    )
    for kind, row_id in parent:
        root = find((kind, row_id))
        clusters[root][kind].append(row_id)
    refs = [
        WorkRef(
            hypothesis_ids=tuple(sorted(cluster["hyp"])),
            gap_ids=tuple(sorted(cluster["gap"])),
            task_ids=tuple(sorted(cluster["task"])),
        )
        for cluster in clusters.values()
    ]
    return sorted(refs, key=lambda ref: ref.ref_id)


def work_progress_snapshot(
    db: CaseDB,
    hypothesis_id: str,
    *,
    case_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Project the existing semantic progress view onto one hypothesis."""
    from forensia.investigation.report_gap import evaluation_snapshot

    row = db.execute(
        "SELECT verification_spec, required_entities FROM hypotheses "
        "WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchone()
    if row is None:
        return None

    snapshot = case_snapshot if case_snapshot is not None else evaluation_snapshot(db)
    identity = json.dumps(
        {
            "source_coverage": snapshot["identity"],
            "verification_spec": normalize_value(row[0]),
            "required_entities": normalize_value(row[1]),
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return {
        "identity": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "open_work": tuple(
            ref for ref in snapshot["open_work"] if hypothesis_id in ref[0]
        ),
        "observations": tuple(
            item for item in snapshot["observations"] if item[0] == hypothesis_id
        ),
        "contradictions": tuple(
            item for item in snapshot["contradictions"] if item[0] == hypothesis_id
        ),
    }


def work_progress_fingerprint(snapshot: dict[str, Any]) -> str:
    """Hash the stable JSON form of one semantic work snapshot."""
    encoded = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def work_progress_exhausted(
    db: CaseDB,
    session_id: str,
    hypothesis_id: str,
    *,
    current: dict[str, Any] | None = None,
) -> bool:
    """Check whether this session's unchanged completed attempt exhausted work."""
    if not session_id:
        return False
    row = db.execute(
        "SELECT output_json FROM trace.investigation_steps "
        "WHERE session_id = ? AND hypothesis_id = ? AND phase = 'work-progress' "
        "ORDER BY iteration DESC, created_at DESC, step_id DESC LIMIT 1",
        [session_id, hypothesis_id],
    ).fetchone()
    if row is None:
        return False
    output = row[0]
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            return False
    if not isinstance(output, dict) or output.get("status") != "completed":
        return False
    previous_fingerprint = output.get("fingerprint")
    if output.get("progressed") or not isinstance(previous_fingerprint, str):
        return False
    if current is None:
        current = work_progress_snapshot(db, hypothesis_id)
    if current is None:
        return False
    return previous_fingerprint == work_progress_fingerprint(current)


@dataclass(frozen=True)
class WorkContextSnapshot:
    """The deterministic Case/Trace context of the current attempt (V2-07).

    Built on demand from the existing owners — the canonical Spec/hypothesis
    row (current work), the shared work judgment (unmet requirements with
    owners), and ``hypothesis_evidence`` with the read-time currentness
    predicate (assessed support/contradiction grouped by derivation root) —
    so the same originals and work yield the same context, without a cached digest,
    LLM digest, or cache layer in between. Units carry original refs
    (derivation root, evidence id, assessment id, query id), never
    re-summarized prose.
    """

    hypothesis_id: str
    status: str
    capabilities: tuple[str, ...]
    unready_capabilities: tuple[str, ...]
    #: Declared evaluable Spec support conditions that no currently-current
    #: assessed link has matched (``key=condition-json``, sorted).
    unmet_conditions: tuple[str, ...]
    support_roots: tuple[str, ...]
    contradiction_roots: tuple[str, ...]
    #: Current judged material whose identity no longer verifies; presented
    #: as historical only — never counted as current support.
    reevaluation_required: tuple[str, ...]
    #: Linked open Gap/Task ids plus work-judgment blockers with owners.
    requirements: tuple[str, ...]


def _condition_unit(key: str, condition: Any) -> str:
    """Render one declared Spec condition as sorted, bounded JSON."""
    if isinstance(condition, (int, float, str, bool)) or condition is None:
        rendered = json.dumps(condition, ensure_ascii=False)
    else:
        rendered = json.dumps(condition, ensure_ascii=False, sort_keys=True)
    if len(rendered) > 200:
        rendered = rendered[:197] + "..."
    return f"{key}={rendered}"


def _root_unit(label: str, links: list[EvidenceLink], max_ids: int = 5) -> str:
    """Render one derivation-root unit with its original refs (V2-07)."""
    evidence_ids = sorted({str(link.evidence_id or "") for link in links} - {""})
    shown = evidence_ids[:max_ids]
    parts = ["evidence=" + (",".join(shown) or "-")]
    # An undeclared root defaults to the evidence id itself; repeating the
    # same id as "root=" would state one fact twice, so name the root only
    # when it differs from the listed material.
    declared = label.startswith("declared:")
    root_id = label[len("declared:") :] if declared else label
    if not (root_id and root_id in evidence_ids):
        parts.insert(0, f"root={label}")
    if len(evidence_ids) > max_ids:
        parts.append(f"(+{len(evidence_ids) - max_ids} more evidence ids)")
    assessment_ids = sorted({str(link.assessment_id or "") for link in links} - {""})
    if assessment_ids:
        parts.append(f"assessment={assessment_ids[0]}")
    query_ids = sorted({str(link.query_id or "") for link in links} - {""})
    if query_ids:
        parts.append(f"query={query_ids[0]}")
    return " ".join(parts)


def work_context_snapshot(
    db: CaseDB,
    hypothesis_id: str,
    *,
    max_units: int = 6,
) -> WorkContextSnapshot | None:
    """Select the per-attempt work context from Case/Trace on demand (V2-07).

    One deterministic read over the existing owners:

    - current work: the canonical Spec and status of the hypothesis row;
    - assessed material: ``hypothesis_evidence`` links grouped by
      ``derivation_root_key`` and annotated with the read-time currentness
      predicate; material whose identity no longer verifies is reported
      separately and never as current support;
    - unmet conditions: declared evaluable support-condition keys that no
      currently-current assessed link has matched;
    - unmet requirements: the shared work judgment (blockers with owners,
      capability readiness) plus the linked open Gap/Task rows of the work
      ref that contains this hypothesis.

    Returns None when the hypothesis has no Case State row. A missing or
    unparsable canonical spec fails explicitly, matching ``spec_capabilities``.
    """
    hid = str(hypothesis_id or "").strip()
    if not hid:
        return None
    row = db.execute(
        "SELECT status, verification_spec FROM hypotheses WHERE hypothesis_id = ?",
        [hid],
    ).fetchone()
    if row is None:
        return None
    capabilities = spec_capabilities(row[1], hypothesis_id=hid)
    raw_spec = json.loads(row[1]) if isinstance(row[1], str) else row[1]
    declared = sorted(
        set(raw_spec.get("support_conditions") or {}) & EVALUABLE_CONDITION_KEYS
    )

    links = load_evidence_links(db, hid)
    support: dict[str, list[EvidenceLink]] = {}
    contradiction: dict[str, list[EvidenceLink]] = {}
    reevaluation: list[str] = []
    matched_conditions: set[str] = set()
    for link in links:
        is_current, stale_reason = evidence_link_currentness(db, link)
        if not is_current:
            if stale_reason:
                reevaluation.append(
                    f"evidence={link.evidence_id} reason={stale_reason}"
                )
            continue
        matched = {str(k) for k in (getattr(link, "matched_conditions", ()) or ())}
        if matched and str(link.assessment_id or "").strip():
            matched_conditions.update(matched)
        # A present evidence row is not by itself an Assessment. Match the
        # sufficiency gate's assessed-link boundary before projecting support
        # or contradiction into model-visible context.
        if not str(link.assessment_id or "").strip():
            continue
        unit_roots = (
            support
            if link.role in ("supporting", "corroborating")
            else (contradiction if link.role == "contradictory" else None)
        )
        if unit_roots is not None:
            unit_roots.setdefault(derivation_root_key(link), []).append(link)

    unmet_conditions = [
        _condition_unit(key, raw_spec["support_conditions"][key])
        for key in declared
        if key not in matched_conditions
    ]

    judgment = judge_work(db, [hid]).get(hid)
    requirements: list[str] = []
    if judgment is not None:
        if not judgment.runnable:
            message = blocker_message(judgment)
            if message:
                requirements.append(f"blocked: {message}")
        for task_id in judgment.external_task_ids:
            requirements.append(f"external task={task_id}")
    work_ref = next(
        (ref for ref in open_work_refs(db) if hid in ref.hypothesis_ids), None
    )
    if work_ref is not None:
        requirements.extend(f"gap={gid}" for gid in work_ref.gap_ids)
        requirements.extend(f"task={tid}" for tid in work_ref.task_ids)

    # Deterministic ordering with a hard cap so a long history cannot flood
    # the per-attempt prompt; truncation is only ever arithmetic (sorted).
    deduped_requirements = list(dict.fromkeys(requirements))
    return WorkContextSnapshot(
        hypothesis_id=hid,
        status=str(row[0] or "active"),
        capabilities=tuple(capabilities),
        unready_capabilities=tuple(
            judgment.unavailable_capabilities if judgment else ()
        ),
        unmet_conditions=tuple(sorted(unmet_conditions)),
        support_roots=tuple(
            _root_unit(label, group)
            for label, group in sorted(support.items())[:max_units]
        ),
        contradiction_roots=tuple(
            _root_unit(label, group)
            for label, group in sorted(contradiction.items())[:max_units]
        ),
        reevaluation_required=tuple(sorted(reevaluation)[:max_units]),
        requirements=tuple(deduped_requirements[: max_units * 4]),
    )
