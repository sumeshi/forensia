"""Canonical verification semantics for admitted hypotheses.

``VerificationSpec`` is the single representation of one hypothesis' test
policy.  Rule and LLM declarations use the planning vocabulary
(``confirm_when`` / ``refute_when`` / ``evidence_requirements``);
``VerificationSpec.from_declaration`` converts such declarations into a spec once
at admission.  Afterwards the model, storage, and evaluators read only the
spec — there is no second condition representation to keep in sync, and no
reader falls back to declaration-shaped fields.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

# Shared support-condition vocabulary ("confirm_when" / VerificationSpec
# support_conditions).  This is the single owner of the condition-key set that
# admission and Assessment agree on, so a spec admitted with a key is always
# evaluable at Assessment.  Each key and where it is evaluated:
#
# - ``co_observed_event_ids``: integer event IDs that must all be observed in
#   the evidence group.  Required by the admission pre-screen
#   (``_claim_spec_conformance_error``); evaluated through the co-observation
#   adapter (``investigation/verification/check_guardrails._co_observation_satisfied``).
# - ``event_contexts``: catalog-qualified channel/provider declarations for
#   provider-reused event IDs.  Admission validates each declaration against
#   the event catalog; the co-observation adapter filters rows through
#   ``_context_qualified_rows`` before checking ID presence.
# - ``same_host`` / ``within_minutes`` / ``same_entities`` / ``min_count``:
#   correlation constraints evaluated by the co-observation adapter at
#   Assessment; admission additionally cross-checks them against the claim
#   wording.
# - ``event_constraints``: per-event field constraints of the shape
#   ``{event_id: {field: [values]}}`` (for example requiring
#   ``logon_type=10`` on the 4624 rows of an RDP hypothesis).  Evaluated
#   before host/entity/time correlation by the shared co-observation adapter
#   at Assessment and Settlement, so the gates use the same witnesses. A
#   declared event absent from the rows, or a constraint field no row
#   carries, fails closed with an explicit reason.
#
# Condition keys outside this set are never treated as satisfied: Assessment
# keeps the observation contextual and records an explicit unsupported-key
# reason.  In particular ``keywords`` (declared by some rulepacks next to
# ``co_observed_event_ids``) is NOT an observation condition: nothing in the
# pipeline evaluates it over rows, so it stays outside the vocabulary and a
# spec that carries it fails closed at Assessment with an explicit reason.
# Keywords used by the planner/checker live in ``fallback_search[].keywords``
# and ``event_ids.yaml`` (``keywords_for_string_search``), a separate
# planner-facing vocabulary.  Refute conditions use a separate vocabulary
# (for example ``zero_rows``) owned by the settlement gates.
EVALUABLE_CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "co_observed_event_ids",
        "event_contexts",
        "same_host",
        "within_minutes",
        "same_entities",
        "min_count",
        "event_constraints",
        "observation",
    }
)


def clean_support_conditions(conditions: dict[str, Any]) -> dict[str, Any]:
    """Keep only finding/event IDs in a support condition's ``co_observed_event_ids``.

    Validates that each entry is either a valid finding_id (matching DB id
    pattern) or an integer event id.  Drops keypoint names and free text.
    Mutates and returns ``conditions``; returns ``{}`` when nothing remains.
    """

    co_observed = conditions.get("co_observed_event_ids")
    if not co_observed or not isinstance(co_observed, list):
        return conditions
    cleaned: list[Any] = []
    for entry in co_observed:
        entry_str = str(entry).strip()
        if not entry_str:
            continue
        # Keep valid finding_ids (pattern: windows-xxx-yyyy-xxxx-xxxx)
        if re.match(r"^[a-z]+-[a-z0-9]+-[0-9]+-[a-z0-9-]+$", entry_str):
            cleaned.append(entry_str)
            continue
        # Keep valid event_ids (pure integers, stored as integers)
        try:
            cleaned.append(int(entry_str))
        except ValueError:
            continue
    if not cleaned:
        conditions.pop("co_observed_event_ids", None)
    else:
        conditions["co_observed_event_ids"] = cleaned
    return conditions if any(conditions.values()) else {}


class VerificationSpec(BaseModel):
    """Versioned, serializable verification policy for one hypothesis.

    The condition payloads intentionally remain structured JSON: rulepacks
    and future artifact families may add condition keys without a schema
    migration.  Unknown top-level fields are rejected (``extra="forbid"``) so
    a stored spec in an unsupported format fails explicitly instead of being
    silently reinterpreted.
    """

    model_config = ConfigDict(extra="forbid")

    CURRENT_VERSION: ClassVar[str] = "1"

    spec_version: Literal["1"] = CURRENT_VERSION
    support_conditions: dict[str, Any] = Field(default_factory=dict)
    refute_conditions: dict[str, Any] = Field(default_factory=dict)
    required_capabilities: list[str] = Field(default_factory=list)
    # Declared scope/correlation metadata.  They have exactly one consumer:
    # ``sql_absence_scope`` keeps the absence scope "unknown" for a spec that
    # declares a scope or correlation the simple EVTX lookup rule cannot
    # certify, so the settlement gate refuses to treat emptiness as a refuted
    # condition it cannot observe.
    scope: dict[str, Any] = Field(default_factory=dict)
    correlation: dict[str, Any] = Field(default_factory=dict)
    evidence_requirements: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_declaration(
        cls,
        *,
        confirm_when: Any = None,
        refute_when: Any = None,
        evidence_requirements: Any = None,
    ) -> VerificationSpec:
        """Convert the current rule/LLM declaration vocabulary at admission."""

        def object_or_empty(value: Any, name: str) -> dict[str, Any]:
            if value is None:
                return {}
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be a JSON object")
            return deepcopy(value)

        return cls(
            support_conditions=clean_support_conditions(
                object_or_empty(confirm_when, "confirm_when")
            ),
            refute_conditions=object_or_empty(refute_when, "refute_when"),
            evidence_requirements=object_or_empty(
                evidence_requirements, "evidence_requirements"
            ),
        )
