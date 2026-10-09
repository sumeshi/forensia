"""L1 reproduction: admission-accepted `event_contexts` at Assessment.

Runs assess_evidence_group (deterministic, no LLM) with a VerificationSpec whose
support_conditions declare `event_contexts`, `co_observed_event_ids` and
`same_host`, against EVTX rows.

- B0 (rev 242ca6a): role="contextual" for every case — `_condition_matches`
  rejected the un-shared `event_contexts` key even though admission accepted it
  (recorded in git revision `68b2ba6:docs/round-b0-baseline.md`, section 4).
- M0 (T01): the shared vocabulary (`core.verification.EVALUABLE_CONDITION_KEYS`)
  makes `event_contexts` evaluable through the co-observation adapter, so
  catalog-qualified rows reach `supporting`; rows that do not carry the declared
  channel/provider context still fail closed (contextual).
"""

from __future__ import annotations

import json

from forensia.ai.checking.assessment import assess_evidence_group
from forensia.core.session import Hypothesis

CONFIRM_WHEN = {
    "co_observed_event_ids": [4624, 4104],
    "event_contexts": [
        {
            "event_id": 4104,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
        },
        {
            "event_id": 4624,
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
        },
    ],
    "same_host": True,
}

QUALIFIED_ROWS = [
    {
        "event_id": 4624,
        "computer": "PC",
        "user": "j.doe",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
    },
    {
        "event_id": 4104,
        "computer": "PC",
        "user": "j.doe",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "provider": "Microsoft-Windows-PowerShell",
    },
]

UNQUALIFIED_ROWS = [
    {"event_id": 4624, "computer": "PC", "user": "j.doe"},
    {"event_id": 4104, "computer": "PC", "user": "j.doe"},
]


def assess(rows: list[dict[str, object]]) -> dict[str, object]:
    hypothesis = Hypothesis(
        id="H-001",
        description="RDP logon co-observed with PowerShell scriptblock",
        confirm_when=CONFIRM_WHEN,
    )
    spec = hypothesis.verification_spec
    support = dict(spec.support_conditions) if spec else {}
    assessment = assess_evidence_group(
        hypothesis=hypothesis,
        rows=rows,
        evidence_ids=["evtx-4624-a", "evtx-4104-b"],
    )
    return {
        "admitted_support_condition_keys": sorted(support),
        "role": assessment.role,
        "reason": assessment.reason,
        "matched_conditions": list(assessment.matched_conditions),
        "spec_version": assessment.spec_version,
    }


def main() -> None:
    print(
        json.dumps(
            {
                "admission_check": (
                    "qualify_event_contexts binds event_contexts at admission"
                ),
                "catalog_qualified_rows": assess(QUALIFIED_ROWS),
                "rows_without_declared_context": assess(UNQUALIFIED_ROWS),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
