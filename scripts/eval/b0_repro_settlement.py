"""L3 reproduction: repeated zero-row inconclusive vs rule refutation.

Runs decide_settlement (deterministic, no LLM) with the auto-refute trigger
(consecutive_zero_row_inconclusive=3 plus has_rule_refute_when_zero_rows=True).

- B0 (rev 242ca6a): verdict="refuted" for every coverage state (partial,
  unavailable, unknown) — the zero-row branch returned `auto_refute_zero_rows`
  before any coverage gate was consulted (recorded in
  git revision `68b2ba6:docs/round-b0-baseline.md`, section 4).
- M0 (T03): refutation additionally requires the runner-supplied scope-wise
  absence judgment (`absence_scope="observable"`).  Without it the hypothesis
  downgrades to untestable on `auto_untestable_zero_rows` with the reason
  naming why the absence is not observable; with it the rule-declared refute
  path is preserved.
"""

from __future__ import annotations

import json

from forensia.ai.checking.settlement import SettlementInput, decide_settlement
from forensia.core.session import Hypothesis

STATES = ("partial", "unavailable", "unknown")


def main() -> None:
    results = []
    for state in STATES:
        si = SettlementInput(
            hypothesis=Hypothesis(
                id="H-001",
                description="PowerShell 4104 password reset context",
            ),
            checker_verdict="inconclusive",
            check_summary="three consecutive 0-row searches",
            consecutive_zero_row_inconclusive=3,
            has_rule_refute_when_zero_rows=True,
        )
        coverage = {"evtx:powershell_operational": {"state": state}}
        decision = decide_settlement(si, links=[], coverage=coverage)
        results.append(
            {
                "capability_state": state,
                "verdict": decision.verdict,
                "reason": decision.reason,
                "gates_passed": list(decision.gates_passed),
            }
        )
    observable = SettlementInput(
        hypothesis=Hypothesis(
            id="H-002",
            description="PowerShell 4104 password reset context",
        ),
        checker_verdict="inconclusive",
        check_summary="three consecutive 0-row searches",
        consecutive_zero_row_inconclusive=3,
        has_rule_refute_when_zero_rows=True,
        absence_scope="observable",
        absence_note="",
    )
    observable_decision = decide_settlement(
        observable,
        links=[],
        coverage={"evtx:powershell_operational": {"state": "available"}},
    )
    print(
        json.dumps(
            {
                "cases": results,
                "observable_absence_case": {
                    "verdict": observable_decision.verdict,
                    "reason": observable_decision.reason,
                    "gates_passed": list(observable_decision.gates_passed),
                },
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
