from __future__ import annotations

from dataclasses import replace
from typing import Any

from forensia.context.playbook import (
    _dfir_playbook as dfir_playbook,
)

_SMALL_EVENT_IDS = {
    4624,
    4625,
    4648,
    4688,
    4697,
    7045,
    1102,
    104,
    4768,
    4771,
    4720,
    4724,
}


def test_tables_gate_excludes_artifact_when_no_mft_prefetch() -> None:
    """Artifact inference section excluded when tables set lacks MFT/prefetch."""
    playbook = dfir_playbook(
        "check", event_ids=_SMALL_EVENT_IDS, tables={"evtx_events"}
    )
    assert "Artifact-to-Application Inference" not in playbook


def test_tables_gate_includes_artifact_when_mft_present() -> None:
    """Artifact inference section included when MFT is in tables."""
    playbook = dfir_playbook(
        "check", event_ids=_SMALL_EVENT_IDS, tables={"evtx_events", "mft_entries"}
    )
    assert "Artifact-to-Application Inference" in playbook


def test_total_prompt_budget_is_configurable_and_auto_derived() -> None:
    from forensia.config import (
        get_prompt_budget_tokens,
        get_settings,
        get_system_prompt_budget_chars,
        settings_scope,
    )

    base = get_settings()
    with settings_scope(
        replace(
            base, forensia_system_prompt_budget_chars=0, forensia_prompt_budget_tokens=0
        )
    ):
        assert get_prompt_budget_tokens() == 12000
        assert get_system_prompt_budget_chars() == 24000
    with settings_scope(
        replace(
            base,
            forensia_system_prompt_budget_chars=0,
            forensia_prompt_budget_tokens=32000,
        )
    ):
        assert get_prompt_budget_tokens() == 32000
        assert get_system_prompt_budget_chars() == 64000


def test_table_gating_planning_phases() -> None:
    """Planning phases exclude artifact/IOC regardless of tables."""
    for phase in ("broad_plan", "hypothesis_plan"):
        playbook = dfir_playbook(
            phase,
            event_ids=_SMALL_EVENT_IDS,
            tables={"mft_entries", "prefetch_executions"},
        )
        assert "Artifact-to-Application Inference" not in playbook, (
            f"{phase} should exclude artifact"
        )
        assert "False-Positive Reduction Guidance" not in playbook, (
            f"{phase} should exclude FP"
        )


def test_combined_filtering_reaches_budget(tmp_path: Any) -> None:
    """With event_ids filter + tables gate, playbook fits within 24KB default budget."""
    from forensia.config import get_system_prompt_budget_chars

    budget = get_system_prompt_budget_chars()
    event_subset = {
        4624,
        4625,
        4648,
        4688,
        4697,
        7045,
        1102,
        104,
        4720,
        4724,
        4768,
        4771,
        4672,
        4732,
        4738,
        5136,
        5156,
        5158,
    }
    playbook = dfir_playbook("check", event_ids=event_subset, tables={"evtx_events"})
    assert len(playbook) <= budget, f"playbook {len(playbook)} > budget {budget}"


def testsections_for_hypothesis_auth_excludes_catalogs() -> None:
    """An auth-only hypothesis must not pull file/tool catalogs into context.

    Why: catalog sections are interpretation aids for executable/file
    evidence. Including them for a pure authentication hypothesis dilutes
    the prompt for weak local models without adding signal.
    """
    from forensia.context.playbook import (
        _sections_for_hypothesis as sections_for_hypothesis,
    )
    from forensia.core.session import Hypothesis

    auth = Hypothesis(
        id="H-001",
        description="credential reuse via explicit credentials",
        confirm_when={"co_observed_event_ids": [4648]},
    )
    sections = sections_for_hypothesis(auth)
    assert sections is not None
    assert "logon_types" in sections
    assert "ioc_catalog" not in sections
    assert "app_catalog" not in sections

    narrowed = dfir_playbook("check", event_ids={4648}, sections=sections)
    full = dfir_playbook("check", event_ids={4648})
    assert "## IOC Catalog" not in narrowed
    assert len(narrowed) < len(full)


def testsections_for_hypothesis_exec_includes_catalogs() -> None:
    """A hypothesis about executables keeps the catalog interpretation aids."""
    from forensia.context.playbook import (
        _sections_for_hypothesis as sections_for_hypothesis,
    )
    from forensia.core.session import Hypothesis

    exe = Hypothesis(
        id="H-002",
        description="anti-forensic tool execution",
        required_entities=["executable_name"],
    )
    sections = sections_for_hypothesis(exe)
    assert sections is not None
    assert {"ioc_catalog", "app_catalog", "artifact_inference"} <= sections


def testsections_for_hypothesis_no_signal_returns_none() -> None:
    """No event IDs and no entities means there is no signal for narrowing."""
    from forensia.context.playbook import (
        _sections_for_hypothesis as sections_for_hypothesis,
    )
    from forensia.core.session import Hypothesis

    assert sections_for_hypothesis(Hypothesis(id="H-003", description="x")) is None


def test_dfir_playbook_discloses_selected_event_rules_and_instruments(
    tmp_path: Any,
) -> None:
    """Selected event IDs are disclosed directly without an unreachable index."""
    from forensia.core.case import Case
    from forensia.db.database import CaseDB

    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        playbook = dfir_playbook(
            "check", event_ids={4624, 4625}, db=db, session_id="S-1"
        )
        assert "<EVENT_ID_INDEX>" not in playbook
        assert " - Event 4624" in playbook
        assert " - Event 4625" in playbook
        assert "load event rule" not in playbook
        assert "First check events [1102, 104]" not in playbook
        row = db.execute("SELECT source_kind FROM trace.retrieval_events").fetchone()
        assert row is not None
        assert row[0] == "dfir_playbook"
