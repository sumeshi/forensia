from __future__ import annotations

import os
from typing import Any

from forensia.ai.prompts.prompt_playbook import (
    PLAYBOOK_SECTION_DROP_ORDER,
    dfir_playbook,
    load_dfir_yamls_cached,
    render_event_narrative,
)


def test_filter_event_ids_reduces_size() -> None:
    """With a subset of event IDs (12 items), playbook has fewer event lines."""
    full = dfir_playbook("check", event_ids=None)
    filtered = dfir_playbook(
        "check",
        event_ids={
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
        },
    )
    full_events = full.count(" - Event ")
    filtered_events = filtered.count(" - Event ")
    assert filtered_events <= 12, f"Expected ≤12 event entries, got {filtered_events}"
    if full_events > 0:
        assert filtered_events < full_events


def test_filter_event_ids_caps_at_forty() -> None:
    """Event narrative is capped at 40 entries when event_ids is large."""
    render_event_narrative(load_dfir_yamls_cached()["event_ids"].get("events", {}))
    many_ids = set(range(1, 200))
    playbook = dfir_playbook("check", event_ids=many_ids)
    assert "Event ID Reference" in playbook
    # Count event ID entries in the playbook — each starts with " - Event "
    id_count = playbook.count(" - Event ")
    assert id_count <= 40, f"Expected ≤40 event IDs, got {id_count}"


def test_filter_event_ids_includes_hypothesis_context_ids() -> None:
    """Hypothesis-referenced event IDs not in the case set are still rendered."""
    playbook = dfir_playbook("check", event_ids={9999})
    assert " - Event 9999" in playbook or "No event ID reference" in playbook


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


def test_tables_gate_ioc_with_mft() -> None:
    """IOC catalog included when MFT/prefetch present in tables."""
    playbook = dfir_playbook(
        "check", event_ids=_SMALL_EVENT_IDS, tables={"prefetch_executions"}
    )
    assert "IOC Catalog" in playbook


def test_tables_gate_ioc_excluded_without_mft_prefetch() -> None:
    """IOC catalog excluded when no MFT/prefetch in tables for check phase."""
    playbook = dfir_playbook(
        "check", event_ids=_SMALL_EVENT_IDS, tables={"evtx_events"}
    )
    assert "IOC Catalog" not in playbook


def test_tables_none_includes_all_sections() -> None:
    """When tables=None (default with filtering), sections are included by phase."""
    playbook = dfir_playbook("check", event_ids=_SMALL_EVENT_IDS, tables=None)
    assert "Event ID Reference" in playbook
    assert "Logon Type Reference" in playbook
    assert "False-Positive Reduction Guidance" in playbook


def test_budget_enforcement_drops_sections_in_order(tmp_path: Any) -> None:
    """With a tiny budget, sections drop in declared priority order."""
    from forensia.config import get_system_prompt_budget_chars, reload_settings

    old_budget = os.environ.get("FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS")
    os.environ["FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS"] = "1000"
    reload_settings()
    try:
        assert get_system_prompt_budget_chars() == 1000

        playbook = dfir_playbook("check")
        # With 1KB budget, sections are aggressively dropped.
        # The full playbook is ~69KB; a 1KB budget forces most sections out.
        # Only preamble, priority sections + phase MD (~3.5KB) remain.
        assert len(playbook) < 10000  # well under full size
    finally:
        if old_budget is not None:
            os.environ["FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS"] = old_budget
        else:
            os.environ.pop("FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS", None)
        reload_settings()


def test_budget_drop_order_is_stable() -> None:
    """Drop order is deterministic: IOC → app → artifact → extractor → FP → logon → schema → events."""
    expected = [
        "ioc",  # first to drop
        "app",  # application catalog
        "artifact",  # artifact inference
        "logon",  # logon types
        "events",  # event IDs
        "priority",  # priority investigation order
        "fp",  # false-positive guidance
        "extractor",  # JSON extractors
        "schema",  # schema notes — highest priority, last to drop
    ]
    assert PLAYBOOK_SECTION_DROP_ORDER == expected


def test_empty_event_ids_still_produces_playbook() -> None:
    """Empty event_ids set doesn't crash — falls back to minimal playbook."""
    playbook = dfir_playbook("hypothesis_plan", event_ids=set())
    assert len(playbook) > 0
    assert "DFIR_PLAYBOOK" in playbook or "No event ID reference" in playbook


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


def test_collect_event_ids_helper() -> None:
    """_collect_event_ids extracts ints from evidence result rows."""
    from forensia.ai.prompts.prompt_context import _collect_event_ids

    results = [
        {"sample_rows": [{"event_id": 4624}, {"event_id": 4625}]},
        {"sample_rows": [{"event_id": 4624, "computer": "X"}]},
        {"head_rows": [{"event_id": 4688}]},
    ]
    ids = _collect_event_ids(results)
    assert 4624 in ids
    assert 4625 in ids
    assert 4688 in ids
    assert len(ids) == 3


def test_no_profile_playbook_truncates_events_instead_of_dropping_everything():
    """Without a case profile the full Event ID Reference (~55 KB) exceeds the
    default budget. The fix shrinks it to the declarative priority_events list
    so the other guidance sections survive, instead of the serial drop loop
    discarding every droppable section (the pre-fix behavior left only the
    Priority Investigation Order)."""
    from forensia.ai.case_profile import set_case_profile
    from forensia.ai.prompts.prompt_playbook import dfir_playbook
    from forensia.config import get_system_prompt_budget_chars

    set_case_profile(None, None)
    try:
        playbook = dfir_playbook("report_section")
    finally:
        set_case_profile(None, None)

    assert "priority events only" in playbook
    assert "## False-Positive Reduction Guidance" in playbook
    assert "## Application Catalog" in playbook
    assert "## Logon Type Reference" in playbook
    # Stays in the same order of magnitude as the budget (phase narrative is
    # appended after enforcement, so allow headroom above the raw budget).
    assert len(playbook) < get_system_prompt_budget_chars() * 1.5


def testsections_for_hypothesis_auth_excludes_catalogs() -> None:
    """An auth-only hypothesis must not pull file/tool catalogs into context.

    Why: catalog sections are interpretation aids for executable/file
    evidence. Including them for a pure authentication hypothesis dilutes
    the prompt for weak local models without adding signal (G-1).
    """
    from forensia.ai.prompts.prompt_playbook import sections_for_hypothesis
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
    from forensia.ai.prompts.prompt_playbook import sections_for_hypothesis
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
    """No event IDs and no entities → None (full playbook, backward safe)."""
    from forensia.ai.prompts.prompt_playbook import sections_for_hypothesis
    from forensia.core.session import Hypothesis

    assert sections_for_hypothesis(Hypothesis(id="H-003", description="x")) is None
