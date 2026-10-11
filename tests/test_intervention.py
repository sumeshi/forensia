from __future__ import annotations

import json

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.investigation import intervention
from forensia.investigation.case_policy import (
    CasePolicyInput,
    decide_policy,
    load_recorded_policy,
    update_policy_sections,
)


def test_policy_intervention_updates_objective_and_records_receipt(
    tmp_path, monkeypatch
):
    case = Case.init(tmp_path / "case")
    policy = "# Objective\n\nDetermine whether Alice accessed the host.\n\n# Guidance\n\nPrioritize logon evidence."
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {
            "action": "update_policy",
            "policy_updates": {
                "objective": "Determine whether Alice accessed the host.",
                "guidance": "Prioritize logon evidence.",
            },
        },
    )

    with CaseDB(case) as db:
        result = intervention.apply_intervention(
            case,
            db,
            "Investigate Alice's access and focus on logon evidence.",
            base_url="http://local.test",
            model="test-model",
        )
        assert result["status"] == "applied"
        assert result["new_policy"].strip() == policy
        assert (
            db.execute(
                "SELECT objective FROM investigation_state WHERE state_id = 'case'"
            ).fetchone()[0]
            == "Determine whether Alice accessed the host."
        )
        assert load_recorded_policy(db)["body"].strip() == policy
        trace = db.execute(
            "SELECT input_json FROM trace.investigation_steps WHERE phase = ?",
            ["human-intervention"],
        ).fetchone()[0]
        assert "Investigate Alice's access" in json.loads(trace)["text"]


def test_policy_intervention_uses_same_half_prompt_budget_as_file_adoption(
    tmp_path, monkeypatch
):
    case = Case.init(tmp_path / "case")
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {
            "action": "update_policy",
            "policy_updates": {"objective": "x" * 60},
        },
    )
    monkeypatch.setattr(
        "forensia.investigation.case_policy.get_system_prompt_budget_chars",
        lambda: 100,
    )

    with CaseDB(case) as db:
        result = intervention.apply_intervention(
            case,
            db,
            "Adopt a longer policy.",
            base_url="http://local.test",
            model="test-model",
        )
        assert result["status"] == "rejected"
        assert "budget allows 50 chars" in result["reason"]
        assert load_recorded_policy(db) is None


def test_policy_intervention_preserves_unedited_tail(tmp_path, monkeypatch):
    case = Case.init(tmp_path / "case")
    tail = "# Guidance\n\n" + "Retain original directions. " * 260
    tail += "\n\n# Constraints\n\nNever investigate excluded-host.\n"
    original = "# Objective\n\nInvestigate the acquired artifacts.\n\n" + tail
    assert len(original) > 6000
    sent = []

    def proposal(messages, **_kwargs):
        sent.extend(messages)
        return {
            "action": "update_policy",
            "policy_updates": {"priority": "Prioritize host-A."},
        }

    monkeypatch.setattr(intervention, "request_llm_json", proposal)
    with CaseDB(case) as db:
        receipt = decide_policy(
            CasePolicyInput(original, "explicit_path", "operator.md"), None
        ).record
        db.execute(
            "INSERT INTO trace.investigation_steps "
            "(step_id, session_id, iteration, phase, output_json, created_at) "
            "VALUES ('policy-initial', 'initial', 0, 'forensia-md', ?, now())",
            [json.dumps(receipt)],
        )
        result = intervention.apply_intervention(
            case, db, "Prioritize host-A.", base_url="http://local.test", model="test"
        )
        adopted = load_recorded_policy(db)
    assert result["status"] == "applied"
    assert adopted["body"].startswith(original)
    assert adopted["body"].count("Never investigate excluded-host.") == 1
    assert json.loads(sent[1]["content"])["case_context"]["current_policy"] == original
    assert result["previous_policy_sha256"] == receipt["content_sha256"]
    assert result["updated_sections"] == ["priority"]
    nested = "# Objective\n\nOld objective.\n\n## Constraints\n\nPreserve this.\n"
    updated = update_policy_sections(nested, {"objective": "New objective."})
    assert updated.endswith("## Constraints\n\nPreserve this.\n")


def test_work_intervention_uses_existing_gap_admission(tmp_path, monkeypatch):
    case = Case.init(tmp_path / "case")
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {
            "action": "add_work",
            "work_description": "Confirm with the business owner whether maintenance activity was approved.",
            "required_entities": [],
            "confirm_when": None,
        },
    )

    with CaseDB(case) as db:
        result = intervention.apply_intervention(
            case,
            db,
            "Ask the owner whether this maintenance was approved.",
            base_url="http://local.test",
            model="test-model",
        )
        assert result["status"] == "applied"
        assert result["refs"]["task_id"]
        assert db.execute(
            "SELECT origin, status FROM report_gaps WHERE gap_id = ?",
            [result["refs"]["gap_id"]],
        ).fetchone() == ("human", "open")


def test_prioritization_persists_active_hypothesis_preference(tmp_path, monkeypatch):
    case = Case.init(tmp_path / "case")
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {
            "action": "prioritize_hypothesis",
            "hypothesis_id": "H-1",
        },
    )
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status, created_at, updated_at) "
            "VALUES ('H-1', 'Existing test hypothesis', 'deferred', now(), now())"
        )
        result = intervention.apply_intervention(
            case,
            db,
            "Prioritize H-1.",
            base_url="http://local.test",
            model="test-model",
        )
        assert (
            db.execute(
                "SELECT preferred_hypothesis_id FROM investigation_state WHERE state_id = 'case'"
            ).fetchone()[0]
            == "H-1"
        )
        assert (
            db.execute(
                "SELECT status FROM hypotheses WHERE hypothesis_id = 'H-1'"
            ).fetchone()[0]
            == "deferred"
        )
    assert result["status"] == "applied"
    assert result["refs"]["hypothesis_id"] == "H-1"


def test_prioritization_rejects_missing_hypothesis_id(tmp_path, monkeypatch):
    case = Case.init(tmp_path / "case")
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {
            "action": "prioritize_hypothesis",
            "hypothesis_id": "missing-id",
        },
    )
    with CaseDB(case) as db:
        result = intervention.apply_intervention(
            case,
            db,
            "Prioritize missing-id.",
            base_url="http://local.test",
            model="test-model",
        )
    assert result["status"] == "rejected"
    assert result["reason"] == "hypothesis_not_found"


def test_invalid_proposal_fails_closed_and_preserves_user_instruction(
    tmp_path, monkeypatch
):
    case = Case.init(tmp_path / "case")
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {"action": "add_work", "work_description": ""},
    )
    with CaseDB(case) as db:
        result = intervention.apply_intervention(
            case,
            db,
            "Please examine the suspicious logon.",
            base_url="http://local.test",
            model="test-model",
        )
        trace = db.execute(
            "SELECT input_json FROM trace.investigation_steps WHERE phase = ?",
            ["human-intervention"],
        ).fetchone()[0]
    assert result["status"] == "failed"
    assert "Please examine" in json.loads(trace)["text"]
