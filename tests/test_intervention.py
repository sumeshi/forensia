from __future__ import annotations

import json

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.investigation import intervention
from forensia.investigation.case_policy import load_recorded_policy


def test_policy_intervention_updates_objective_and_records_receipt(
    tmp_path, monkeypatch
):
    case = Case.init(tmp_path / "case")
    policy = "# Objective\n\nDetermine whether Alice accessed the host.\n\n# Guidance\n\nPrioritize logon evidence."
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {"action": "update_policy", "policy_body": policy},
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
        assert result["new_policy"] == policy
        assert (
            db.execute(
                "SELECT objective FROM investigation_state WHERE state_id = 'case'"
            ).fetchone()[0]
            == "Determine whether Alice accessed the host."
        )
        assert load_recorded_policy(db)["body"] == policy
        trace = db.execute(
            "SELECT input_json FROM trace.investigation_steps WHERE phase = ?",
            ["human-intervention"],
        ).fetchone()[0]
        assert "Investigate Alice's access" in json.loads(trace)["text"]


def test_policy_intervention_uses_same_half_prompt_budget_as_file_adoption(
    tmp_path, monkeypatch
):
    case = Case.init(tmp_path / "case")
    policy = "# Objective\n\n" + ("x" * 60)
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {"action": "update_policy", "policy_body": policy},
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
