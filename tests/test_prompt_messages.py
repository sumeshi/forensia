from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from forensia.context.case_profile import CaseEvidenceProfile
from forensia.context.prompt_context import (
    _build_schema_guidance,
    fit_prompt_messages,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.report.sections.evidence_projection import (
    project_report_evidence_row,
)
from forensia.report.sections.prompts import (
    build_paragraph_narrate_messages,
)
from forensia.report.sections.section_quality import validate_body_evidence_ids


class PromptMessageTests(unittest.TestCase):
    def test_rendered_prompts_use_nested_evtx_fields_and_neutral_claims(self) -> None:
        from pathlib import Path

        import duckdb
        import yaml

        from forensia.context.playbook import _dfir_playbook

        playbook = _dfir_playbook("hypothesis_plan")
        self.assertIn("$.winlog.event_data.TargetUserName", playbook)
        self.assertNotIn("$.winlog.event_data.TargetDomainName') as fallback", playbook)
        check_prompt = _dfir_playbook("check")
        self.assertIn(
            "VerificationSpec's support conditions pass in Assessment", check_prompt
        )
        self.assertIn("never translate a numeric confidence threshold", check_prompt)
        self.assertIn("at least three consecutive zero-row", check_prompt)
        self.assertNotIn(
            "MUST explicitly name the specific missing entity type", check_prompt
        )
        self.assertNotIn(
            "Use 'refuted' if the hypothesis claim is clearly disproven", check_prompt
        )

        schema_path = (
            Path(__file__).parents[1] / "src/forensia/data/schema/evtx_events.yaml"
        )
        extractors = yaml.safe_load(schema_path.read_text())["json_field_extractors"]
        with duckdb.connect() as connection:
            connection.execute("CREATE TABLE events (raw_json JSON)")
            connection.execute(
                "INSERT INTO events VALUES (?)",
                [
                    '{"winlog":{"event_data":{"TargetUserName":"alice",'
                    '"TargetDomainName":"EXAMPLE"}}}'
                ],
            )
            user_sql = extractors["TargetUserName"]
            self.assertEqual(
                connection.execute(f"SELECT {user_sql} FROM events").fetchone()[0],
                "alice",
            )
            self.assertNotEqual(
                connection.execute(
                    f"SELECT {extractors['TargetDomainName']} FROM events"
                ).fetchone()[0],
                "alice",
            )

        messages, _ = build_paragraph_narrate_messages(
            heading="Authentication Activity",
            key_points=[],
            evidence_rows=[],
            template_body="",
        )
        rendered = messages[0]["content"]
        self.assertIn(
            "Distinguish an observed attempt from a successful logon", rendered
        )
        self.assertNotIn("localhost credential injection", rendered)
        self.assertNotIn("All attempts succeeded", rendered)
        self.assertIn("<raw evidence_id from the supporting row>", rendered)
        self.assertNotIn("identified host", rendered)

    def test_prompt_projection_decodes_and_bounds_json_arrays(self) -> None:
        from forensia.context.prompt_context import prompt_value_projection

        projected = prompt_value_projection('["a", "b", "c", "d"]')

        self.assertEqual(
            projected,
            {"count": 4, "sample": ["a", "b", "c"], "omitted_count": 1},
        )

    def test_array_observation_example_uses_disclosed_value(self) -> None:
        from forensia.db.evidence_lookup import fetch_evidence_records
        from forensia.investigation import prompts
        from forensia.investigation.planner import _typed_observation_query
        from forensia.investigation.verification.assessment import assess_evidence_group

        path = r"\\server\share\file.txt"
        candidate = {
            "evidence": [
                {
                    "evidence_id": "prefetch-p1",
                    "_source": "prefetch_executions",
                    "filenames": json.dumps([path, "b", "c", "omitted"]),
                }
            ]
        }
        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            messages, _ = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "host_execution_activity"},
                [],
                observed_candidate=candidate,
            )
        text = "\n".join(message["content"] for message in messages)
        description = (
            "At least 1 prefetch observation has filenames contains "
            + json.dumps(path)
            + "."
        )
        self.assertIn(json.dumps(path), text)
        observed = json.loads(
            text.split("<OBSERVED_CANDIDATE>\n", 1)[1].split(
                "\n</OBSERVED_CANDIDATE>", 1
            )[0]
        )
        self.assertEqual(
            observed["observations"][0]["filenames"],
            {
                "count": 4,
                "sample": [path, "b", "c"],
                "omitted_count": 1,
            },
        )
        hypothesis = Hypothesis(
            id="H-array",
            description=description,
            confirm_when={
                "observation": {
                    "family": "prefetch",
                    "capability": "process_execution",
                    "field": "filenames",
                    "operator": "contains",
                    "value": path,
                },
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            with CaseDB(Case.init(temp_dir)) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, source_file, filenames) VALUES (?, ?, ?)",
                    ["prefetch-p1", "source", candidate["evidence"][0]["filenames"]],
                )
                query = _typed_observation_query(
                    hypothesis=hypothesis,
                    spec_payload=hypothesis.verification_spec.model_dump(mode="json"),
                    query_index=1,
                    db=db,
                )
                self.assertIsNotNone(query)
                self.assertEqual(db.execute(query.sql).fetchall(), [("prefetch-p1",)])
                row = fetch_evidence_records(db, ["prefetch-p1"])["prefetch-p1"]
                self.assertEqual(
                    row["filenames"], candidate["evidence"][0]["filenames"]
                )
                assessment = assess_evidence_group(
                    hypothesis=hypothesis,
                    rows=[{**row, "source_family": "prefetch"}],
                    evidence_ids=["prefetch-p1"],
                )
                self.assertEqual(assessment.role, "supporting")

    def test_query_prompt_keeps_eligible_scope_without_provider_schema(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        messages = build_query_intent_messages(
            hypothesis=Hypothesis(id="H-mft", description="MFT observation"),
            recent_history=[],
            active_hypotheses=[],
            eligible_tables=("mft_entries", "mft_timeline", "prefetch_executions"),
            prior_check_feedback="Missing EVTX events",
        )
        system = messages[0]["content"]
        self.assertIn(
            'eligible_tables: ["mft_entries", "mft_timeline", "prefetch_executions"]',
            system,
        )
        self.assertNotIn("SELECT evidence_id FROM evtx_events LIMIT 20", system)
        self.assertIn("report the unmet requirement", system)

    """Prompt message content: truncation, guidance blocks, language handling."""

    def test_common_fitter_drops_whole_optional_template_context(self) -> None:
        messages = [
            {"role": "system", "content": "<TASK>Write the report.</TASK>"},
            {
                "role": "user",
                "content": "Required evidence stays.\n<TEMPLATE_CONTEXT>"
                + ("template detail " * 100)
                + "</TEMPLATE_CONTEXT>",
            },
        ]
        with (
            patch(
                "forensia.context.prompt_context.get_llm_settings",
                return_value={"max_tokens": 1, "llm_context_window_tokens": None},
            ),
            patch(
                "forensia.context.prompt_context.get_prompt_budget_tokens",
                return_value=20,
            ),
        ):
            fitted = fit_prompt_messages(messages)

        self.assertIsNotNone(fitted)
        fitted_text = "\n".join(message["content"] for message in fitted or [])
        self.assertIn("<TASK>Write the report.</TASK>", fitted_text)
        self.assertIn("Required evidence stays.", fitted_text)
        self.assertNotIn("TEMPLATE_CONTEXT", fitted_text)
        self.assertNotIn("template detail", fitted_text)

    def test_observed_candidate_drafter_discloses_sigma_fields_and_retrieval_terms(
        self,
    ) -> None:
        from forensia.investigation import prompts

        captured: dict[str, object] = {}

        def capture_knowledge(*, extra_words=None, **_kwargs):
            captured["extra_words"] = extra_words
            return ""

        candidate = {
            "candidate_ref": "cand-test",
            "title": "Suspicious service creation",
            "summary": "Service command launched remotely",
            "scope": {"source_family": "evtx"},
            "evidence_ids": ["evtx-test"],
            "evidence": [
                {
                    "evidence_id": "evtx-test",
                    "event_id": 7045,
                    "command_line": "sc.exe create updater binPath=...",
                    "service_name": "Updater",
                    "logon_type": 3,
                    "subject_user": "CORP\\analyst",
                    "target_group": "Administrators",
                    "target_server": "host-02",
                }
            ],
        }
        rules = [
            {
                "id": "sigma-service-rule",
                "title": "Remote Service Installation",
                "tags": ["attack.persistence", "attack.t1543.003"],
            }
        ]
        with patch.object(
            prompts, "_org_knowledge_block", side_effect=capture_knowledge
        ):
            messages, schema = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "host_execution_activity"},
                rules,
                observed_candidate=candidate,
            )

        joined = "\n".join(message["content"] for message in messages)
        for field in (
            "command_line",
            "service_name",
            "logon_type",
            "subject_user",
            "target_group",
            "target_server",
        ):
            self.assertIn(field, joined)
        self.assertIn("sc.exe create updater", joined)
        self.assertIn("Remote Service Installation", captured["extra_words"])
        self.assertIn("attack.t1543.003", captured["extra_words"])
        self.assertIn("Suspicious service creation", captured["extra_words"])
        required_entity_items = schema["properties"]["hypothesis"]["properties"][
            "required_entities"
        ]["items"]
        self.assertNotIn("evidence_id", required_entity_items["enum"])
        self.assertNotIn("source_file", required_entity_items["enum"])

    def test_hypothesis_drafter_only_discloses_observed_eligible_event_contexts(
        self,
    ) -> None:
        import duckdb

        from forensia.investigation import prompts

        db = duckdb.connect()
        db.execute(
            "CREATE TABLE evtx_events (event_id INTEGER, channel VARCHAR, raw_json JSON)"
        )
        db.executemany(
            "INSERT INTO evtx_events VALUES (?, ?, ?)",
            [
                (
                    4104,
                    "Microsoft-Windows-PowerShell/Operational",
                    json.dumps(
                        {
                            "winlog": {
                                "provider": {"name": "Microsoft-Windows-PowerShell"}
                            }
                        }
                    ),
                ),
                (
                    4104,
                    "Microsoft-Windows-PowerShell/Operational",
                    json.dumps(
                        {
                            "winlog": {
                                "provider": {"name": "Microsoft-Windows-PowerShell"}
                            }
                        }
                    ),
                ),
                (
                    4104,
                    "Application",
                    json.dumps(
                        {
                            "winlog": {
                                "provider": {"name": "Microsoft-Windows-PowerShell"}
                            }
                        }
                    ),
                ),
                (
                    4104,
                    "Microsoft-Windows-PowerShell/Operational",
                    json.dumps({"winlog": {"provider": {"name": "Other-Provider"}}}),
                ),
                (
                    104,
                    "System",
                    json.dumps({"winlog": {"provider": "Microsoft-Windows-Eventlog"}}),
                ),
                (104, "Microsoft-Windows-Diagnosis-Scripted/Operational", "{}"),
            ],
        )

        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            messages, schema = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "host_execution_activity"},
                [],
                case_profile=CaseEvidenceProfile(
                    event_ids=frozenset({4104, 104, 1102}), summary="case events"
                ),
                db=db,
            )

        joined = "\n".join(message["content"] for message in messages)
        self.assertNotIn("<AVAILABLE_TYPED_OBSERVATIONS>", joined)
        self.assertNotIn('"observation":', joined)
        self.assertIn(
            "Typed observations use fields from canonical evidence records", joined
        )
        event_contexts = joined.split("<AVAILABLE_EVENT_CONTEXTS>\n", 1)[1].split(
            "\nUse only listed", 1
        )[0]
        self.assertEqual(
            json.loads(event_contexts),
            [
                {
                    "event_id": 104,
                    "channel": "System",
                    "provider": "Microsoft-Windows-Eventlog",
                },
                {
                    "event_id": 4104,
                    "channel": "Microsoft-Windows-PowerShell/Operational",
                    "provider": "Microsoft-Windows-PowerShell",
                },
            ],
        )
        ids_schema = schema["properties"]["hypothesis"]["properties"]["confirm_when"][
            "properties"
        ]["co_observed_event_ids"]
        self.assertEqual(ids_schema["items"]["enum"], [104, 4104])
        confirm_properties = schema["properties"]["hypothesis"]["properties"][
            "confirm_when"
        ]["properties"]
        self.assertNotIn("observation", confirm_properties)
        self.assertEqual(confirm_properties["min_count"]["minimum"], 1)
        many_contexts = [
            {
                "event_id": event_id,
                "channel": f"channel-{event_id}",
                "provider": f"provider-{event_id}",
            }
            for event_id in range(1, 26)
        ]
        with (
            patch.object(
                prompts, "observed_event_contexts", return_value=many_contexts
            ),
            patch.object(prompts, "_org_knowledge_block", return_value=""),
        ):
            limited_messages, limited_schema = (
                prompts.build_hypothesis_drafter_messages(
                    {"keypoint_id": "host_execution_activity"},
                    [],
                    case_profile=CaseEvidenceProfile(
                        event_ids=frozenset(range(1, 26)), summary="case events"
                    ),
                    db=db,
                    observed_candidate={"evidence": [{"event_id": 25}]},
                )
            )
        limited_contexts = (
            limited_messages[0]["content"]
            .split("<AVAILABLE_EVENT_CONTEXTS>\n", 1)[1]
            .split("\nUse only listed", 1)[0]
        )
        disclosed_contexts = json.loads(limited_contexts)
        self.assertEqual(disclosed_contexts, [])
        self.assertEqual(
            limited_schema["properties"]["hypothesis"]["properties"]["confirm_when"][
                "properties"
            ]["co_observed_event_ids"]["maxItems"],
            0,
        )
        db.close()

    def test_hypothesis_drafter_typed_catalog_matches_candidate_and_schema(
        self,
    ) -> None:
        from forensia.investigation import prompts

        candidate = {
            "evidence": [
                {
                    "evidence_id": "mft-m1",
                    "_source": "mft_entries",
                    "file_path": "C:/ProgramData/updater.exe",
                    "is_deleted": False,
                    "timestamp": "derived timeline value",
                },
                {
                    "evidence_id": "prefetch-p1",
                    "_source": "prefetch_executions",
                    "executable_name": "cmd.exe",
                    "exec_times": ["2025-01-02T03:04:05"],
                    "exec_time": "derived timeline value",
                },
                {
                    "evidence_id": "registry-r1",
                    "_source": "registry_artifacts",
                    "key_path": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run",
                },
            ]
        }

        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            messages, schema = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "persistence"}, [], observed_candidate=candidate
            )

        joined = "\n".join(message["content"] for message in messages)
        block = joined.split("<AVAILABLE_TYPED_OBSERVATIONS>\n", 1)[1].split(
            "\nUse only the listed", 1
        )[0]
        entries = json.loads(block)
        self.assertEqual(
            [item["family"] for item in entries], ["mft", "prefetch", "registry"]
        )
        self.assertEqual(
            entries[0]["capabilities"],
            ["file_activity", "persistence", "process_execution"],
        )
        self.assertEqual(entries[0]["fields"], ["file_path"])
        self.assertEqual(entries[0]["boolean_fields"], ["is_deleted"])
        self.assertEqual(entries[0]["boolean_operators"], ["equals"])
        self.assertEqual(entries[1]["capabilities"], ["process_execution"])
        self.assertEqual(entries[1]["fields"], ["exec_times", "executable_name"])
        self.assertEqual(entries[2]["capabilities"], ["registry_observation"])
        self.assertEqual(entries[2]["fields"], ["key_path"])
        self.assertTrue(
            all(
                item["operators"] == ["equals", "contains", "greater_than"]
                for item in entries
            )
        )
        self.assertIn('"exec_times": ["2025-01-02T03:04:05"]', joined)
        self.assertIn('"is_deleted": false', joined)
        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            duplicate_messages, _ = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "persistence"},
                [],
                observed_candidate={
                    "evidence": [candidate["evidence"][0]] * 2,
                },
            )
        self.assertNotIn(
            "At least 2 mft observations have file_path equals "
            '"C:/ProgramData/updater.exe".',
            "\n".join(message["content"] for message in duplicate_messages),
        )
        self.assertNotIn("observation(s) has/have", joined)
        self.assertNotIn('"exec_time":', joined)
        self.assertNotIn('"timestamp": "derived timeline value"', joined)

        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            observation_messages, _ = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "host_execution_activity"},
                [],
                observed_candidate={"evidence": [candidate["evidence"][1]]},
            )
        observation_prompt = "\n".join(
            message["content"] for message in observation_messages
        )
        self.assertIn('"confirm_when": {"observation": {', observation_prompt)
        self.assertNotIn('"observation": {"observation":', observation_prompt)

        observation_schema = schema["properties"]["hypothesis"]["properties"][
            "confirm_when"
        ]["properties"]["observation"]
        allowed = set()
        for variant in observation_schema["anyOf"]:
            properties = variant["properties"]
            allowed.update(
                (family, capability, field, operator)
                for family in properties["family"]["enum"]
                for capability in properties["capability"]["enum"]
                for field in properties["field"]["enum"]
                for operator in properties["operator"]["enum"]
            )
        self.assertIn(
            ("prefetch", "process_execution", "exec_times", "contains"), allowed
        )
        self.assertNotIn(
            ("prefetch", "process_execution", "exec_time", "contains"), allowed
        )
        self.assertNotIn(("mft", "file_activity", "timestamp", "equals"), allowed)
        self.assertIn(("mft", "file_activity", "is_deleted", "equals"), allowed)
        self.assertNotIn(("mft", "file_activity", "is_deleted", "contains"), allowed)
        boolean_variant = next(
            variant
            for variant in observation_schema["anyOf"]
            if "is_deleted" in variant["properties"]["field"]["enum"]
        )
        self.assertEqual(boolean_variant["properties"]["value"], {"type": "boolean"})
        self.assertEqual(boolean_variant["properties"]["operator"]["enum"], ["equals"])

    def test_typed_observation_examples_run_through_admission_assessment_settlement(
        self,
    ) -> None:
        from forensia.core.session import SessionState
        from forensia.evidence.links import EvidenceLink
        from forensia.investigation import prompts
        from forensia.investigation.hypotheses.hypothesis_manager import (
            admit_new_hypothesis,
        )
        from forensia.investigation.verification.assessment import (
            assess_evidence_group,
        )
        from forensia.investigation.verification.settlement import (
            build_settlement_input_from_confirm_when,
            decide_settlement,
        )
        from forensia.investigation.verification.sufficiency import SufficiencyResult
        from forensia.knowledge.coverage import canonical_observation_claim

        candidate = {
            "scope": {"source_family": "mft"},
            "evidence": [
                {
                    "evidence_id": "mft-m1",
                    "_source": "mft_entries",
                    "file_path": "C:/ProgramData/updater.exe",
                },
                {
                    "evidence_id": "mft-m2",
                    "_source": "mft_entries",
                    "file_path": "C:/ProgramData/updater.exe",
                },
            ],
        }
        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            messages, schema = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "persistence"}, [], observed_candidate=candidate
            )
        fitted = fit_prompt_messages(messages)
        self.assertIsNotNone(fitted)
        prompt_text = "\n".join(message["content"] for message in fitted or [])
        examples = (
            "At least 1 mft observation has file_path equals "
            '"C:/ProgramData/updater.exe".',
            "At least 2 mft observations have file_path equals "
            '"C:/ProgramData/updater.exe".',
        )
        self.assertIn('"min_count": 2', prompt_text)
        observation_schema = schema["properties"]["hypothesis"]["properties"][
            "confirm_when"
        ]["properties"]["observation"]
        self.assertEqual(
            ["file_path"],
            observation_schema["anyOf"][0]["properties"]["field"]["enum"],
        )

        rows = [
            {
                "evidence_id": row["evidence_id"],
                "source_family": "mft",
                "file_path": row["file_path"],
            }
            for row in candidate["evidence"]
        ]
        sufficiency = SufficiencyResult(
            status="sufficient",
            score=1.0,
            reasons=[],
            independent_groups=2,
            families=["mft"],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )
        for count, description in zip((1, 2), examples, strict=True):
            support = {
                "observation": {
                    "family": "mft",
                    "capability": "file_activity",
                    "field": "file_path",
                    "operator": "equals",
                    "value": "C:/ProgramData/updater.exe",
                },
                **({"min_count": count} if count > 1 else {}),
            }
            from forensia.investigation.investigation_cycle import (
                _parse_hypothesis_from_drafter,
            )

            self.assertNotIn(
                "description", schema["properties"]["hypothesis"]["properties"]
            )
            hypothesis, parse_error = _parse_hypothesis_from_drafter(
                {"hypothesis": {"confirm_when": support}},
                allowed_rule_ids=set(),
                observation_only=True,
            )
            self.assertIsNone(parse_error)
            self.assertIsNotNone(hypothesis)
            hypothesis.id = f"H-PROMPT-{count}"
            self.assertEqual(
                description,
                canonical_observation_claim(hypothesis.verification_spec),
            )
            accepted, reason = admit_new_hypothesis(
                hypothesis, SessionState(session_id=f"S-{count}")
            )
            self.assertTrue(accepted, reason)

            assessment = assess_evidence_group(
                hypothesis=hypothesis,
                rows=rows,
                evidence_ids=[row["evidence_id"] for row in rows],
            )
            self.assertEqual("supporting", assessment.role)
            self.assertEqual(2, len(assessment.evidence_ids))
            links = [
                EvidenceLink(
                    link_id=f"L-{count}-{evidence_id}",
                    hypothesis_id=hypothesis.id,
                    evidence_id=evidence_id,
                    finding_id="",
                    query_id=f"Q-{count}",
                    assessment_id=assessment.assessment_id,
                    role="supporting",
                    source_family="mft",
                    source_file=f"{evidence_id}.mft",
                    derivation_group=evidence_id,
                    strength="strong",
                )
                for evidence_id in assessment.evidence_ids
            ]
            settled = decide_settlement(
                build_settlement_input_from_confirm_when(
                    hypothesis=hypothesis,
                    checker_verdict="inconclusive",
                    check_summary="typed observation",
                    sample_rows=rows,
                    sufficiency_result=sufficiency,
                ),
                links=links,
                coverage={},
            )
            self.assertEqual("confirmed", settled.verdict)
            self.assertTrue(settled.allowed)

    def test_hypothesis_drafter_discloses_empty_context_and_disallows_event_ids(
        self,
    ) -> None:
        import duckdb

        from forensia.investigation import prompts

        db = duckdb.connect()
        db.execute(
            "CREATE TABLE evtx_events (event_id INTEGER, channel VARCHAR, raw_json JSON)"
        )

        with patch.object(prompts, "_org_knowledge_block", return_value=""):
            messages, schema = prompts.build_hypothesis_drafter_messages(
                {"keypoint_id": "host_execution_activity"},
                [],
                case_profile=CaseEvidenceProfile(
                    event_ids=frozenset({1102}), summary="case events"
                ),
                db=db,
            )

        self.assertIn("<AVAILABLE_EVENT_CONTEXTS>\n[]", messages[0]["content"])
        ids_schema = schema["properties"]["hypothesis"]["properties"]["confirm_when"][
            "properties"
        ]["co_observed_event_ids"]
        self.assertEqual(ids_schema["maxItems"], 0)
        db.close()


class TestRuleMatchLeadsBlock(unittest.TestCase):
    """Rule matches stay labelled as leads and stable refs are never clipped."""

    def test_no_findings_omits_block(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=[],
        )
        system_content = msgs[0]["content"]
        self.assertNotIn("<RULE_MATCH_LEADS", system_content)

    def test_evidence_ids_string_parsed(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        h = Hypothesis(description="test", id="H-001")
        findings = [
            {
                "severity": "high",
                "title": "test finding",
                "hypothesis_id": "H-001",
                "finding_id": "f-001",
                "evidence_ids": "evtx-001,evtx-002",
            },
        ]
        msgs = build_query_intent_messages(
            hypothesis=h,
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=findings,
        )
        system_content = msgs[0]["content"]
        self.assertIn("<RULE_MATCH_LEADS status=unverified>", system_content)
        self.assertIn("Rule matches are leads, not confirmed activity.", system_content)
        self.assertIn("evtx-001", system_content)
        self.assertIn("evtx-002", system_content)
        self.assertNotIn("<CONFIRMED_FINDINGS>", system_content)

    def test_long_evidence_reference_is_not_truncated(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        evidence_id = "evtx-" + "x" * 220
        msgs = build_query_intent_messages(
            hypothesis=Hypothesis(description="test", id="H-001"),
            recent_history=[],
            active_hypotheses=[],
            findings_snapshot=[
                {
                    "severity": "high",
                    "title": "long-reference",
                    "evidence_ids": [evidence_id],
                }
            ],
        )

        self.assertIn(evidence_id, msgs[0]["content"])


class PriorAttemptsBlockTests(unittest.TestCase):
    """Attempt history reaches the planner as structured fields, not prose.

    Why: weak local models act reliably on structured lists (query_id /
    verdict / evidence_count) but often ignore clipped free text. The
    structured block is also what lets the planner avoid repeating queries.
    """

    def test_render_prior_attempts_structured_fields(self) -> None:
        from forensia.investigation.prompts import render_prior_attempts

        sql = (
            "SELECT evidence_id, timestamp FROM evtx_events WHERE message = '"
            + "a" * 260
            + "'\nORDER BY timestamp"
        )
        block = render_prior_attempts(
            [
                {
                    "query_id": "q-001",
                    "attempt_ref": "attempt-1",
                    "status": "inconclusive",
                    "retrieval_outcome": "empty",
                    "returned_count": 0,
                    "evidence_ids": [],
                    "purpose": "find 4720 account creation",
                    "template_id": "t-logon",
                    "summary": "no rows returned for event 4720",
                    "normalized_sql": sql,
                },
                {
                    "query_id": "q-002",
                    "attempt_ref": "attempt-2",
                    "status": "partial",
                    "returned_count": 2,
                    "evidence_ids": ["e-1", "e-2"],
                    "body": "partial overlap only",
                },
            ]
        )
        self.assertIn("<PRIOR_ATTEMPTS>", block)
        self.assertIn("query_id=q-001", block)
        self.assertIn("attempt_ref=attempt-1", block)
        self.assertIn("status=inconclusive", block)
        self.assertIn("retrieval_outcome=empty", block)
        self.assertIn("returned_count=0", block)
        self.assertIn("attempt_ref=attempt-2", block)
        self.assertIn("evidence_ids=[e-1,e-2]", block)
        self.assertNotIn("template_id", block)
        self.assertNotIn("summary", block)
        self.assertNotIn("body", block)
        self.assertIn(f"sql={json.dumps(sql)}", block)

    def test_intent_messages_carry_structured_attempts(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        msgs = build_query_intent_messages(
            hypothesis=Hypothesis(id="H-001", description="test hypothesis"),
            recent_history=[
                {
                    "query_id": "q-009",
                    "verdict": "inconclusive",
                    "summary": "zero rows",
                }
            ],
            active_hypotheses=[],
            time_range={},
            schema_context="",
        )
        system = msgs[0]["content"]
        self.assertIn("<PRIOR_ATTEMPTS>", system)
        self.assertIn("query_id=q-009", system)
        # The raw JSON dump of history must be gone.
        self.assertNotIn("recent_history:", system)

    def test_investigation_prompts_project_history_without_markdown_memory(
        self,
    ) -> None:
        from forensia.investigation.prompts import (
            build_query_intent_messages,
            build_verdict_review_messages,
        )

        hypothesis = Hypothesis(
            id="H-001",
            description="UNIQUE-CURRENT-HYPOTHESIS",
            required_entities=["computer", "logon_type"],
            confirm_when={"co_observed_event_ids": [4625]},
        )
        with patch(
            "forensia.investigation.prompts._org_knowledge_block",
            return_value="",
        ):
            plan_messages = build_query_intent_messages(
                hypothesis=hypothesis,
                recent_history=[],
                active_hypotheses=[
                    hypothesis,
                    Hypothesis(id="H-002", description="peer hypothesis"),
                ],
            )
        combined = "\n".join(message["content"] for message in plan_messages)
        self.assertEqual(1, combined.count("UNIQUE-CURRENT-HYPOTHESIS"))
        self.assertNotIn("confirm_when", combined)
        self.assertIn("verification_spec", combined)
        self.assertIn("peer hypothesis", combined)
        self.assertNotIn("<WORK_CONTEXT", combined)
        self.assertNotIn("Theme Finding IDs", combined)
        self.assertIn("plausible alternative explanation", combined)
        self.assertIn("Keep the original subject", combined)

        raw_json = (
            '{"event":{"provider":"microsoft-windows-eventsystem","code":4625},'
            '"winlog":{"channel":"Application","event_id":4625,'
            '"provider":{"name":"Microsoft-Windows-EventSystem",'
            '"guid":"discard-me"},"event_data":{"param1":"86400"}},'
            '"log":{"file":{"path":"/private/sample.evtx"}},'
            '"source_file":"hash","ingested_at":"later"}'
        )
        summary = {
            "row_count": 2,
            "head_rows": [{"evidence_id": "ev-1", "raw_json": raw_json}],
            "tail_rows": [{"evidence_id": "ev-2", "raw_json": raw_json}],
            "sample_rows": [
                {
                    "evidence_id": "ev-1",
                    "event_id": 4625,
                    "_source": "canonical-evidence-lookup",
                    "raw": json.loads(raw_json),
                    "raw_json": raw_json,
                },
                {
                    "evidence_id": "ev-2",
                    "event_id": 4625,
                    "_source": "canonical-evidence-lookup",
                    "raw": json.loads(raw_json),
                    "raw_json": raw_json,
                },
            ],
            "event_id_set": [4625],
            "evidence_ids": ["ev-1", "ev-2"],
        }
        verdict_messages, verdict_schema = build_verdict_review_messages(
            hypothesis,
            PlannedQuery(
                query_id="Q-1", hypothesis_id="H-001", purpose="test", sql="SELECT 1"
            ),
            summary,
        )
        verdict_user = verdict_messages[1]["content"]
        verdict_system = verdict_messages[0]["content"]
        self.assertIn("No counterevidence is not proof", verdict_system)
        self.assertIn("not a stronger accusation", verdict_system)
        self.assertEqual(
            ["confirmed", "inconclusive", "refuted", "newlead"],
            verdict_schema["properties"]["verdict"]["enum"],
        )
        self.assertIn(
            '"verdict": "confirmed | refuted | inconclusive | newlead"', verdict_system
        )
        self.assertIn(
            "For confirmed, refuted, or newlead, return an empty missing_questions array.",
            verdict_system,
        )
        self.assertNotIn("minItems", verdict_schema["properties"]["missing_questions"])
        self.assertNotIn('"head_rows"', verdict_user)
        self.assertNotIn('"tail_rows"', verdict_user)
        self.assertNotIn('"raw":', verdict_user)
        self.assertNotIn('"raw_json":', verdict_user)
        self.assertNotIn('"_source":', verdict_user)
        self.assertEqual(1, verdict_user.count("raw_event_context"))
        self.assertIn('"required_entities": ["computer", "logon_type"]', verdict_user)
        self.assertIn(
            '"support_conditions": {"co_observed_event_ids": [4625]}', verdict_user
        )
        self.assertIn("Application", verdict_user)
        self.assertIn("Microsoft-Windows-EventSystem", verdict_user)
        self.assertIn("param1", verdict_user)
        self.assertNotIn('"guid"', verdict_user)
        self.assertNotIn("/private/sample.evtx", verdict_user)
        self.assertNotIn("discard-me", verdict_user)

        from forensia.investigation.prompts import _result_summary_prompt_projection

        preserved_id = "Activity-" + ("x" * 90)
        bounded = _result_summary_prompt_projection(
            {
                "sample_rows": [
                    {
                        "evidence_id": "evtx-" + ("e" * 180),
                        "raw": {
                            "winlog": {
                                "channel": "Security",
                                "event_id": 4663,
                                "event_data": {
                                    "ActivityId": preserved_id,
                                    "Items": [{"id": "item-a"}, {"id": "item-b"}],
                                    "LargeValue": "x" * 500,
                                },
                            },
                            "message": "m" * 700,
                        },
                    }
                ]
            }
        )
        bounded_row = bounded["sample_rows"][0]
        bounded_context = bounded_row["raw_event_context"]
        self.assertEqual("evtx-" + ("e" * 180), bounded_row["evidence_id"])
        self.assertEqual(preserved_id, bounded_context["event_data"]["ActivityId"])
        self.assertEqual(
            [{"id": "item-a"}, {"id": "item-b"}],
            bounded_context["event_data"]["Items"],
        )
        self.assertEqual(2, bounded_context["omitted_field_count"])
        self.assertEqual(
            ["event_data.LargeValue", "message"],
            bounded_context["omitted_field_ids"],
        )
        self.assertLessEqual(len(json.dumps(bounded_context)), 2500)

    def test_intent_knowledge_terms_include_previous_check_feedback(self) -> None:
        from forensia.investigation.prompts import build_query_intent_messages

        with patch(
            "forensia.investigation.prompts._org_knowledge_block",
            return_value="",
        ) as knowledge_block:
            build_query_intent_messages(
                hypothesis=Hypothesis(id="H-001", description="test hypothesis"),
                recent_history=[{"summary": "prior answer about log clearing"}],
                active_hypotheses=[],
                prior_check_feedback="missing event_id 1102",
            )
        extra_words = knowledge_block.call_args.kwargs["extra_words"]
        self.assertIn("missing event_id 1102", extra_words)
        self.assertIn("prior answer about log clearing", extra_words)


class NarratePromptContractTests(unittest.TestCase):
    """Schema and brief-slimming contracts for narrative section prompts."""

    def test_large_aggregate_evidence_is_semantically_projected(self) -> None:
        """A complete 5,199-ID set stays authoritative but never floods report prompts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            db = CaseDB(case)
            try:
                evidence_ids = [
                    f"evtx-{'a' * 64}-security-{index:012d}" for index in range(1, 5200)
                ]
                base = datetime(2015, 3, 22, 12, 0, 0)
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, timestamp, channel, computer, target_user, event_id
                    )
                    SELECT 'evtx-' || repeat('a', 64) || '-security-' ||
                           lpad((i + 1)::VARCHAR, 12, '0'),
                           ?::TIMESTAMP + i * INTERVAL '1 second',
                           ['Security', 'System', 'Application'][i % 3 + 1],
                           ['host-a', 'host-b'][i % 2 + 1],
                           ['alice', 'bob', 'carol'][i % 3 + 1],
                           [4624, 4625, 4648, 4720][i % 4 + 1]
                    FROM range(5199) AS r(i)
                    """,
                    (base,),
                )
                unordered_ids = evidence_ids[2600:] + evidence_ids[:2600]
                aggregate = {
                    "first_event": str(base),
                    "last_event": str(base + timedelta(seconds=5198)),
                    "event_count": 5199,
                    "evidence_ids": unordered_ids,
                    "_source_keypoint": "evidence_query",
                }
                original = copy.deepcopy(aggregate)

                projected = project_report_evidence_row(aggregate, db=db)
                projected_from_reverse = project_report_evidence_row(
                    {**aggregate, "evidence_ids": list(reversed(unordered_ids))},
                    db=db,
                )

                self.assertEqual(original, aggregate)
                self.assertEqual(projected, projected_from_reverse)
                self.assertEqual(5199, projected["event_count"])
                self.assertEqual(5199, projected["evidence_count"])
                self.assertEqual(str(base), projected["first_event"])
                self.assertEqual(
                    str(base + timedelta(seconds=5198)), projected["last_event"]
                )
                self.assertNotIn("evidence_ids", projected)
                representatives = projected["representative_evidence_ids"]
                self.assertIn(evidence_ids[0], representatives)
                self.assertIn(evidence_ids[-1], representatives)
                self.assertTrue(set(representatives).issubset(evidence_ids))
                self.assertLessEqual(len(representatives), 10)
                distribution = projected["evidence_distribution"]
                self.assertEqual(3, distribution["source_family"]["distinct_count"])
                self.assertEqual(2, distribution["host"]["distinct_count"])
                self.assertEqual(3, distribution["user"]["distinct_count"])
                self.assertEqual(4, distribution["event_family"]["distinct_count"])

                narrative, _ = build_paragraph_narrate_messages(
                    heading="Time Basis and Coverage",
                    key_points=[],
                    evidence_rows=[aggregate],
                    template_body="Covered period, source coverage, timezone, gaps.",
                    report_context={"source_timezone": "UTC"},
                    db=db,
                )
                prompt_texts = [narrative[1]["content"]]
                raw_size = len(json.dumps([aggregate]))
                for prompt_text in prompt_texts:
                    self.assertIn("evidence_count", prompt_text)
                    self.assertIn("first_event", prompt_text)
                    self.assertIn("last_event", prompt_text)
                    self.assertIn("evidence_query", prompt_text)
                    self.assertLess(len(prompt_text), raw_size // 10)
                    self.assertLessEqual(
                        len(
                            re.findall(
                                r"evtx-[a-f0-9]{64}-security-\d{12}", prompt_text
                            )
                        ),
                        20,
                    )
                self.assertIn('"source_timezone": "UTC"', narrative[1]["content"])

                body = "Observed coverage (" + ", ".join(representatives[:3]) + ")."
                self.assertEqual([], validate_body_evidence_ids(db, body))

                small = {
                    "event_count": 3,
                    "evidence_ids": evidence_ids[:3],
                    "_source_keypoint": "evidence_query",
                }
                self.assertEqual(small, project_report_evidence_row(small, db=db))

                unavailable = project_report_evidence_row(aggregate, db=None)
                self.assertNotIn("evidence_ids", unavailable)
                self.assertEqual([], unavailable["representative_evidence_ids"])
                self.assertFalse(unavailable["citable"])
                no_db_messages, _ = build_paragraph_narrate_messages(
                    heading="Time Basis and Coverage",
                    key_points=[],
                    evidence_rows=[aggregate],
                    template_body="## Time Basis and Coverage",
                )
                self.assertNotIn(evidence_ids[0], no_db_messages[1]["content"])
                self.assertLess(len(no_db_messages[1]["content"]), raw_size // 10)

                unresolved = project_report_evidence_row(
                    {
                        "event_count": 21,
                        "evidence_ids": [
                            f"evtx-{'a' * 64}-security-{index:012d}"
                            for index in range(900_000, 900_021)
                        ],
                    },
                    db=db,
                )
                self.assertEqual([], unresolved["representative_evidence_ids"])
                self.assertFalse(unresolved["citable"])
                self.assertEqual(
                    21,
                    unresolved["evidence_projection"]["unresolved_evidence_count"],
                )
            finally:
                db.close()


class IndexedContextTests(unittest.TestCase):
    """T-21: repeated global prompts become compact indexes with lazy detail."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.case = Case.init(self.tmpdir)
        self.db = CaseDB(self.case)

    def tearDown(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass

    def test_schema_guidance_returns_only_selected_card(self) -> None:
        text = _build_schema_guidance("evtx_events", db=self.db, session_id="S-1")
        self.assertNotIn("<SCHEMA_INDEX>", text)
        self.assertNotIn("load schema card", text)
        self.assertNotIn("RECIPE_INDEX", text)
        self.assertIn("<SELECTED_SCHEMA_CARDS>", text)
        row = self.db.execute(
            "SELECT source_kind, selected_refs FROM trace.retrieval_events"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual("schema_hints", row[0])
        self.assertIn("evtx_events", row[1])

    def test_provider_prompt_metadata_carries_captured_retrieval_refs(self) -> None:
        from forensia.context.prompt_context import PromptMessages
        from forensia.llm.request_metadata import prompt_metadata

        messages = PromptMessages(
            [{"role": "user", "content": "query"}], ["retrieval-1", "retrieval-2"]
        )

        self.assertEqual(
            ["retrieval-1", "retrieval-2"],
            prompt_metadata(messages)["retrieval_event_ids"],
        )
        metadata = prompt_metadata(messages)
        self.assertEqual(
            "prompt_builder_selection", metadata["retrieval_event_ids_stage"]
        )
        self.assertEqual("provider_attempt_messages", metadata["selected_ids_stage"])

    def test_prompt_metadata_records_optional_blocks_removed_for_each_reason(
        self,
    ) -> None:
        from forensia.context.prompt_context import PromptMessages
        from forensia.llm.json_response import (
            _compact_messages_after_context_rejection,
            _messages_for_truncation_retry,
        )
        from forensia.llm.request_metadata import prompt_metadata

        messages = PromptMessages(
            [
                {
                    "role": "system",
                    "content": "<TASK>" + ("required " * 40) + "</TASK>\n"
                    "<ORG_KNOWLEDGE>"
                    + ("optional " * 100)
                    + "- id=doc-1 [SELECTED]</ORG_KNOWLEDGE>",
                },
                {
                    "role": "user",
                    "content": "<TEMPLATE_CONTEXT>"
                    + ("template " * 20)
                    + "</TEMPLATE_CONTEXT>",
                },
            ],
            ["retrieval-1"],
        )
        with (
            patch(
                "forensia.context.prompt_context.get_prompt_budget_tokens",
                return_value=200,
            ),
            patch(
                "forensia.context.prompt_context.get_llm_settings",
                return_value={"llm_context_window_tokens": None, "max_tokens": 100},
            ),
        ):
            budget_fitted = fit_prompt_messages(messages)
            self.assertIsNotNone(budget_fitted)
            assert budget_fitted is not None
            budget_metadata = prompt_metadata(budget_fitted)
            self.assertEqual(
                [
                    {
                        "name": "ORG_KNOWLEDGE",
                        "count": 1,
                        "reason": "input_budget",
                    },
                ],
                budget_metadata["omitted_optional_blocks"],
            )
            self.assertEqual([], budget_metadata["selected_ids"])
            self.assertEqual(["retrieval-1"], budget_metadata["retrieval_event_ids"])

            rejected_fitted = _compact_messages_after_context_rejection(budget_fitted)
            self.assertIsNotNone(rejected_fitted)
            assert rejected_fitted is not None
            self.assertEqual(
                [
                    *budget_metadata["omitted_optional_blocks"],
                    {
                        "name": "TEMPLATE_CONTEXT",
                        "count": 1,
                        "reason": "provider_context_rejection",
                    },
                ],
                prompt_metadata(rejected_fitted)["omitted_optional_blocks"],
            )
            self.assertEqual(
                ["retrieval-1"],
                prompt_metadata(rejected_fitted)["retrieval_event_ids"],
            )

            no_op_fitted = fit_prompt_messages(rejected_fitted)
            self.assertEqual(
                prompt_metadata(rejected_fitted), prompt_metadata(no_op_fitted)
            )
            truncation_retry = _messages_for_truncation_retry(rejected_fitted)
            retry_metadata = prompt_metadata(truncation_retry)
            self.assertEqual(
                prompt_metadata(rejected_fitted)["omitted_optional_blocks"],
                retry_metadata["omitted_optional_blocks"],
            )
            self.assertEqual(["retrieval-1"], retry_metadata["retrieval_event_ids"])


if __name__ == "__main__":
    unittest.main()
