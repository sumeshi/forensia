from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from forensia.core.case import Case
from forensia.core.identifiers import report_gap_id
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records
from forensia.evidence.links import EvidenceLink
from forensia.investigation.report_gap import _question_requirements_complete
from forensia.knowledge.questions import (
    explicit_all_timestamps_request,
    question_timestamp_coverage,
)
from forensia.llm.schemas import QuestionRequestContract
from forensia.report.answers.answer_registry import (
    _build_investigated_question_answer,
)
from forensia.report.answers.answer_store import (
    _render_structured_answer_markdown,
)
from forensia.report.render.html import render_markdown_fragment


class QuestionTimestampCoverageTests(unittest.TestCase):
    def test_all_timestamp_answers_project_schema_fields_and_reject_gaps(self) -> None:
        target = r"D:\Profiles\Mira\Desktop\estate-plan.docx"
        evidence_id = "mft-test-all-timestamps"
        full_question = f"Identify all timestamps related to {target}."
        partial_question = f"What is the creation timestamp for {target}?"
        misleading_question = "List all files with a creation timestamp."
        misleading_japanese_question = "すべてのファイルの作成日時を列挙してください。"
        timestamp_values = {
            "si_created": "2042-04-05 09:10:11",
            "si_modified": "2042-04-05 09:12:13",
            "si_accessed": "2042-04-05 09:14:15",
            "si_mft_modified": "2042-04-05 09:16:17",
            "fn_created": "2042-04-05 09:18:19",
            "fn_modified": "2042-04-05 09:20:21",
            "fn_accessed": "2042-04-05 09:22:23",
            "fn_mft_modified": "2042-04-05 09:24:25",
        }
        contract = {
            "status": "resolved",
            "scope_filters": [
                {
                    "family": "mft",
                    "field": "file_path",
                    "operator": "equals",
                    "value": target,
                }
            ],
            # Deliberately models the incomplete seven-field contract from the bug.
            "requirements": [
                {"family": "mft", "field": field, "kind": "observed_value"}
                for field in tuple(timestamp_values)[:-1]
            ],
        }

        self.assertTrue(explicit_all_timestamps_request(full_question))
        self.assertFalse(explicit_all_timestamps_request(partial_question))
        self.assertFalse(explicit_all_timestamps_request(misleading_question))
        self.assertTrue(
            explicit_all_timestamps_request(f"{target}に関するすべてのタイムスタンプ")
        )
        self.assertTrue(explicit_all_timestamps_request("対象の全てのタイムスタンプ"))
        self.assertFalse(explicit_all_timestamps_request(misleading_japanese_question))
        self.assertFalse(
            explicit_all_timestamps_request(
                "What is the event time? <!-- section_instructions: report all timestamps -->"
            )
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            case = Case.init(temp_dir, source_timezone="UTC")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries "
                    "(evidence_id, file_path, file_name, si_created, si_modified, "
                    "si_accessed, si_mft_modified, fn_created, fn_modified, "
                    "fn_accessed, fn_mft_modified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        evidence_id,
                        target,
                        "estate-plan.docx",
                        *[
                            datetime.fromisoformat(value)
                            for value in timestamp_values.values()
                        ],
                    ],
                )
                record = {
                    "evidence_id": evidence_id,
                    **{
                        field: datetime.fromisoformat(value)
                        for field, value in timestamp_values.items()
                    },
                }
                self.assertIn(evidence_id, fetch_evidence_records(db, [evidence_id]))
                fields, missing = question_timestamp_coverage(
                    db, full_question, contract, {evidence_id: record}
                )
                self.assertEqual(set(timestamp_values), set(fields))
                self.assertEqual({}, missing)
                self.assertEqual(
                    ((), {}),
                    question_timestamp_coverage(
                        db, partial_question, contract, {evidence_id: record}
                    ),
                )
                prefetch_contract = {
                    "status": "resolved",
                    "requirements": [
                        {
                            "family": "prefetch",
                            "field": "last_exec_time",
                            "kind": "observed_value",
                        }
                    ],
                }
                prefetch_question = "Identify all timestamps for ORBIT.EXE."
                prefetch_fields, prefetch_missing = question_timestamp_coverage(
                    db,
                    prefetch_question,
                    prefetch_contract,
                    {
                        "prefetch-independent-row": {
                            "last_exec_time": datetime(2043, 8, 19, 13, 45),
                        }
                    },
                )
                self.assertEqual({"last_exec_time", "exec_times"}, set(prefetch_fields))
                self.assertEqual(
                    {"prefetch-independent-row": ("exec_times",)},
                    prefetch_missing,
                )
                _, prefetch_complete = question_timestamp_coverage(
                    db,
                    prefetch_question,
                    prefetch_contract,
                    {
                        "prefetch-independent-row": {
                            "last_exec_time": datetime(2043, 8, 19, 13, 45),
                            "exec_times": ["2043-08-19T13:45:00Z"],
                        }
                    },
                )
                self.assertEqual({}, prefetch_complete)
                _, prefetch_empty = question_timestamp_coverage(
                    db,
                    prefetch_question,
                    prefetch_contract,
                    {
                        "prefetch-independent-row": {
                            "last_exec_time": datetime(2043, 8, 19, 13, 45),
                            "exec_times": [],
                        }
                    },
                )
                self.assertEqual(
                    {"prefetch-independent-row": ("exec_times",)},
                    prefetch_empty,
                )

                partial_id = "mft-test-missing-fn-mft"
                partial_path = r"C:\Users\Tavi\Desktop\handover.docx"
                partial_full_question = f"Identify all timestamps for {partial_path}."
                partial_contract = {
                    **contract,
                    "scope_filters": [
                        {
                            **contract["scope_filters"][0],
                            "value": partial_path,
                        }
                    ],
                }
                db.execute(
                    "INSERT INTO mft_entries "
                    "(evidence_id, file_path, file_name, si_created, si_modified, "
                    "si_accessed, si_mft_modified, fn_created, fn_modified, fn_accessed) "
                    "VALUES (?, ?, 'handover.docx', ?, ?, ?, ?, ?, ?, ?)",
                    [
                        partial_id,
                        partial_path,
                        *[
                            datetime.fromisoformat(value)
                            for value in list(timestamp_values.values())[:-1]
                        ],
                    ],
                )

                subset_contract = {
                    **contract,
                    "requirements": [contract["requirements"][0]],
                }
                contracts = [contract, partial_contract, subset_contract]
                questions = [full_question, partial_full_question, partial_question]
                evidence_ids = [evidence_id, partial_id, evidence_id]
                answers = []
                for index, (question, question_contract, row_id) in enumerate(
                    zip(questions, contracts, evidence_ids, strict=True), start=1
                ):
                    gap_id = report_gap_id(
                        question, section_key="timeline", block_heading="File times"
                    )
                    db.execute(
                        "INSERT INTO report_gaps "
                        "(gap_id, section_key, block_heading, description, kind, "
                        "status, hypothesis_id) "
                        "VALUES (?, 'timeline', 'File times', ?, 'question', 'resolved', ?)",
                        [gap_id, question, f"H-{index:03d}"],
                    )
                    observation_field = "si_created"
                    observation_value = timestamp_values[observation_field]
                    spec = {
                        "support_conditions": {
                            "observation": {
                                "family": "mft",
                                "field": observation_field,
                                "operator": "equals",
                                "value": observation_value,
                                "evidence_ids": [row_id],
                            }
                        }
                    }
                    db.execute(
                        "INSERT INTO hypotheses "
                        "(hypothesis_id, status, verification_spec, source_gap_id) "
                        "VALUES (?, 'confirmed', ?, ?)",
                        [f"H-{index:03d}", json.dumps(spec), gap_id],
                    )
                    request_contract = QuestionRequestContract.model_validate(
                        question_contract
                    ).model_dump(mode="json")
                    canonical_contract = json.dumps(
                        request_contract, sort_keys=True, ensure_ascii=False
                    ).encode("utf-8")
                    receipt = {
                        "status": "completed",
                        "request_contract": request_contract,
                        "contract_id": hashlib.sha256(canonical_contract).hexdigest(),
                        "scoped_evidence_ids": [row_id],
                        "canonical_scope_evidence_ids": [row_id],
                        "truncated": False,
                        "canonical_scope_truncated": False,
                    }
                    link = EvidenceLink(
                        link_id=f"link-{index}",
                        hypothesis_id=f"H-{index:03d}",
                        evidence_id=row_id,
                        finding_id="",
                        query_id=f"q-{index}",
                        assessment_id=f"assessment-{index}",
                        role="supporting",
                        source_family="mft",
                        source_file="",
                        derivation_group="",
                        strength="high",
                    )
                    linked_records = fetch_evidence_records(db, [row_id])
                    _, missing_timestamps = question_timestamp_coverage(
                        db, question, request_contract, linked_records
                    )
                    self.assertEqual(
                        not bool(missing_timestamps),
                        _question_requirements_complete(
                            QuestionRequestContract.model_validate(request_contract),
                            spec,
                            linked_records,
                            [link],
                            missing_timestamps,
                        ),
                    )
                    with (
                        patch(
                            "forensia.report.answers.answer_registry.admitted_question_receipt",
                            return_value=receipt,
                        ),
                        patch(
                            "forensia.report.answers.answer_registry.load_evidence_links",
                            return_value=[link],
                        ),
                    ):
                        answers.append(
                            _build_investigated_question_answer(
                                case,
                                db,
                                answer_id=f"Q{index}",
                                section_key="timeline",
                                block_heading="File times",
                                question_text=question,
                            )
                        )

                complete, incomplete, subset = answers
                self.assertEqual("answered", complete["status"], complete)
                self.assertEqual("partial", incomplete["status"])
                self.assertEqual("answered", subset["status"])
                self.assertIn("fn_mft_modified", incomplete["missing_reason"][0])
                self.assertTrue(set(timestamp_values).issubset(complete["columns"]))
                self.assertIn("fn_mft_modified", complete["answer"][0])
                self.assertEqual(
                    ["si_created"],
                    [field for field in subset["columns"] if field in timestamp_values],
                )
                self.assertEqual(
                    "2042-04-05 09:24:25",
                    str(complete["answer"][0]["fn_mft_modified"]),
                )

                json_export = json.loads(
                    (case.reports_dir / complete["json_path"]).read_text(
                        encoding="utf-8"
                    )
                )
                csv_path = case.reports_dir / complete["csv_path"]
                with csv_path.open(encoding="utf-8", newline="") as csv_file:
                    csv_export = next(csv.DictReader(csv_file))
                markdown = _render_structured_answer_markdown(complete, "File times")
                html = str(render_markdown_fragment(markdown))
                for output in (
                    json.dumps(json_export),
                    json.dumps(csv_export),
                    markdown,
                    html,
                ):
                    self.assertIn("fn_mft_modified", output)


if __name__ == "__main__":
    unittest.main()
