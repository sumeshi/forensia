"""Run with python -m scripts.eval.refutation from the checkout root.

prepare CASE CANDIDATES.json OUT freezes four supplied interpretations and
their evidence. run OUT executes both instruction conditions in fresh cases.
Run again for a complete second round; no trial is resumed or overwritten.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import shutil
import time
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from scripts.eval.run import extract_case

from forensia.config import load_settings, settings_scope
from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records, routed_family
from forensia.evidence.content_identity import fingerprint_from_record
from forensia.investigation import planner
from forensia.investigation.hypotheses import hypothesis_runner as runner
from forensia.investigation.hypotheses.hypothesis_manager import (
    admit_new_hypothesis,
    qualify_event_contexts,
)
from forensia.investigation.hypotheses.hypothesis_store import _upsert_hypothesis
from forensia.investigation.investigation_session import (
    Ctx,
    _save_step,
    persist_session_terminal_receipt,
)
from forensia.investigation.progress import HypothesisProgressTracker
from forensia.investigation.verification import checker
from forensia.llm import json_response
from forensia.llm.telemetry import (
    LLMTelemetry,
    reset_active_telemetry,
    set_active_telemetry,
    telemetry_scope,
)

REPO = Path(__file__).resolve().parents[2]
# Keep only pre-investigation observations and their provenance, never prior
# judgments, reports, findings enriched by a model, or execution history.
EVIDENCE_TABLES = {
    "forensia_schema",
    "evtx_events",
    "mft_entries",
    "mft_timeline",
    "prefetch_executions",
    "prefetch_timeline",
    "registry_datasets",
    "registry_artifacts",
    "registry_timeline",
    "ingested_files",
    "evidence_sources",
    "evidence_coverage",
}
USEFUL_SEARCH = (
    "Preserves the original target and can change support, refutation, or "
    "evidence-insufficiency judgment. Rechecking supplied values, losing the "
    "target, repeating a query, or merely passing SQL validation is not enough."
)
COMMON = (
    "The supplied interpretation is unconfirmed; recorded observations remain "
    "observations. Propose at most one additional search with its purpose. "
    "After the search, use the existing verdict and rationale to explain whether "
    "to maintain, limit, withdraw, or defer the interpretation. Do not supply "
    "private deliberation. Missing counterevidence and zero rows do not prove "
    "the interpretation. Keep the existing output schema."
)
COUNTEREVIDENCE = (
    "Consider another explanation. What observation would require withdrawing "
    "or limiting this interpretation? Choose a search that distinguishes the "
    "explanations; do not assume the interpretation or its alternative is true."
)


def _write(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _code_identity() -> dict[str, str]:
    paths = sorted((REPO / "src/forensia").rglob("*.py"))
    paths += [Path(__file__).resolve(), REPO / "scripts/eval/run.py", REPO / "uv.lock"]
    paths += sorted(
        path for path in (REPO / "src/forensia/data").rglob("*") if path.is_file()
    )
    return {str(path.relative_to(REPO)): _sha(path) for path in paths}


def _public_settings(settings) -> dict:
    values = asdict(settings)
    values.pop("llm_api_key")
    return values


def prepare(source: Path, candidates_path: Path, out: Path) -> dict:
    source, out = source.resolve(), out.resolve()
    if source == out or source in out.parents or out in source.parents:
        raise ValueError("Experiment output must be outside the source case")
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    if not isinstance(candidates, list) or len(candidates) != 4:
        raise ValueError("Supply exactly four candidates")
    settings = load_settings(require_inference=True)
    families = set()
    source_case = Case.open(source)
    source_sha = _sha(source_case.database_path)
    with CaseDB(source_case, read_only=True) as db:
        if source_case.database_path.with_suffix(".duckdb.wal").exists():
            raise ValueError("Use a completed, frozen case without a WAL")
        if db.execute(
            "SELECT COUNT(*) FROM trace.investigation_sessions WHERE status = 'running'"
        ).fetchone()[0]:
            raise ValueError("Use a completed, frozen case without a running session")
        for index, candidate in enumerate(candidates, 1):
            if not candidate.get("question", "").strip():
                raise ValueError("Every candidate requires a question")
            hypothesis = Hypothesis.model_validate(candidate["hypothesis"])
            hypothesis.id = f"H-{index:03d}"
            if hypothesis.status != "active" or hypothesis.verdict is not None:
                raise ValueError("Interpretations must be unconfirmed")
            if hypothesis.source_rule_ids or hypothesis.source_gap_id:
                raise ValueError("Do not import prior investigation state")
            ids = candidate["evidence_ids"]
            if (
                not isinstance(ids, list)
                or not ids
                or any(not isinstance(e, str) for e in ids)
            ):
                raise ValueError("Every candidate requires observed Evidence IDs")
            records = fetch_evidence_records(db, ids)
            if set(records) != set(ids):
                raise ValueError(f"Unresolved Evidence IDs for {hypothesis.id}")
            families.update(routed_family(e) for e in ids)
            hypothesis = qualify_event_contexts(hypothesis, db)
            candidate["hypothesis"] = hypothesis.model_dump(mode="json")
            candidate["observations"] = [records[e] for e in ids]
            candidate["evidence_fingerprints"] = {
                e: fingerprint_from_record(records[e]) for e in ids
            }
        if None in families or len(families) < 2:
            raise ValueError("Use at least two recognized artifact families")
        out.mkdir(parents=True, exist_ok=False)
        seed = Case.init(out / "seed", source_timezone=source_case.source_timezone)
        shutil.copyfile(source_case.database_path, seed.database_path)
    if _sha(source_case.database_path) != source_sha:
        raise ValueError("Source changed while freezing; experiment is invalid")
    with CaseDB(seed) as db, db.transaction():
        tables = db.execute(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_type = 'BASE TABLE' AND table_catalog = current_database()"
        ).fetchall()
        for schema, name in tables:
            if schema != "main" or name not in EVIDENCE_TABLES:
                quoted = '"' + str(name).replace('"', '""') + '"'
                db.execute(f'DELETE FROM "{schema}".{quoted}')
    manifest = {
        "source": str(source),
        "source_database_sha256": source_sha,
        "seed_database_sha256": _sha(seed.database_path),
        "code_identity": _code_identity(),
        "settings": _public_settings(settings),
        "conditions": {
            "ordinary": COMMON,
            "counterevidence": COMMON + " " + COUNTEREVIDENCE,
        },
        "budget": {
            "searches": 1,
            "planner_corrections": 1,
            "result_evaluations": 1,
            "logical_calls": 3,
            "evaluation_corrections": 0,
        },
        "useful_search": USEFUL_SEARCH,
        "preparation_model_calls": 0,
        "preparation": "Human-supplied unconfirmed interpretations; no reference answers",
        "candidates": candidates,
    }
    _write(out / "inputs.json", manifest)
    (out / "inputs.sha256").write_text(_sha(out / "inputs.json"), encoding="utf-8")
    return manifest


def _instruction_builder(builder, candidate: dict, instruction: str):
    def build(*args, **kwargs):
        built = builder(*args, **kwargs)
        messages = built[0] if isinstance(built, tuple) else built
        messages[-1]["content"] += (
            "\n<EXPERIMENT_INPUT>\n"
            + json.dumps(
                {
                    "question": candidate["question"],
                    "interpretation": candidate["hypothesis"]["description"],
                    "observations": candidate["observations"],
                },
                ensure_ascii=False,
                default=str,
            )
            + "\n</EXPERIMENT_INPUT>\n"
            + instruction
        )
        return built

    return build


async def _trial(
    case: Case, candidate: dict, condition: str, instruction: str, settings
) -> dict:
    session_id = f"refutation-{condition}"
    hypothesis = Hypothesis.model_validate(candidate["hypothesis"])
    state = SessionState(session_id=session_id)
    outcome = {
        "hypothesis_id": hypothesis.id,
        "condition": condition,
        "status": "running",
    }
    started = time.monotonic()
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.investigation_sessions (session_id, started_at, status, phase) "
            "VALUES (?, now(), 'running', 'refutation-experiment')",
            [session_id],
        )
        _save_step(
            db,
            session_id,
            1,
            "experiment-input",
            hypothesis.id,
            {"candidate": candidate, "instruction": instruction},
            {"status": "running"},
        )
        token = set_active_telemetry(LLMTelemetry(db, session_id, max_logical_calls=3))
        try:
            accepted, reason = admit_new_hypothesis(hypothesis, state)
            if not accepted:
                outcome.update(status="contract_rejected", reason=reason)
            elif "observation" in hypothesis.verification_spec.support_conditions:
                outcome.update(
                    status="contract_rejected", reason="observation_not_interpretation"
                )
            else:
                state.active_hypotheses.append(hypothesis)
                _upsert_hypothesis(db, hypothesis, "refutation-experiment", session_id)
                rs = runner._HypothesisRunState(
                    hypothesis=hypothesis,
                    state=state,
                    ctx=Ctx(),
                    db=db,
                    base_url=settings.llm_base_url,
                    model=settings.llm_model,
                    plan_cycle=1,
                    session_id=session_id,
                    case=case,
                    emit_fn=None,
                    llm_status_fn=None,
                    case_profile=None,
                    candidates=[],
                    tracker=HypothesisProgressTracker(),
                    focus_sections={},
                    query_index=2,
                )
                with (
                    ExitStack() as stack,
                    telemetry_scope(iteration=1, hypothesis_id=hypothesis.id),
                ):
                    stack.enter_context(
                        patch.object(
                            planner,
                            "build_query_intent_messages",
                            _instruction_builder(
                                planner.build_query_intent_messages,
                                candidate,
                                instruction,
                            ),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            checker,
                            "build_verdict_review_messages",
                            _instruction_builder(
                                checker.build_verdict_review_messages,
                                candidate,
                                instruction,
                            ),
                        )
                    )
                    # Only one search and one evaluation: no fallback searches
                    # or finding-enrichment calls after a proposed verdict.
                    stack.enter_context(
                        patch.object(
                            runner,
                            "resolve_zero_row_fallbacks",
                            lambda **kw: (kw["rows"], None),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            checker, "_extract_confirmed_findings", return_value=[]
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            checker,
                            "_request_check_json",
                            lambda **kw: json_response.request_llm_json(
                                messages=kw["messages"],
                                base_url=kw["base_url"],
                                model=kw["model"],
                                json_schema=kw["schema"],
                                telemetry_phase=kw["phase"],
                                correction_budget=[0],
                            ),
                        )
                    )
                    for attempt in (1, 2):
                        rs.hypothesis_plan = planner.plan_hypothesis_query(
                            state,
                            hypothesis,
                            settings.llm_base_url,
                            settings.llm_model,
                            db=db,
                            query_index=2,
                            correction_budget=rs.correction_budget,
                        )
                        flow = planner.persist_hypothesis_plan_result(
                            db=db,
                            session_id=session_id,
                            iteration=1,
                            hypothesis=hypothesis,
                            query_index=2,
                            plan=rs.hypothesis_plan,
                            state=state,
                            attempt_number=attempt,
                            correction_budget=rs.correction_budget,
                        )
                        if flow != "continue":
                            break
                        rs.correction_budget[0] -= 1
                    outcome.update(
                        status="plan_rejected", reason=rs.hypothesis_plan.stop_reason
                    )
                    if flow == "ok":
                        outcome["query"] = rs.hypothesis_plan.query.model_dump(
                            mode="json"
                        )
                        execute_flow = runner._phase_execute(rs)
                        outcome.update(status="execution_stopped", reason=execute_flow)
                        if (
                            execute_flow == "ok"
                            and await runner._phase_check(rs) == "continue"
                        ):
                            outcome.update(
                                status="evaluation_failed",
                                reason="See check error in Trace",
                            )
                        elif execute_flow == "ok":
                            outcome["model_proposal"] = rs.check_result.raw_response
                            with db.transaction():
                                runner._phase_apply_verdict(rs)
                            outcome.update(
                                status="evaluated",
                                reason=rs.check_result.verdict,
                                result_summary=rs.result_summary,
                            )
        except Exception as exc:
            outcome.update(status="failed", reason=f"{type(exc).__name__}: {exc}")
        finally:
            # Persist the terminal state before metrics or presentation can fail.
            persist_session_terminal_receipt(
                db,
                session_id,
                "failed" if outcome["status"] == "failed" else "stopped",
                terminal_reason=outcome.get("reason") or outcome["status"],
            )
            reset_active_telemetry(token)
        outcome["elapsed_seconds"] = round(time.monotonic() - started, 3)
        _save_step(db, session_id, 1, "experiment-outcome", hypothesis.id, {}, outcome)
    return outcome


async def run(experiment: Path) -> dict:
    experiment = experiment.resolve()
    if _sha(experiment / "inputs.json") != (experiment / "inputs.sha256").read_text(
        encoding="utf-8"
    ):
        raise ValueError("Fixed experiment inputs changed")
    manifest = json.loads((experiment / "inputs.json").read_text(encoding="utf-8"))
    settings = load_settings(require_inference=True)
    if (
        _public_settings(settings) != manifest["settings"]
        or _code_identity() != manifest["code_identity"]
    ):
        raise ValueError(
            "Code or model settings changed after preparation; prepare a new experiment"
        )
    seed = Case.open(experiment / "seed")
    if _sha(seed.database_path) != manifest["seed_database_sha256"]:
        raise ValueError("Frozen evidence snapshot changed")
    round_dir = experiment / f"round-{1 + len(list(experiment.glob('round-*')))}"
    round_dir.mkdir(exist_ok=False)
    results = []
    with settings_scope(settings):
        for index, candidate in enumerate(manifest["candidates"]):
            # Alternate order to avoid always warming the model for condition B.
            conditions = list(manifest["conditions"])
            if index % 2:
                conditions.reverse()
            for condition in conditions:
                case = Case.init(
                    round_dir / f"{candidate['hypothesis']['id']}-{condition}",
                    source_timezone=seed.source_timezone,
                )
                shutil.copyfile(seed.database_path, case.database_path)
                result = await _trial(
                    case,
                    candidate,
                    condition,
                    manifest["conditions"][condition],
                    settings,
                )
                metrics = extract_case(case.path)
                result["metrics"] = {
                    key: metrics.get(key)
                    for key in ("usage", "query_metrics", "cycles")
                }
                _write(case.path.parent / f"{case.path.name}.json", result)
                results.append(result)
                _write(round_dir / "results.json", results)
                print(
                    f"{candidate['hypothesis']['id']} {condition}: {result['status']} ({result.get('reason')})",
                    flush=True,
                )
    report = {
        "decision": "pending_human_review",
        "useful_search": manifest["useful_search"],
        "trials": results,
    }
    _write(round_dir / "comparison.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("prepare")
    freeze.add_argument("case", type=Path)
    freeze.add_argument("candidates", type=Path)
    freeze.add_argument("out", type=Path)
    execute = commands.add_parser("run")
    execute.add_argument("experiment", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.case, args.candidates, args.out)
        print(f"Frozen inputs: {args.out / 'inputs.json'}")
    else:
        asyncio.run(run(args.experiment))


if __name__ == "__main__":
    main()
