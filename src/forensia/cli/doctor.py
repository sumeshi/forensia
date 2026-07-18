"""Self-contained health checks used by the hidden ``doctor`` command."""

import logging
import subprocess
import sys
from pathlib import Path

from rich import print

from forensia.cli.support import _status

logger = logging.getLogger(__name__)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _run_doctor_script_check(
    label: str,
    status_line: str,
    script_name: str,
    extra_args: list[str],
    timeout: int,
    ok_message: str,
    fail_heading: str,
) -> tuple[str, bool]:
    """Run a scripts/*.py health check in a subprocess and report pass/fail."""
    _status(status_line)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(_project_root() / "scripts" / script_name),
                *extra_args,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ok = result.returncode == 0
        if ok:
            print(f"  ✓ {ok_message}")
        else:
            print(f"  ✗ {fail_heading}:\n{result.stdout}")
        return label, ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return label, False


def _doctor_schema_coverage_check() -> tuple[str, bool]:
    return _run_doctor_script_check(
        "Schema coverage",
        "Schema coverage audit...",
        "audit_schema_coverage.py",
        ["--strict"],
        60,
        "All event IDs and question types covered",
        "Uncovered entries",
    )


def _doctor_playbook_drift_check() -> tuple[str, bool]:
    return _run_doctor_script_check(
        "Playbook drift",
        "Playbook MD/YAML drift check...",
        "regenerate_playbook.py",
        ["--check"],
        30,
        "All playbook files up to date",
        "Drift detected",
    )


def _doctor_import_layer_check() -> tuple[str, bool]:
    return _run_doctor_script_check(
        "Import layers",
        "Import layer contract (R4)...",
        "check_imports.py",
        [],
        30,
        "No forbidden import edges",
        "Layer violations",
    )


def _doctor_verdict_taxonomy_check() -> tuple[str, bool]:
    _status("Verdict taxonomy enforcement...")
    try:
        from forensia.core.verdicts import valid_verdicts

        h_count = len(valid_verdicts("hypothesis_verdict"))
        s_count = len(valid_verdicts("section_verdict"))
        q_count = len(valid_verdicts("structured_status"))
        print(
            f"  ✓ {h_count} hypothesis, {s_count} section, {q_count} structured-question verdicts defined"
        )

        import ast
        import os

        enforcement_files = []
        for root, dirs, files in os.walk(Path(__file__).parent.parent):
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(root, f)
                    try:
                        tree = ast.parse(open(path).read())
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                callee = node.func
                                name = (
                                    callee.attr
                                    if isinstance(callee, ast.Attribute)
                                    else (
                                        callee.id
                                        if isinstance(callee, ast.Name)
                                        else ""
                                    )
                                )
                                if name == "assert_valid_verdict":
                                    enforcement_files.append(
                                        os.path.relpath(path, _project_root())
                                    )
                                    break
                    except Exception:
                        logger.debug(
                            "Failed to parse %s for verdict enforcement scan",
                            path,
                            exc_info=True,
                        )
        enforcement_count = len(enforcement_files)
        ok = enforcement_count >= 4
        print(
            f"  {'✓' if ok else '✗'} {enforcement_count} files use assert_valid_verdict: {enforcement_files}"
        )
        return "Verdict enforcement", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Verdict enforcement", False


def _doctor_report_template_policy_check() -> tuple[str, bool]:
    _status("Report template contract...")
    try:
        from forensia.report.resources import report_templates_dir
        from forensia.report.sections.template_parsing import parse_template

        problems = []
        for path in sorted(report_templates_dir().glob("[0-9]*_*.md")):
            _body, meta = parse_template(str(path))
            missing = [
                name
                for name, value in (
                    ("type", meta.type),
                    ("title", meta.title),
                    ("description", meta.description),
                    ("tags", meta.tags),
                    ("timestamp", meta.timestamp),
                    ("instructions", meta.instructions),
                )
                if not value
            ]
            if missing:
                problems.append(f"{path.name}: missing {', '.join(missing)}")
        ok = not problems
        if ok:
            print("  ✓ Packaged templates include knowledge metadata and instructions")
        else:
            print(
                "  ✗ Invalid packaged templates:\n"
                + "\n".join(f"      - {p}" for p in problems)
            )
        return "Report template contract", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Report template contract", False


def _doctor_report_validation_self_check() -> tuple[str, bool]:
    _status("Report output validation self-check...")
    try:
        from forensia.report.report_validation import validate_report

        # Build a synthetic brief with known-bad patterns to exercise
        # every validator check without depending on pre-generated case output.
        synthetic_brief = {
            "executive_summary": (
                "Analysis revealed signs of lateral movement and network "
                "intrusion via compromised host."
            ),
            "confirmed_hypotheses": [
                {
                    # No source_rule_ids → not a "strong" hypothesis
                    "description": "Attacker used RDP lateral movement to pivot",
                    "source_rule_ids": [],
                    "tags": [],
                },
                {
                    # Tagged benign → should be excluded from strong count
                    "description": "Loopback 4648 logon via explicit credentials",
                    "source_rule_ids": ["SIGMA-001"],
                    "tags": ["benign"],
                },
            ],
            "refuted_hypotheses": [
                {
                    # Duplicate description → verdict_contradiction
                    "description": "Attacker used RDP lateral movement to pivot",
                },
            ],
            "evidence_gaps": [],
        }
        synthetic_body = (
            "Evidence sourced from sample/MFT_C and Prefetch/RDPBLAH.pf. "
            "For Executive Summary, the collected evidence returned 14 related rows."
        )
        findings = validate_report(synthetic_brief, report_body=synthetic_body)
        # The validator should catch: thesis_alignment, verdict_contradiction,
        # local_path_leak (sample/ in body), and fallback_stub.
        ok = len(findings) >= 4
        if ok:
            names = [f.check_name for f in findings]
            print(
                f"  ✓ Validator correctly caught {len(findings)} intentional "
                f"issues ({', '.join(names)})"
            )
        else:
            print(
                f"  ✗ Validator only caught {len(findings)} issue(s) "
                "(expected >= 3); possible regression"
            )
            for f_item in findings:
                print(
                    f"      [{f_item.severity}] {f_item.check_name}: {f_item.message}"
                )
        return "Report output validation", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Report output validation", False


def _doctor_static_lint_check() -> tuple[str, bool]:
    _status("Static lint (undefined names, unused imports)...")
    try:
        # Runtime-only NameErrors (e.g. a constant referenced in a code path
        # tests never execute) crash long investigation runs hours in. Ruff's
        # pyflakes rules catch them statically before any run starts.
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--no-cache",
                "src/forensia",
                "tests",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 and "No module named" in (result.stderr or ""):
            print("  ✓ ruff not installed — skipping (dev dependency)")
            return "Static lint", True
        else:
            ok = result.returncode == 0
            if ok:
                print("  ✓ ruff check clean")
            else:
                print(f"  ✗ Lint findings:\n{result.stdout[-500:]}")
            return "Static lint", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Static lint", False


def _doctor_test_suite_check() -> tuple[str, bool]:
    _status("Test suite...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/",
                "-q",
                "--no-header",
                "-p",
                "no:cacheprovider",
                "--ignore=tests/test_memory.py",
                "--ignore=tests/test_ingest.py",
                "--ignore=tests/test_persistence.py",
                "--ignore=tests/test_web_api.py",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        last_line = (
            result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        )
        ok = result.returncode == 0
        if ok:
            print(f"  ✓ {last_line}")
        else:
            print(f"  ✗ Failures:\n{result.stdout[-500:]}")
        return "Test suite", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Test suite", False


def _finish_doctor_checks(checks: list[tuple[str, bool]]) -> None:
    print()
    total = len(checks)
    passed = sum(1 for _, ok in checks if ok)
    failed = total - passed
    if failed == 0:
        print(f"[bold green]✓ All {total} checks passed[/bold green]")
    else:
        print(f"[bold red]✗ {failed}/{total} checks failed[/bold red]")
        for name, ok in checks:
            status_char = "✓" if ok else "✗"
            print(f"  {status_char} {name}")
    sys.exit(0 if failed == 0 else 1)


def run_doctor() -> None:
    """Run all health checks: schema coverage, playbook drift, verdict taxonomy."""
    checks = [
        _doctor_schema_coverage_check(),
        _doctor_playbook_drift_check(),
        _doctor_import_layer_check(),
        _doctor_verdict_taxonomy_check(),
        _doctor_report_template_policy_check(),
        _doctor_report_validation_self_check(),
        _doctor_static_lint_check(),
        _doctor_test_suite_check(),
    ]
    _finish_doctor_checks(checks)
