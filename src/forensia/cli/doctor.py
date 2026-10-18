"""Offline health checks for the installed package; development gates live in CI."""

import sys
import tempfile
from collections.abc import Callable

from rich import print


def _check(label: str, check: Callable[[], None]) -> tuple[str, bool]:
    print(f"[bold cyan]==>[/bold cyan] {label}...")
    try:
        check()
    except Exception as exc:
        print(f"  FAIL {label}: {exc}")
        return label, False
    print(f"  OK {label}")
    return label, True


def _declarations() -> None:
    from forensia.core.verdicts import valid_verdicts
    from forensia.knowledge.catalog import validate_declarations

    validate_declarations()
    for category in ("hypothesis_verdict", "section_verdict", "structured_status"):
        if not valid_verdicts(category):
            raise ValueError(f"Missing verdict category: {category}")


def _sigma_bundle() -> None:
    from forensia.knowledge.resources import sigma_bundle_path
    from forensia.knowledge.sigma_bundle import load_sigma_bundle

    path = sigma_bundle_path()
    if not path.exists():
        print("  Sigma rules not installed; run 'forensia setup' before offline use")
        return
    bundle = load_sigma_bundle(path)
    counts = bundle["summary"]
    print(
        "  Sigma bundle: "
        f"build={bundle['build_id'][:12]}, "
        f"rules={counts['admitted_rules']}/{counts['total']}, "
        f"targets={counts['admitted_bindings']}/{counts['bindings']}, "
        f"fixture_verified={counts['by_fixture']['passed']}"
    )


def _case_storage() -> None:
    from forensia.core.case import Case
    from forensia.db.database import CaseDB

    with tempfile.TemporaryDirectory(prefix="forensia-doctor-") as directory:
        case = Case.init(directory)
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO trace.investigation_steps (step_id, phase) VALUES ('doctor', 'health')"
            )
        with CaseDB(case) as db:
            if db.execute(
                "SELECT phase FROM trace.investigation_steps WHERE step_id = 'doctor'"
            ).fetchone() != ("health",):
                raise RuntimeError("Trace persistence readback failed")
            db.execute("SELECT COUNT(*) FROM evidence_sources").fetchone()


def _doctor_report_template_policy_check() -> tuple[str, bool]:
    print("[bold cyan]==>[/bold cyan] Report template contract...")
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
            print("  OK Packaged templates include knowledge metadata and instructions")
        else:
            print(
                "  FAIL Invalid packaged templates:\n"
                + "\n".join(f"      - {p}" for p in problems)
            )
        return "Report template contract", ok
    except Exception as exc:
        print(f"  FAIL Error: {exc}")
        return "Report template contract", False


def run_doctor() -> None:
    """Check installed declarations, packaged templates and disposable storage."""
    checks = [
        _check("Packaged declarations", _declarations),
        _check("User-installed Sigma rules", _sigma_bundle),
        _doctor_report_template_policy_check(),
        _check("Case/Trace storage", _case_storage),
    ]
    failed = [name for name, ok in checks if not ok]
    if failed:
        print(f"[bold red]Failed: {', '.join(failed)}[/bold red]")
    else:
        print(f"[bold green]All {len(checks)} checks passed[/bold green]")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    run_doctor()
