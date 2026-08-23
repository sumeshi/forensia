#!/usr/bin/env python3
"""Regenerate auto-generated sections within _schema/playbook/*.md files.

Scans each MD file for section markers like:
    <!-- AUTO-FROM: event_ids.yaml -->
    ...content...
    <!-- END-AUTO -->

And replaces the content between markers with the latest data from the YAML schemas.

Usage:
    python scripts/regenerate_playbook.py
    python scripts/regenerate_playbook.py --check  # dry-run, exit 1 if drift
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "src" / "forensia" / "knowledge" / "rulepacks" / "_schema"
PLAYBOOK_DIR = SCHEMA_DIR / "playbook"


def _load_yaml(path: Path) -> dict:
    import yaml

    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _generate_event_id_narrative() -> str:
    """Build event ID reference section from event_ids.yaml."""
    event_ids = _load_yaml(SCHEMA_DIR / "event_ids.yaml")
    events = event_ids.get("events", {}) if isinstance(event_ids, dict) else {}
    parts = []
    for eid in sorted(events, key=lambda x: int(x) if str(x).isdigit() else 0):
        info = events[eid]
        if isinstance(info, dict):
            title = info.get("title", "")
            required = info.get("required_fields", [])
            allowed = info.get("allowed_claims", [])
            disallowed = info.get("disallowed_without_extra", [])
            channels = info.get("channels", [])
            providers = info.get("providers", [])
            line = f"- Event {eid} ({title})"
            if channels:
                line += f" | ONLY meaningful on channel(s): {', '.join(str(c) for c in channels)}"
            if providers:
                line += f" | ONLY meaningful for provider(s): {', '.join(str(p) for p in providers)}"
            if required:
                line += f" | query columns: {', '.join(required)}"
            if allowed:
                line += f" | may claim: {'; '.join(allowed)}"
            if disallowed:
                line += f" | DO NOT claim: {'; '.join(disallowed)}"
            parts.append(line)
    return "\n".join(parts)


def _generate_app_catalog_narrative() -> str:
    """Build app catalog section from app_catalog.yaml."""
    app_catalog = _load_yaml(SCHEMA_DIR / "app_catalog.yaml")
    mappings = app_catalog.get("mappings", {}) if isinstance(app_catalog, dict) else {}
    parts = []
    for exe in sorted(mappings):
        info = mappings[exe]
        if isinstance(info, dict):
            parts.append(
                f"- {exe}: {info.get('category', '?')} — {info.get('description', '')}"
            )
    return "\n".join(parts)


AUTO_GENERATORS: dict[str, callable] = {
    "event_ids.yaml": _generate_event_id_narrative,
    "app_catalog.yaml": _generate_app_catalog_narrative,
}


def _process_playbook_file(path: Path, check_only: bool) -> bool:
    """Process one playbook MD file. Return True if modified."""
    content = path.read_text(encoding="utf-8")
    new_content = content
    for marker, generator in AUTO_GENERATORS.items():
        start_tag = f"<!-- AUTO-FROM: {marker} -->"
        end_tag = "<!-- END-AUTO -->"
        if start_tag not in content:
            new_content += (
                f"\n{start_tag}\n<!-- Generated content below -->\n{end_tag}\n"
            )
        start_idx = new_content.find(start_tag)
        end_idx = new_content.find(end_tag, start_idx)
        if start_idx >= 0 and end_idx >= 0:
            before = new_content[: start_idx + len(start_tag)]
            after = new_content[end_idx:]
            generated = "\n" + generator() + "\n"
            replacement = before + generated + after
            new_content = (
                new_content[:start_idx] + replacement[len(new_content[:start_idx]) :]
                if False
                else replacement
            )
    if new_content != content:
        if check_only:
            print(f"  DRIFT: {path.name}")
            return True
        path.write_text(new_content, encoding="utf-8")
        print(f"  Updated: {path.name}")
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate playbook auto-sections")
    parser.add_argument(
        "--check", action="store_true", help="Check-only: report drift without writing"
    )
    args = parser.parse_args()

    if not PLAYBOOK_DIR.exists():
        print(f"Playbook dir not found: {PLAYBOOK_DIR}")
        sys.exit(0)

    any_drift = False
    for md_path in sorted(PLAYBOOK_DIR.glob("*.md")):
        if _process_playbook_file(md_path, check_only=args.check):
            any_drift = True

    if args.check and any_drift:
        print("\nDrift detected. Run `python scripts/regenerate_playbook.py` to fix.")
        sys.exit(1)
    if not any_drift:
        print("All playbook files are up to date.")


if __name__ == "__main__":
    main()
