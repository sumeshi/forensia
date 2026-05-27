from __future__ import annotations

from pathlib import Path

import yaml

from forensia.rules.models import Rule


def load_rules_from_dir(directory: str | Path, profile_path: str | Path | None = None) -> list[Rule]:
    directory = Path(directory)
    allowed_paths: set[str] | None = None
    allowed_rule_ids: set[str] | None = None
    if profile_path:
        profile = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8")) or {}
        packs = profile.get("rulepacks") or []
        allowed_paths = {str(pack).strip("/") for pack in packs if str(pack).strip("/")}
        rule_ids = profile.get("rule_ids")
        if rule_ids:
            allowed_rule_ids = {str(rule_id).strip() for rule_id in rule_ids if str(rule_id).strip()}

    rules: list[Rule] = []
    for path in sorted(directory.rglob("*.yaml")):
        rel_path = str(path.relative_to(directory))
        rel_parent = str(path.parent.relative_to(directory))
        if allowed_paths is not None:
            matched = False
            for allowed in allowed_paths:
                if rel_path == allowed or rel_path.startswith(f"{allowed}/"):
                    matched = True
                    break
                if rel_parent == allowed or rel_parent.startswith(f"{allowed}/"):
                    matched = True
                    break
            if not matched:
                continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and str(data.get("kind") or "").startswith("allowlist"):
            continue
        if data:
            # Remove optional fields that aren't in the Rule model for backward compatibility
            # (pydantic will handle missing optional fields via default_factory)
            rule = Rule.model_validate(data)
            if allowed_rule_ids is not None and rule.id not in allowed_rule_ids:
                continue
            rules.append(rule)
    return rules
