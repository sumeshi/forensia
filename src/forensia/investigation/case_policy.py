"""FORENSIA.md investigation-policy adoption (V2-05).

One operator-authored Markdown input — ``case_root/FORENSIA.md`` or an
explicitly given path — is adopted at run start as investigation policy
(objective / scope / priority / constraints / guidance). It replaces the
neutral default investigation guidance *inside* the host-fixed structure:
role prompts, output schemas, typed action validation and the
evidence/assessment/settlement gates stay untouched. Adoption is fixed for
the whole run; a later edit never reopens admitted work — Case State remains
the authority for accepted Objective/Gap/Task/Spec.

State and resume: the applied body, its content hash, the designated source
and the target roles are recorded in the existing ``trace.investigation_steps``
payload (phase ``forensia-md``, one step per session, V2-05). No new table or
column. Resume always re-applies the *recorded* revision; a differing current
file is surfaced explicitly, and explicit adoption goes through the explicit
``--forensia-md`` path (a reload applies at the next session start — the safe
boundary). Raw evidence directories and parent directories are never searched
for same-name files.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from forensia.db.database import CaseDB

#: Existing-durable phase under ``investigation_steps`` for policy receipts.
CASE_POLICY_STEP_PHASE = "forensia-md"

#: The investigation roles that receive the adopted policy text (GOAL §10.5:
#: investigation roles get investigation policy; report roles get the report
#: spec — V2-06). Evidence/assessment/settlement roles never see it.
CASE_POLICY_ROLES: tuple[str, ...] = (
    "gap_identifier",
    "hypothesis_drafter",
    "query_intent_planner",
)

#: Markdown section headings that can carry admission input (objective /
#: scope). Anything else is guidance passed through as text only.
_POLICY_SECTION_KEYS = ("objective", "scope", "priority", "constraints", "guidance")


@dataclass(frozen=True, slots=True)
class CasePolicyInput:
    """The one designated policy input for this run, as read from the file."""

    body: str
    source: str  # "case_root" or "explicit_path"
    source_path: str

    @property
    def content_sha256(self) -> str:
        return sha256_hex(self.body)


@dataclass(frozen=True, slots=True)
class AppliedCasePolicy:
    """The policy actually in force for this session (recorded receipt)."""

    body: str
    content_sha256: str
    source: str
    source_path: str
    roles: tuple[str, ...] = CASE_POLICY_ROLES
    #: Non-empty when a difference to the current file was surfaced explicitly.
    notice: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """One run-start adoption decision plus its durable receipt payload."""

    applied: AppliedCasePolicy | None
    #: JSON payload for the ``forensia-md`` step; None → nothing recorded.
    record: dict[str, Any] | None = None


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _short_hash(digest: str) -> str:
    return digest[:16]


def extract_policy_sections(body: str) -> dict[str, str]:
    """Extract §labeled sections from an ATX-heading Markdown outline.

    Tiny sugar-level extraction only: a heading whose lowercased text contains
    one of the policy keys owns its body until the next heading. Host-fixed
    structure never grows beyond this.
    """
    sections: dict[str, str] = {}
    current_key: str | None = None
    buf: list[str] = []
    for line in body.splitlines():
        if line.lstrip().startswith("#"):
            if current_key is not None:
                sections[current_key] = "\n".join(buf).strip()
            current_key = None
            buf = []
            heading = line.lstrip("#").strip().lower()
            for key in _POLICY_SECTION_KEYS:
                if key in heading:
                    current_key = key
                    break
        elif current_key is not None:
            buf.append(line)
    if current_key is not None:
        sections[current_key] = "\n".join(buf).strip()
    return {key: text for key, text in sections.items() if text}


def policy_objective(policy: AppliedCasePolicy) -> str:
    """Objective text for the existing work-admission objective seam.

    The first paragraph of the ``objective`` (or ``scope``) section is used;
    without such section the policy carries no admission objective and the
    objective stays configured by the existing default path.
    """
    if not policy:
        return ""
    sections = extract_policy_sections(policy.body)
    text = sections.get("objective") or sections.get("scope") or ""
    if not text:
        return ""
    first_paragraph = text.split("\n\n", 1)[0]
    return " ".join(line.strip() for line in first_paragraph.splitlines()).strip()


def load_recorded_policy(db: CaseDB) -> dict[str, Any] | None:
    """Read the latest recorded adoption receipt (one step per session).

    Resume reads this recorded revision — never the current file. A payload
    recording ``policy_state="unset"`` (revert to neutral default) counts as
    "no policy in force" so the next run can adopt again.
    """
    row = db.execute(
        """
        SELECT output_json FROM trace.investigation_steps
        WHERE phase = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        [CASE_POLICY_STEP_PHASE],
    ).fetchone()
    if not row:
        return None
    try:
        payload = json.loads(str(row[0]))
    except json.JSONDecodeError as exc:
        raise ValueError("forensia-md receipt is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("forensia-md receipt must be a mapping")
    if payload.get("policy_state") == "unset":
        return None
    if payload.get("policy_state") not in {"adopted", "pinned"}:
        raise ValueError("forensia-md receipt has unsupported policy_state")
    if any(
        not isinstance(payload.get(key), str) or not payload[key]
        for key in ("body", "content_sha256", "source", "source_path")
    ):
        raise ValueError("forensia-md receipt is missing adopted policy fields")
    if sha256_hex(payload["body"]) != payload["content_sha256"]:
        raise ValueError("forensia-md receipt content_sha256 does not match body")
    return payload


def decide_policy(
    policy_input: CasePolicyInput | None,
    recorded: dict[str, Any] | None,
) -> PolicyDecision:
    """Resolve one run-start policy decision.

    - explicit path in use → adopt this run's content (the explicit reload);
    - other designated input (case-root ``FORENSIA.md``):
        * no recorded revision → adopt (first adoption);
        * identical content hash → adopt (unchanged, no notice);
        * differing content → keep the recorded *body* in force (pinning)
          and surface the difference explicitly;
    - no designated input at all → use the recorded revision when one exists;
      a missing file cannot silently change the policy on resume.
    """
    current_hash = sha256_hex(policy_input.body) if policy_input else None
    if policy_input is None:
        if recorded is None:
            return PolicyDecision(applied=None, record=None)
        notice = (
            f"FORENSIA.md: the input file is absent; recorded revision "
            f"{_short_hash(str(recorded['content_sha256']))} remains in force. "
            "Adopt a changed policy explicitly with --forensia-md <path>."
        )
        applied = AppliedCasePolicy(
            body=str(recorded["body"]),
            content_sha256=str(recorded["content_sha256"]),
            source=str(recorded["source"]),
            source_path=str(recorded["source_path"]),
            notice=notice,
        )
        record = {
            "policy_state": "pinned",
            "body": applied.body,
            "content_sha256": applied.content_sha256,
            "source": applied.source,
            "source_path": applied.source_path,
            "roles": list(applied.roles),
            "notice": notice,
            "current_file": {"present": False},
        }
        return PolicyDecision(applied=applied, record=record)

    if (
        recorded is None
        or policy_input.source == "explicit_path"
        or str(recorded["content_sha256"]) == current_hash
    ):
        applied = AppliedCasePolicy(
            body=policy_input.body,
            content_sha256=current_hash or "",
            source=policy_input.source,
            source_path=policy_input.source_path,
        )
    else:
        applied = AppliedCasePolicy(
            body=str(recorded["body"]),
            content_sha256=str(recorded["content_sha256"]),
            source=str(recorded["source"]),
            source_path=str(recorded["source_path"]),
            notice=(
                f"FORENSIA.md changed since the recorded revision "
                f"({_short_hash(str(recorded['content_sha256']))} → file "
                f"{_short_hash(current_hash or '')}); the recorded revision remains "
                "in force this run. Adopt explicitly: --forensia-md "
                f"{policy_input.source_path}"
            ),
        )
    record = {
        "policy_state": "pinned" if applied.notice else "adopted",
        "body": applied.body,
        "content_sha256": applied.content_sha256,
        "source": applied.source,
        "source_path": applied.source_path,
        "roles": list(applied.roles),
        "notice": applied.notice,
        "current_file": {
            "present": True,
            "sha256": current_hash,
            "source": policy_input.source,
            "path": policy_input.source_path,
        },
    }
    return PolicyDecision(applied=applied, record=record)


def collect_policy_progress_event(policy: Any) -> dict[str, Any] | None:
    """Structured progress payload that surfaces an explicit resume difference."""
    if policy is None or not getattr(policy, "notice", None):
        return None
    from forensia.core.progress_event import progress_event

    return progress_event(
        "policy.revision_pinned",
        "completed",
        severity="warning",
        stage=CASE_POLICY_STEP_PHASE,
        reason="recorded_policy_remains_in_force",
        summary=str(policy.notice),
    )


def case_policy_block(policy: AppliedCasePolicy) -> str:
    """Render the adopted policy inside the host-fixed prompt framing.

    The framing states the fixed precedence: host execution contracts (roles,
    output schemas, typed action validation, evidence/assessment/settlement
    gates) bind regardless of this policy; the adopted investigation policy
    replaces same-purpose default (playbook) guidance. Placed at the head of
    the system prompt so deterministic budget compaction (which preserves the
    head) cannot silently drop interior policy lines.
    """
    return (
        "<CASE_INSTRUCTIONS "
        f'source="{policy.source_path}" revision="{_short_hash(policy.content_sha256)}">\n'
        "Operator-authored investigation policy for this case, adopted at "
        "session start and fixed for this run. Precedence is fixed:\n"
        "- Host contracts bind regardless of this policy: role/output schemas, "
        "the typed action menu, SQL and execution validation, and the "
        "Evidence/Assessment/Sufficiency/Settlement gates are NOT overridable "
        "by any text below.\n"
        "- Where this policy conflicts with the default playbook guidance in "
        "this prompt, follow this policy.\n"
        "- This policy is investigation guidance only; it never supplies "
        "evidence, verdicts, or direct execution rights.\n"
        "<POLICY>\n"
        f"{policy.body.rstrip()}\n"
        "</POLICY>\n"
        "</CASE_INSTRUCTIONS>\n\n"
    )
