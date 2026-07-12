"""Parse report templates: frontmatter metadata, preamble/body split, block hints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TemplateMeta:
    type: str = ""
    title: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()
    timestamp: str = ""
    instructions: str = ""


GAP_PATTERN = re.compile(
    r"\[INSUFFICIENT EVIDENCE:\s*([^\]]+)\]",
    re.IGNORECASE,
)
BLOCK_HINT_PATTERN = re.compile(
    r"<!--\s*(?P<name>evidence_keypoints|mode|question_id|benchmark_id|answer_id|answer_spec|builder)\s*:\s*(?P<value>.*?)\s*-->",
    re.IGNORECASE,
)
QUESTION_HINT_PATTERN = re.compile(
    r"<!--\s*question(?:\s*:\s*(?P<value>.*?))?\s*-->", re.IGNORECASE
)
RAW_EVIDENCE_HEADING_PATTERN = re.compile(r"^#{2,6}\s*Raw Evidence\s*$", re.IGNORECASE)


def parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter dict from text starting with ---."""
    if not text.startswith("---\n"):
        return {}
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        return {}
    import yaml

    try:
        meta = yaml.safe_load(parts[1])
    except Exception:
        meta = {}
    return meta if isinstance(meta, dict) else {}


@cache
def parse_template(template_path: str) -> tuple[str, TemplateMeta]:
    """Parse YAML front matter from a template file, returning (body, meta)."""
    text = Path(template_path).read_text(encoding="utf-8")
    meta = parse_frontmatter(text)
    if text.startswith("---\n"):
        parts = text.split("---\n", 2)
        body = parts[2].strip() if len(parts) == 3 else text.strip()
    else:
        body = text.strip()
    instructions = str(meta.get("instructions") or "").strip()
    raw_tags = meta.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    tags = tuple(str(tag).strip() for tag in raw_tags if str(tag).strip())
    return body, TemplateMeta(
        type=str(meta.get("type") or "").strip(),
        title=str(meta.get("title") or "").strip(),
        description=str(meta.get("description") or "").strip(),
        tags=tags,
        timestamp=str(meta.get("timestamp") or "").strip(),
        instructions=instructions,
    )


def parse_block_hints(block_body: str) -> dict[str, Any]:
    """Extract hint annotations from a block's HTML comment markers."""
    hints: dict[str, Any] = {
        "evidence_keypoints": [],
        "mode": "",
        "question_id": "",
        "answer_id": "",
        "answer_spec": "",
        "question": "",
        "builder": "",
    }

    def _iter_hint_pairs(name: str, value: str):
        parts = [part.strip() for part in value.split(";")]
        yield name, parts[0]
        for part in parts[1:]:
            if ":" in part:
                sub_name, sub_value = part.split(":", 1)
                yield sub_name.strip().lower(), sub_value.strip()

    seen_keypoints: set[str] = set()
    pairs: list[tuple[str, str]] = []
    for match in BLOCK_HINT_PATTERN.finditer(block_body):
        raw_name = str(match.group("name") or "").strip().lower()
        raw_value = str(match.group("value") or "").strip()
        if not raw_name or not raw_value:
            continue
        pairs.extend(_iter_hint_pairs(raw_name, raw_value))

    for name, value in pairs:
        if not name or not value:
            continue
        if name == "evidence_keypoints":
            keypoints = [
                item.strip() for item in re.split(r"[,，\s]+", value) if item.strip()
            ]
            for keypoint in keypoints:
                if keypoint in seen_keypoints:
                    continue
                seen_keypoints.add(keypoint)
                hints["evidence_keypoints"].append(keypoint)
        elif name == "mode":
            hints["mode"] = value.casefold()
        elif name in ("question_id", "benchmark_id"):
            hints["question_id"] = value.strip()
            hints["answer_id"] = value.strip()
        elif name == "answer_id":
            hints["answer_id"] = value.strip()
        elif name == "answer_spec":
            hints["answer_spec"] = value.strip()
        elif name == "builder":
            hints["builder"] = value.strip()

    question_match = QUESTION_HINT_PATTERN.search(block_body)
    if question_match:
        hints["question"] = str(question_match.group("value") or "").strip()
        if not hints["mode"]:
            hints["mode"] = "structured"
    if hints["question"] and not hints["mode"]:
        hints["mode"] = "structured"
    return hints


def split_template_body(template_body: str) -> tuple[str, list[dict[str, Any]]]:
    """Split template body into preamble and annotated Markdown blocks."""
    lines = template_body.splitlines()
    preamble: list[str] = []
    blocks: list[dict[str, Any]] = []
    current_heading: str | None = None
    current_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            if current_heading is not None:
                current_text = "\n".join(current_lines).strip()
                blocks.append(
                    {
                        "heading": current_heading,
                        "template_body": current_text,
                        **parse_block_hints(current_text),
                    }
                )
            current_heading = stripped[3:].strip()
            current_lines = [line]
        elif current_heading is None:
            preamble.append(line)
        else:
            current_lines.append(line)

    if current_heading is not None:
        current_text = "\n".join(current_lines).strip()
        blocks.append(
            {
                "heading": current_heading,
                "template_body": current_text,
                **parse_block_hints(current_text),
            }
        )
    preamble_text = "\n".join(preamble).strip()
    return preamble_text, blocks


_parse_frontmatter = parse_frontmatter
_parse_template = parse_template
_parse_block_hints = parse_block_hints
_split_template_body = split_template_body
