#!/usr/bin/env python3
"""Evaluate investigation quality metrics from a forensia case directory.

Usage:
    python scripts/eval_run.py <case_dir>

Outputs report.json and prints a Markdown summary.

Metrics computed (all case-agnostic, no DB/LLM dependency):
  1. Hypothesis family diversity — distribution of artifact families
  2. Confirmed-while-benign rate — proportion of confirmed hypotheses whose
     supporting rows match benign-context rules (placeholder; returns 0
     when R2-06 annotations absent)
  3. Placeholder leak count — regex for {...} and [placeholder] in
     hypotheses, facts, and SQL log content
  4. Memory duplication ratio — pairwise token-set similarity >=0.7 among
     overview.md lines
  5. Report hygiene — error-string leaks, bare-ID tables, day coverage
  6. Evidence traceability — share of report claims with resolvable IDs
  7. Per-phase LLM call counts — from ai_logs meta phase labels
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def _parse_hypothesis_file(path: Path) -> dict:
    text = _read(path)
    lines = text.splitlines()
    meta = {
        "id": path.stem,
        "path": str(path),
        "status": "",
        "verdict": "",
        "description": "",
        "summary": "",
    }
    in_section = None
    for line in lines:
        stripped = line.strip()
        if stripped == "## Status":
            in_section = "status"
        elif stripped == "## Verdict":
            in_section = "verdict"
        elif stripped == "## Description":
            in_section = "description"
        elif stripped == "## Summary":
            in_section = "summary"
        elif stripped.startswith("## "):
            in_section = None
        elif in_section and stripped and not stripped.startswith("#"):
            if in_section == "status":
                meta["status"] = stripped.lstrip("- ")
            elif in_section == "verdict":
                meta["verdict"] = stripped.lstrip("- ")
            elif in_section == "description":
                meta["description"] += stripped + " "
            elif in_section == "summary":
                meta["summary"] += stripped + " "
    for k in ("description", "summary"):
        meta[k] = meta[k].strip()
    return meta


def _load_hypotheses(memory_dir: Path) -> list[dict]:
    hyp_dir = memory_dir / "hypotheses"
    if not hyp_dir.is_dir():
        return []
    results = []
    for f in sorted(hyp_dir.iterdir()):
        if f.suffix == ".md":
            results.append(_parse_hypothesis_file(f))
    return results


def _family_from_description(desc: str) -> str:
    lower = desc.lower()
    if any(
        w in lower
        for w in (
            "logon",
            "log in",
            "log-in",
            "rdp",
            "credential",
            "authentication",
            "password",
            "4648",
            "4624",
            "4625",
        )
    ):
        return "account"
    if any(w in lower for w in ("service", "driver", "installation", "7045", "7040")):
        return "persistence"
    if any(w in lower for w in ("timeline", "time", "date", "sequence", "chornolog")):
        return "timeline"
    if any(
        w in lower
        for w in ("mft", "file", "rename", "desktop", "document", "folder", "directory")
    ):
        return "mft"
    if any(w in lower for w in ("prefetch", "execut", "process", "binary", "program")):
        return "host"
    if any(
        w in lower
        for w in ("cloud", "email", "mail", "browser", "internet", "sync", "drive")
    ):
        return "ioc"
    if any(
        w in lower
        for w in (
            "antiforensic",
            "anti-forensic",
            "log clear",
            "tamper",
            "eraser",
            "ccleaner",
        )
    ):
        return "gaps"
    if any(w in lower for w in ("ip", "network", "connect", "external", "remote")):
        return "ioc"
    return "other"


def _load_facts(memory_dir: Path) -> list[str]:
    facts_text = _read(memory_dir / "facts.md")
    lines = []
    for line in facts_text.splitlines():
        stripped = line.strip().lstrip("- ")
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def _load_overview(memory_dir: Path) -> list[str]:
    text = _read(memory_dir / "overview.md")
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def _load_report(path: Path) -> str:
    report_md = path / "reports" / "report.md"
    return _read(report_md)


def _token_set(s: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z0-9_]+", s.lower()))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _find_placeholder_lines(text: str) -> list[str]:
    pattern = re.compile(
        r"\{[a-z_]+}|\[[a-z_]*placeholder[a-z_]*]|\[start_time]|\[end_time]"
    )
    return [line for line in text.splitlines() if pattern.search(line)]


_INSTRUCTION_TONE_RE = re.compile(
    r"(してください|必要があります|べきです|do not treat|should be verified|"
    r"を確認する必要があります|を確認してください|扱わないでください|を分けて扱い|"
    r"として扱わない|読みべきです|相関してください|断定せず|評価してください)",
    re.IGNORECASE,
)

_EVIDENCE_ID_RE_GLOBAL = re.compile(r"\b(evtx|mft|prefetch)-[a-z0-9-]+\b")


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


def instruction_tone_ratio(text: str) -> float:
    """Return the fraction of sentences that contain instruction-tone phrases."""
    if not text:
        return 0.0
    sentences = re.split(r"[。．.!?\n]+", text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return 0.0
    flagged = sum(1 for s in sentences if _INSTRUCTION_TONE_RE.search(s))
    return flagged / len(sentences)


def ui_file_consistency(report_sections_path: str, report_md_path: str) -> dict:
    """Check if report_sections bodies match report.md content."""
    sections_path = Path(report_sections_path)
    md_path = Path(report_md_path)

    if not sections_path.exists() or not md_path.exists():
        return {"status": "missing_files", "mismatches": []}

    sections = json.loads(sections_path.read_text())
    md_text = md_path.read_text()

    mismatches = []
    for section in sections:
        key = section.get("section_key", "")
        body = str(section.get("body", "")).strip()
        body_preview = body[:200]
        if body_preview and body_preview not in md_text:
            mismatches.append(
                {
                    "section_key": key,
                    "body_preview": body_preview[:100],
                }
            )

    return {
        "status": "ok" if not mismatches else "mismatch",
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:5],
    }


def block_language_conformity(
    report_sections_path: str, target_language: str = "ja"
) -> dict:
    """Check per-block language conformity from report_sections.json."""
    sections_path = Path(report_sections_path)
    if not sections_path.exists():
        return {"status": "missing_file", "blocks": 0, "conforming": 0}

    sections = json.loads(sections_path.read_text())

    from forensia.report.writer import _detect_body_language

    total_blocks = 0
    conforming = 0
    block_results = []

    for section in sections:
        body = str(section.get("body", "")).strip()
        if not body:
            continue
        clean = re.sub(r"^\*\*Status:\*\*.*$", "", body, flags=re.MULTILINE).strip()
        if not clean:
            continue
        total_blocks += 1
        detected = _detect_body_language(clean)
        if detected == target_language:
            conforming += 1
        block_results.append(
            {
                "section_key": section.get("section_key", ""),
                "detected": detected,
                "target": target_language,
            }
        )

    return {
        "blocks": total_blocks,
        "conforming": conforming,
        "rate": conforming / total_blocks if total_blocks else 1.0,
        "target_language": target_language,
        "block_results": block_results,
    }


def count_invalid_evidence_ids(report_sections_path: str, db_path: str) -> dict:
    """Count cited evidence IDs that don't exist in the DB."""
    import duckdb

    sections_path = Path(report_sections_path)
    db_file = Path(db_path)

    if not sections_path.exists() or not db_file.exists():
        return {"status": "missing_files", "invalid_count": 0}

    conn = duckdb.connect(str(db_file))
    sections = json.loads(sections_path.read_text())

    table_map = {
        "evtx": "evtx_events",
        "mft": "mft_entries",
        "prefetch": "prefetch_executions",
    }

    all_ids = set()
    for section in sections:
        body = str(section.get("body", "")).strip()
        for match in _EVIDENCE_ID_RE_GLOBAL.finditer(body):
            all_ids.add(match.group(0))

    invalid = []
    valid = []
    for eid in sorted(all_ids):
        prefix = eid.split("-")[0]
        table = table_map.get(prefix)
        if not table:
            invalid.append(eid)
            continue
        try:
            row = conn.execute(
                f"SELECT 1 FROM {table} WHERE evidence_id = ? LIMIT 1", (eid,)
            ).fetchone()
            if row:
                valid.append(eid)
            else:
                invalid.append(eid)
        except Exception:
            invalid.append(eid)

    conn.close()
    return {
        "total_cited": len(all_ids),
        "valid": len(valid),
        "invalid_count": len(invalid),
        "invalid_ids": invalid,
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def hypothesis_family_diversity(hypotheses: list[dict]) -> dict:
    families = Counter()
    for h in hypotheses:
        families[_family_from_description(h.get("description", ""))] += 1
    total = sum(families.values()) or 1
    shares = {k: round(v / total, 3) for k, v in sorted(families.items())}
    dominant_share = max(shares.values()) if shares else 0
    return {
        "total_hypotheses": sum(families.values()),
        "families": dict(families),
        "family_shares": shares,
        "dominant_family_share": dominant_share,
        "flag_single_family_over_70pct": dominant_share > 0.7,
    }


def confirmed_while_benign_rate(hypotheses: list[dict]) -> dict:
    confirmed = [h for h in hypotheses if h.get("verdict") == "confirmed"]
    total_confirmed = len(confirmed)
    return {
        "total_confirmed": total_confirmed,
        "note": "benign-context annotation (R2-06) not implemented yet; rate is 0 until annotations available",
        "confirmed_while_benign_count": 0,
        "confirmed_while_benign_rate": 0.0,
    }


def placeholder_leak_count(memory_dir: Path, ai_logs_dir: Path | None) -> dict:
    sources: dict[str, list[str]] = {}
    overview_text = _read(memory_dir / "overview.md")
    facts_text = _read(memory_dir / "facts.md")
    hyp_dir = memory_dir / "hypotheses"
    all_hyp_text = ""
    if hyp_dir.is_dir():
        for f in hyp_dir.iterdir():
            if f.suffix == ".md":
                all_hyp_text += _read(f) + "\n"

    for label, text in [
        ("hypotheses", all_hyp_text),
        ("facts", facts_text),
        ("overview", overview_text),
    ]:
        leaks = _find_placeholder_lines(text)
        if leaks:
            sources[label] = leaks

    sql_text = ""
    if ai_logs_dir and ai_logs_dir.is_dir():
        for f in sorted(ai_logs_dir.iterdir()):
            if f.suffix == ".json":
                raw = f.read_text(encoding="utf-8", errors="replace")
                found = _find_placeholder_lines(raw)
                if found:
                    sql_text += "\n".join(found) + "\n"
        sql_leaks = _find_placeholder_lines(sql_text)
        if sql_leaks:
            sources["ai_logs_sql_content"] = sql_leaks

    total_lines = sum(len(v) for v in sources.values())
    return {
        "total_leak_lines": total_lines,
        "sources_with_leaks": {k: len(v) for k, v in sources.items()},
        "leak_detail_by_source": {k: v[:5] for k, v in sources.items()},
    }


def memory_duplication_ratio(overview_lines: list[str]) -> dict:
    if len(overview_lines) < 2:
        return {
            "pairwise_comparisons": 0,
            "high_similarity_pairs": 0,
            "duplication_ratio": 0.0,
            "flag_high_duplication": False,
        }

    token_sets = [_token_set(line) for line in overview_lines]
    high_sim = 0
    total_pairs = 0
    for i in range(len(token_sets)):
        for j in range(i + 1, len(token_sets)):
            total_pairs += 1
            if _jaccard(token_sets[i], token_sets[j]) >= 0.7:
                high_sim += 1

    ratio = high_sim / total_pairs if total_pairs else 0.0
    return {
        "total_lines": len(overview_lines),
        "pairwise_comparisons": total_pairs,
        "high_similarity_pairs": high_sim,
        "duplication_ratio": round(ratio, 3),
        "flag_high_duplication": ratio > 0.3,
    }


def report_hygiene(case_dir: Path, hypotheses: list[dict]) -> dict:
    report_text = _load_report(case_dir)

    # 1. Error string leaks
    error_patterns = re.compile(
        r"(sqlglot|internal-error|LLM failed|Required keyword|ValueError|KeyError|TypeError|Traceback|duckdb\.Error)",
        re.IGNORECASE,
    )
    error_lines = [l for l in report_text.splitlines() if error_patterns.search(l)]

    # 2. Bare-ID tables (Unresolved Hypotheses table cells containing only IDs)
    bare_id_pattern = re.compile(r"^\| (H-\d+|gap-[a-f0-9]+) \|", re.MULTILINE)
    bare_id_hits = bare_id_pattern.findall(report_text)

    # 3. Days with findings vs days in timeline
    finding_dates = set()
    findings_dir = case_dir / "findings"
    if findings_dir.is_dir():
        for f in findings_dir.iterdir():
            if f.suffix == ".json":
                finding_data = json.loads(_read(f))
                for ev in finding_data.get("evidence", []):
                    ts = ev.get("timestamp", "")
                    if ts:
                        d = ts[:10]
                        if re.match(r"\d{4}-\d{2}-\d{2}", d):
                            finding_dates.add(d)
    timeline_dates = set()
    memory_timeline = _read(case_dir / "memory" / "timeline.md")
    for m in re.finditer(r"\d{4}-\d{2}-\d{2}", memory_timeline):
        timeline_dates.add(m.group())
    for m in re.finditer(r"\|\s*(\d{4}-\d{2}-\d{2})\s*\|", report_text):
        timeline_dates.add(m.group(1))

    return {
        "error_string_leaks": len(error_lines),
        "error_preview_lines": error_lines[:3],
        "bare_id_hypotheses_in_report": bare_id_hits,
        "bare_id_count": len(bare_id_hits),
        "days_with_findings": len(finding_dates),
        "days_in_timeline_coverage": len(timeline_dates),
        "day_coverage_ratio": round(
            len(timeline_dates) / max(len(finding_dates), 1), 3
        ),
    }


def evidence_traceability(case_dir: Path) -> dict:
    report_text = _load_report(case_dir)
    finding_ids = re.findall(r"finding_id['\"]?\s*[:=]\s*['\"]?([\w\-]+)", report_text)
    evidence_ids_in_report = re.findall(
        r"evidence_id['\"]?\s*[:=]\s*['\"]?([\w\-]+)", report_text
    )

    findings_dir = case_dir / "findings"
    registered_evidence_ids: set[str] = set()
    registered_finding_ids: set[str] = set()
    if findings_dir.is_dir():
        for f in findings_dir.iterdir():
            if f.suffix == ".json":
                try:
                    data = json.loads(_read(f))
                    fid = data.get("finding_id")
                    if fid:
                        registered_finding_ids.add(fid)
                    for ev in data.get("evidence", []):
                        eid = ev.get("evidence_id")
                        if eid:
                            registered_evidence_ids.add(eid)
                except json.JSONDecodeError:
                    pass

    resolvable_findings = sum(1 for fid in finding_ids if fid in registered_finding_ids)
    resolvable_evidence = sum(
        1 for eid in evidence_ids_in_report if eid in registered_evidence_ids
    )
    total_claims_in_report = len(finding_ids) + len(evidence_ids_in_report) or 1

    return {
        "finding_ids_in_report": len(finding_ids),
        "evidence_ids_in_report": len(evidence_ids_in_report),
        "resolvable_finding_ids": resolvable_findings,
        "resolvable_evidence_ids": resolvable_evidence,
        "traceability_ratio": round(
            (resolvable_findings + resolvable_evidence) / total_claims_in_report, 3
        ),
    }


def per_phase_llm_call_counts(ai_logs_dir: Path) -> dict:
    if not ai_logs_dir or not ai_logs_dir.is_dir():
        return {"note": "ai_logs directory not found", "phases": {}, "total_calls": 0}

    counts: Counter[str] = Counter()
    for f in ai_logs_dir.iterdir():
        if f.suffix == ".json":
            try:
                data = json.loads(_read(f))
                phase = data.get("meta", {}).get("phase", "unknown")
            except json.JSONDecodeError, KeyError:
                phase = "unknown"
            counts[phase] += 1

    return {
        "phases": dict(counts),
        "total_calls": sum(counts.values()),
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def evaluate(case_dir: Path) -> dict:
    memory_dir = case_dir / "memory"
    ai_logs = _find_ai_logs(case_dir)
    reports_dir = case_dir / "reports"
    db_dir = case_dir / "db"

    hypotheses = _load_hypotheses(memory_dir)
    overview_lines = _load_overview(memory_dir)

    metrics = {
        "case_dir": str(case_dir),
        "hypothesis_family_diversity": hypothesis_family_diversity(hypotheses),
        "confirmed_while_benign_rate": confirmed_while_benign_rate(hypotheses),
        "placeholder_leak_count": placeholder_leak_count(memory_dir, ai_logs),
        "memory_duplication_ratio": memory_duplication_ratio(overview_lines),
        "report_hygiene": report_hygiene(case_dir, hypotheses),
        "evidence_traceability": evidence_traceability(case_dir),
        "per_phase_llm_call_counts": per_phase_llm_call_counts(ai_logs),
    }

    # R3-11: Eval metrics for failure detection
    report_sections_path = reports_dir / "report_sections.json"
    if report_sections_path.exists():
        report_sections = json.loads(_read(report_sections_path))
        section_texts = {
            s.get("section_key", f"block_{i}"): str(s.get("body", ""))
            for i, s in enumerate(report_sections)
        }
    else:
        section_texts = {}
        report_sections = []

    ir = {}
    for section_key, text in section_texts.items():
        ir[section_key] = instruction_tone_ratio(text)

    report_md_path = reports_dir / "report.md"
    blc = (
        block_language_conformity(str(report_sections_path))
        if report_sections_path.exists()
        else {"status": "missing_file"}
    )
    db_path = db_dir / "case.duckdb"
    inv = (
        count_invalid_evidence_ids(str(report_sections_path), str(db_path))
        if report_sections_path.exists()
        else {"status": "missing_files"}
    )

    metrics["r3_metrics"] = {
        "instruction_tone_ratio": ir,
        "ui_file_consistency": ui_file_consistency(
            str(report_sections_path), str(report_md_path)
        ),
        "block_language_conformity": blc,
        "invalid_evidence_ids": inv,
    }
    return metrics


def _find_ai_logs(case_dir: Path) -> Path | None:
    ai_logs_dir = case_dir / "ai_logs"
    if ai_logs_dir.is_dir():
        sessions = sorted(ai_logs_dir.iterdir())
        if sessions:
            return sessions[-1]
    return None


def _format_markdown(metrics: dict) -> str:
    lines = []
    lines.append("# Evaluation Report")
    lines.append("")
    lines.append(f"**Case directory:** `{metrics['case_dir']}`")
    lines.append("")

    lines.append("## 1. Hypothesis Family Diversity")
    d = metrics["hypothesis_family_diversity"]
    lines.append(f"- Total hypotheses: {d['total_hypotheses']}")
    lines.append(f"- Families: {d['families']}")
    lines.append(f"- Dominant family share: {d['dominant_family_share']:.1%}")
    lines.append(
        f"- ⚠️ **Flag (>70% single-family):** {d['flag_single_family_over_70pct']}"
    )
    lines.append("")

    lines.append("## 2. Confirmed-while-Benign Rate")
    d = metrics["confirmed_while_benign_rate"]
    lines.append(f"- Total confirmed hypotheses: {d['total_confirmed']}")
    lines.append(
        f"- Confirmed-while-benign: {d['confirmed_while_benign_count']} ({d['confirmed_while_benign_rate']})"
    )
    lines.append(f"- Note: {d['note']}")
    lines.append("")

    lines.append("## 3. Placeholder Leak Count")
    d = metrics["placeholder_leak_count"]
    lines.append(f"- Total leak lines: {d['total_leak_lines']}")
    for src, cnt in d.get("sources_with_leaks", {}).items():
        lines.append(f"  - {src}: {cnt} leak(s)")
    if d.get("leak_detail_by_source"):
        for src, leaks in d["leak_detail_by_source"].items():
            if leaks:
                lines.append(f"  - {src} (first {len(leaks)}):")
                for leak in leaks:
                    lines.append(f"    - `{leak[:100]}`")
    lines.append("")

    lines.append("## 4. Memory Duplication Ratio")
    d = metrics["memory_duplication_ratio"]
    lines.append(f"- Overview lines: {d['total_lines']}")
    lines.append(f"- Pairwise comparisons: {d['pairwise_comparisons']}")
    lines.append(
        f"- High-similarity pairs (≥0.7 Jaccard): {d['high_similarity_pairs']}"
    )
    lines.append(f"- Duplication ratio: {d['duplication_ratio']}")
    lines.append(f"- ⚠️ **Flag (ratio >0.3):** {d['flag_high_duplication']}")
    lines.append("")

    lines.append("## 5. Report Hygiene")
    d = metrics["report_hygiene"]
    lines.append(f"- Error string leaks: {d['error_string_leaks']}")
    if d.get("error_preview_lines"):
        for el in d["error_preview_lines"]:
            lines.append(f"  - `{el[:120]}`")
    lines.append(f"- Bare-ID hypotheses in report: {d['bare_id_count']}")
    if d.get("bare_id_hypotheses_in_report"):
        lines.append(f"  - IDs: {d['bare_id_hypotheses_in_report'][:5]}")
    lines.append(f"- Days with findings: {d['days_with_findings']}")
    lines.append(f"- Days in timeline coverage: {d['days_in_timeline_coverage']}")
    lines.append(f"- Day coverage ratio: {d['day_coverage_ratio']}")
    lines.append("")

    lines.append("## 6. Evidence Traceability")
    d = metrics["evidence_traceability"]
    lines.append(f"- Finding IDs in report: {d['finding_ids_in_report']}")
    lines.append(f"- Evidence IDs in report: {d['evidence_ids_in_report']}")
    lines.append(f"- Resolvable finding IDs: {d['resolvable_finding_ids']}")
    lines.append(f"- Resolvable evidence IDs: {d['resolvable_evidence_ids']}")
    lines.append(f"- Traceability ratio: {d['traceability_ratio']}")
    lines.append("")

    lines.append("## 7. Per-Phase LLM Call Counts")
    d = metrics["per_phase_llm_call_counts"]
    lines.append(f"- Total LLM calls: {d['total_calls']}")
    for phase, count in sorted(d.get("phases", {}).items()):
        lines.append(f"  - {phase}: {count}")
    if "note" in d:
        lines.append(f"- Note: {d['note']}")
    lines.append("")

    # R3-11 sections
    r3 = metrics.get("r3_metrics", {})
    if r3:
        lines.append("## 8. Instruction-Tone Ratio")
        ir = r3.get("instruction_tone_ratio", {})
        if ir:
            for section_key, ratio in ir.items():
                flag = " ⚠️" if ratio > 0.10 else ""
                lines.append(f"- {section_key}: {ratio:.1%}{flag}")
        else:
            lines.append("- No report sections found.")
        lines.append("")

        lines.append("## 9. UI / File Consistency")
        uif = r3.get("ui_file_consistency", {})
        lines.append(f"- Status: {uif.get('status', 'unknown')}")
        lines.append(f"- Mismatch count: {uif.get('mismatch_count', 0)}")
        for m in uif.get("mismatches", []):
            lines.append(f"  - {m['section_key']}: `{m['body_preview'][:80]}`")
        lines.append("")

        lines.append("## 10. Per-Block Language Conformity")
        blc = r3.get("block_language_conformity", {})
        lines.append(f"- Blocks: {blc.get('blocks', 0)}")
        lines.append(f"- Conforming: {blc.get('conforming', 0)}")
        lines.append(f"- Rate: {blc.get('rate', 1.0):.1%}")
        lines.append(f"- Target language: {blc.get('target_language', 'ja')}")
        lines.append("")

        lines.append("## 11. Invalid Evidence ID Count")
        inv = r3.get("invalid_evidence_ids", {})
        lines.append(f"- Total cited: {inv.get('total_cited', 0)}")
        lines.append(f"- Valid: {inv.get('valid', 0)}")
        lines.append(f"- Invalid: {inv.get('invalid_count', 0)}")
        ids = inv.get("invalid_ids", [])
        if ids:
            lines.append(f"- Invalid IDs: {ids[:10]}")
        if "status" in inv:
            lines.append(f"- Note: {inv['status']}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate investigation quality metrics for a forensia case"
    )
    parser.add_argument("case_dir", type=str, help="Path to forensia case directory")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON path (default: <case_dir>/eval_report.json)",
    )
    parser.add_argument(
        "--markdown",
        type=str,
        default=None,
        help="Output Markdown path (default: stdout)",
    )
    args = parser.parse_args()

    case_path = Path(args.case_dir).resolve()
    if not case_path.is_dir():
        print(f"Error: {args.case_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    metrics = evaluate(case_path)

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = case_path / "eval_report.json"
    output_path.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"JSON report saved to {output_path}", file=sys.stderr)

    md = _format_markdown(metrics)
    if args.markdown:
        Path(args.markdown).write_text(md, encoding="utf-8")
        print(f"Markdown report saved to {args.markdown}", file=sys.stderr)
    else:
        print(md)


if __name__ == "__main__":
    main()
