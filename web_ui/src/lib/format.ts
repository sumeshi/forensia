export function formatVerdict(value: string | null | undefined): string {
  if (value === "confirmed") return "Confirmed";
  if (value === "refuted") return "Refuted";
  if (value === "inconclusive") return "Inconclusive";
  if (value === "newlead") return "New Lead";
  return "Undetermined";
}

export function formatReasoningPhase(value: string | null | undefined): string {
  if (value === "plan") return "plan";
  if (value === "do") return "do";
  if (value === "check") return "check";
  if (value === "act") return "act";
  if (value === "memo") return "memo";
  return value ?? "-";
}

export function reasoningToneClass(value: string | null | undefined): string {
  if (value === "confirmed") return "bg-semantic-ok";
  if (value === "refuted") return "bg-semantic-danger";
  if (value === "inconclusive") return "bg-semantic-warn";
  return "bg-mocha-overlay1";
}

export function parseServerTimestamp(value: string): Date {
  // Backend serializes naive UTC datetimes via datetime.isoformat() without a
  // timezone marker. JS new Date() would interpret these as local time, which
  // produces 9h drift on JST machines. Treat any ISO-shaped string without an
  // explicit timezone as UTC.
  const trimmed = value.trim();
  const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(trimmed);
  const normalized = trimmed.includes("T") ? trimmed : trimmed.replace(" ", "T");
  return new Date(hasTz ? normalized : normalized + "Z");
}

export function formatRelativeTime(value: string | null | undefined): string {
  if (!value) return "-";
  const target = parseServerTimestamp(value);
  if (Number.isNaN(target.getTime())) return "-";
  const diffMs = Date.now() - target.getTime();
  const diffSec = Math.max(0, Math.floor(diffMs / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  return `${diffDay}d ago`;
}

export function truncateText(value: string | null | undefined, maxChars: number): string {
  const text = (value ?? "").trim();
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars).trimEnd()}…`;
}


export function formatPhase(value: string | null | undefined): string {
  if (value === "active") return "Investigating";
  if (value === "confirmed") return "Confirmed";
  if (value === "refuted") return "Refuted";
  return "Idle";
}


export function formatStatus(value: string | null | undefined): string {
  if (value === "suppressed") return "Suppressed";
  if (value === "accepted") return "Accepted";
  if (value === "completed") return "Completed";
  if (value === "running") return "Running";
  return value ?? "-";
}

type AttackMapping = {
  tactic?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
};

export function formatAttackMappings(
  values: Array<AttackMapping | string> | null | undefined
): string {
  if (!values?.length) return "-";
  const labels = values
    .map((value) => {
      if (typeof value === "string") return value.trim();
      const techniqueId = value?.technique_id?.trim() ?? "";
      const techniqueName = value?.technique_name?.trim() ?? "";
      const tactic = value?.tactic?.trim() ?? "";
      return [techniqueId, techniqueName].filter(Boolean).join(" ") || tactic;
    })
    .filter(Boolean);
  return labels.length ? labels.join(", ") : "-";
}


export function formatStage(value: string | null | undefined): string {
  if (!value) return "Idle";
  const map: Record<string, string> = {
    investigate: "Investigate",
    "investigate/plan": "Planning",
    "investigate/hypothesis": "Hypothesis",
    "investigate/do": "Querying",
    "investigate/check": "Evaluating",
    "investigate/act": "Updating",
    "investigate/report-section": "Reporting",
    "investigate/report-section-done": "Report Updated",
    "investigate/report-cycle-done": "Investigation Complete",
    "investigate/llm": "Reasoning",
    analyze: "Analysis",
    normalize: "Normalize",
    ingest: "Ingest"
  };
  return map[value] ?? value;
}

// Coarse, human-facing case status for the header. The fine-grained momentary
// action (Querying / Evaluating / …) belongs in the activity banner, not here.
export function formatCaseStatus(value: string | null | undefined): string {
  if (!value) return "Idle";
  if (value === "investigate/report-cycle-done") return "Investigation Complete";
  if (value.startsWith("investigate")) return "Investigating";
  if (value.startsWith("analyze")) return "Analyzing";
  if (value.startsWith("normalize")) return "Normalizing";
  if (value.startsWith("ingest")) return "Ingesting";
  return formatStage(value);
}

export function formatActionVerb(value: string | null | undefined): string {
  if (!value) return "Waiting";
  const map: Record<string, string> = {
    investigate: "Running investigation cycle",
    "investigate/plan": "Planning next hypothesis to investigate",
    "investigate/hypothesis": "Tracking hypothesis",
    "investigate/do": "Issuing SQL to DuckDB",
    "investigate/check": "AI evaluating results",
    "investigate/act": "Updating memory and AI Review",
    "investigate/report-section": "Writing report section",
    "investigate/report-section-done": "Section done",
    "investigate/report-cycle-done": "Closing report cycle",
    "investigate/llm": "LLM reasoning",
    analyze: "Running rules",
    normalize: "Normalizing logs",
    ingest: "Ingesting logs"
  };
  return map[value] ?? value;
}

export function getPipelinePhase(value: string | null | undefined): { index: number; total: number; label: string } {
  if (!value) {
    return { index: 0, total: 4, label: "Idle" };
  }
  if (value.startsWith("ingest")) {
    return { index: 1, total: 4, label: "Ingest" };
  }
  if (value.startsWith("normalize")) {
    return { index: 2, total: 4, label: "Normalize" };
  }
  if (value.startsWith("analyze")) {
    return { index: 3, total: 4, label: "Analyze" };
  }
  if (value.startsWith("investigate")) {
    return { index: 4, total: 4, label: "Investigate" };
  }
  return { index: 0, total: 4, label: formatStage(value) };
}

export function getInvestigateSubphase(value: string | null | undefined): { index: number; total: number; label: string } | null {
  const order = [
    "investigate/plan",
    "investigate/hypothesis",
    "investigate/do",
    "investigate/check",
    "investigate/act",
    "investigate/report-section",
    "investigate/report-cycle-done"
  ];
  if (!value || !value.startsWith("investigate")) {
    return null;
  }
  const normalized = value === "investigate/report-section-done" ? "investigate/report-section" : value;
  const index = order.indexOf(normalized);
  return {
    index: index >= 0 ? index + 1 : 0,
    total: order.length,
    label: formatStage(value)
  };
}
