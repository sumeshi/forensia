import { derived } from "svelte/store";

import { findings, hypotheses, reportSections } from "../stores";
import { formatVerdict } from "../format";

export const whatWeKnow = derived([findings], ([$findings]) => {
  const accepted = $findings.filter((item) => item.status !== "suppressed").slice(0, 3);
  if (accepted.length === 0) return ["No significant findings yet."];
  return accepted.map((item) => `${item.title} (${item.severity})`);
});

export const currentHypothesis = derived([hypotheses], ([$hypotheses]) => {
  const active = $hypotheses.active[0];
  if (!active) {
    return {
      title: "No active hypothesis",
      status: "Idle",
      summary: "Waiting for new hypothesis generation or gap injection."
    };
  }
  return {
    title: active.description,
    status: "Investigating",
    summary: active.latest_reasoning?.[0]?.body || active.summary || "Exploring additional evidence."
  };
});

export const whyItMatters = derived([findings, hypotheses], ([$findings, $hypotheses]) => {
  const highest = $findings.find((item) => item.status !== "suppressed");
  if (highest) {
    return `${highest.severity.toUpperCase()} severity findings present, impact assessment needed.`;
  }
  if ($hypotheses.active.length > 0) {
    return "Hypotheses remain, but confirmed findings are still lacking.";
  }
  return "No significant unresolved findings at this time.";
});

export const nextAction = derived([reportSections, hypotheses], ([$reportSections, $hypotheses]) => {
  const writing = $reportSections.find((section) => section.is_writing);
  if (writing) return `${writing.title} is being filled.`;
  const gapSection = $reportSections.find((section) => section.gap_count > 0);
  if (gapSection) return `${gapSection.title} gaps require additional confirmation.`;
  const active = $hypotheses.active[0];
  if (active) return `Next: validate hypothesis "${active.description}".`;
  return "No additional work found.";
});

type RecencySortable = {
  latestReasoningAt: string | null;
  latestIteration: number | null;
};

function byRecency(a: RecencySortable, b: RecencySortable): number {
  const aTime = a.latestReasoningAt ? new Date(a.latestReasoningAt).getTime() : 0;
  const bTime = b.latestReasoningAt ? new Date(b.latestReasoningAt).getTime() : 0;
  if (aTime !== bTime) return bTime - aTime;
  return (b.latestIteration ?? 0) - (a.latestIteration ?? 0);
}

export const activeHypothesesView = derived([hypotheses], ([$hypotheses]) =>
  $hypotheses.active.map((item) => ({
    id: item.hypothesis_id,
    description: item.description,
    status: item.status,
    verdict: item.verdict ?? null,
    summary: item.summary || "No summary",
    latestReasoning: item.latest_reasoning ?? [],
    reasoningCount: item.reasoning_count ?? 0,
    latestIteration: item.latest_iteration ?? null,
    latestReasoningAt: item.latest_reasoning_at ?? null
  })).sort(byRecency)
);

export const resolvedHypothesesView = derived([hypotheses], ([$hypotheses]) =>
  $hypotheses.resolved.map((item) => ({
    id: item.hypothesis_id,
    description: item.description,
    status: item.status,
    verdict: item.verdict ?? null,
    summary: item.summary || "No summary",
    latestReasoning: item.latest_reasoning ?? [],
    reasoningCount: item.reasoning_count ?? 0,
    latestIteration: item.latest_iteration ?? null,
    latestReasoningAt: item.latest_reasoning_at ?? null
  })).sort(byRecency)
);

export const openGapsView = derived([reportSections], ([$reportSections]) => {
  const rows = $reportSections.flatMap((section) =>
    section.gaps.map((gap) => ({
      sectionKey: section.section_key,
      sectionTitle: section.title,
      gap
    }))
  );
  return rows;
});

export const recentResolvedSummary = derived([hypotheses], ([$hypotheses]) => {
  const resolved = $hypotheses.resolved.slice(0, 3);
  return resolved.map((item) => `${formatVerdict(item.verdict)}: ${item.description}`);
});

export const verdictBreakdown = derived([hypotheses], ([$hypotheses]) => {
  let confirmed = 0;
  let refuted = 0;
  let inconclusive = 0;
  for (const h of $hypotheses.resolved) {
    if (h.verdict === "confirmed") confirmed++;
    else if (h.verdict === "refuted") refuted++;
    else if (h.verdict === "inconclusive") inconclusive++;
  }
  return {
    confirmed,
    refuted,
    inconclusive,
    active: $hypotheses.active.length
  };
});

export const topRules = derived([findings], ([$findings]) => {
  const counts = new Map<string, { accepted: number; title: string }>();
  for (const f of $findings) {
    if (f.status === "suppressed") continue;
    const key = f.rule_id ?? "unknown";
    const row = counts.get(key) ?? { accepted: 0, title: f.title };
    row.accepted++;
    row.title = f.title;
    counts.set(key, row);
  }
  return Array.from(counts.entries())
    .map(([ruleId, stats]) => ({ ruleId, ...stats }))
    .sort((a, b) => b.accepted - a.accepted)
    .slice(0, 8);
});

export const severityBreakdown = derived([findings], ([$findings]) => {
  const highAccepted = $findings.filter((f) => f.severity === "high" && f.status !== "suppressed").length;
  const highSuppressed = $findings.filter((f) => f.severity === "high" && f.status === "suppressed").length;
  const mediumAccepted = $findings.filter((f) => f.severity === "medium" && f.status !== "suppressed").length;
  const mediumSuppressed = $findings.filter((f) => f.severity === "medium" && f.status === "suppressed").length;
  const lowAccepted = $findings.filter((f) => f.severity === "low" && f.status !== "suppressed").length;
  const lowSuppressed = $findings.filter((f) => f.severity === "low" && f.status === "suppressed").length;
  return {
    highAccepted, highSuppressed,
    mediumAccepted, mediumSuppressed,
    lowAccepted, lowSuppressed
  };
});
