import { derived } from "svelte/store";

import { findingAggregates, findings, hypotheses, reportSections } from "../stores";
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
    latestReasoningAt: item.latest_reasoning_at ?? null,
    blockedReason: item.blocked_reason ?? null,
    sufficiencyStatus: item.sufficiency_status ?? null,
    sufficiencyScore: item.sufficiency_score ?? null,
    sufficiencyReason: item.sufficiency_reason ?? null,
    humanReviewRequired: item.human_review_required ?? false
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
    latestReasoningAt: item.latest_reasoning_at ?? null,
    blockedReason: item.blocked_reason ?? null,
    sufficiencyStatus: item.sufficiency_status ?? null,
    sufficiencyScore: item.sufficiency_score ?? null,
    sufficiencyReason: item.sufficiency_reason ?? null,
    humanReviewRequired: item.human_review_required ?? false
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
  // Canonical status taxonomy (T-51.2): count every hypothesis by its durable
  // `status` rather than inferring from the `verdict` field. The `inconclusive`
  // key is retained for backward-compatible UI but is now derived from status
  // too (legacy verdict-based UI may still reference it).
  const counts: Record<string, number> = {
    active: 0,
    confirmed: 0,
    refuted: 0,
    untestable: 0,
    needs_review: 0,
    deferred: 0,
    blocked: 0,
    inconclusive: 0
  };
  for (const h of [...$hypotheses.active, ...$hypotheses.resolved]) {
    const status = h.status ?? "unknown";
    if (status in counts) counts[status] += 1;
    if (h.verdict === "inconclusive") counts.inconclusive += 1;
  }
  return counts;
});

export const topRules = derived([findings, findingAggregates], ([$findings, $aggregates]) => {
  // Prefer authoritative server-side aggregates over the first-N-row sample
  // (T-51.3). Fall back to local derivation only when aggregates are missing.
  if ($aggregates && Array.isArray($aggregates.top_rules) && $aggregates.top_rules.length > 0) {
    return $aggregates.top_rules.map((rule) => ({
      ruleId: String(rule.rule_id ?? "unknown"),
      title: String(rule.title ?? ""),
      accepted: Number(rule.count ?? 0)
    }));
  }
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

export const severityBreakdown = derived([findings, findingAggregates], ([$findings, $aggregates]) => {
  // Prefer authoritative server-side severity counts (T-51.3). The backend
  // aggregates count every finding (not a sample), so local derivation is only
  // a fallback.
  if ($aggregates && $aggregates.severity_counts) {
    return {
      highAccepted: $aggregates.severity_counts.high ?? 0,
      highSuppressed: 0,
      mediumAccepted: $aggregates.severity_counts.medium ?? 0,
      mediumSuppressed: 0,
      lowAccepted: $aggregates.severity_counts.low ?? 0,
      lowSuppressed: 0
    };
  }
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
