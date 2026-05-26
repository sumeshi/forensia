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

export const activeHypothesesView = derived([hypotheses], ([$hypotheses]) =>
  $hypotheses.active.map((item) => ({
    id: item.hypothesis_id,
    description: item.description,
    status: item.status,
    summary: item.summary || "No summary",
    latestReasoning: item.latest_reasoning ?? [],
    reasoningCount: item.reasoning_count ?? 0,
    latestIteration: item.latest_iteration ?? null,
    latestReasoningAt: item.latest_reasoning_at ?? null
  }))
);

export const openGapsView = derived([reportSections], ([$reportSections]) => {
  const rows = $reportSections.flatMap((section) =>
    section.gaps.map((gap) => ({
      sectionKey: section.section_key,
      sectionTitle: section.title,
      gap
    }))
  );
  return rows.slice(0, 8);
});

export const recentResolvedSummary = derived([hypotheses], ([$hypotheses]) => {
  const resolved = $hypotheses.resolved.slice(0, 3);
  return resolved.map((item) => `${formatVerdict(item.verdict)}: ${item.description}`);
});
