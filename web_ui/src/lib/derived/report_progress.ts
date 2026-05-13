import { derived } from "svelte/store";

import { reportSections } from "../stores";

export const reportProgress = derived(reportSections, ($sections) => {
  const total = $sections.length;
  const humanReviewed = $sections.filter((section) => section.status === "human_reviewed").length;
  const aiExhausted = $sections.filter((section) => section.status === "ai_exhausted").length;
  const stable = $sections.filter((section) => section.status === "stable").length;
  const draft = $sections.filter((section) => section.status === "draft").length;
  const gaps = $sections.reduce((sum, section) => sum + section.gap_count, 0);
  const writing = $sections.find((section) => section.is_writing)?.section_key ?? null;
  const percent = total === 0 ? 0 : Math.round((humanReviewed / total) * 100);
  return {
    total,
    humanReviewed,
    aiExhausted,
    stable,
    draft,
    gaps,
    writing,
    percent,
    sections: $sections
  };
});
