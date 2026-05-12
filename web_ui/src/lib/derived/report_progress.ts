import { derived } from "svelte/store";

import { reportSections } from "../stores";

export const reportProgress = derived(reportSections, ($sections) => {
  const total = $sections.length;
  const approved = $sections.filter((section) => section.status === "approved").length;
  const stable = $sections.filter((section) => section.status === "stable").length;
  const draft = $sections.filter((section) => section.status === "draft").length;
  const gaps = $sections.reduce((sum, section) => sum + section.gap_count, 0);
  const writing = $sections.find((section) => section.is_writing)?.section_key ?? null;
  const percent = total === 0 ? 0 : Math.round((approved / total) * 100);
  return {
    total,
    approved,
    stable,
    draft,
    gaps,
    writing,
    percent,
    sections: $sections
  };
});
