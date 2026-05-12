import { derived } from "svelte/store";

import { findings, hypotheses, reportSections } from "../stores";
import { formatVerdict } from "../format";

export const whatWeKnow = derived([findings], ([$findings]) => {
  const accepted = $findings.filter((item) => item.status !== "suppressed").slice(0, 3);
  if (accepted.length === 0) return ["有意な Finding はまだありません。"];
  return accepted.map((item) => `${item.title} (${item.severity})`);
});

export const currentHypothesis = derived([hypotheses], ([$hypotheses]) => {
  const active = $hypotheses.active[0];
  if (!active) {
    return {
      title: "アクティブな仮説はありません",
      status: "待機",
      summary: "新しい仮説生成または gap 注入を待っています。"
    };
  }
  return {
    title: active.description,
    status: "調査中",
    summary: active.summary || "追加の証拠を探索中です。"
  };
});

export const whyItMatters = derived([findings, hypotheses], ([$findings, $hypotheses]) => {
  const highest = $findings.find((item) => item.status !== "suppressed");
  if (highest) {
    return `${highest.severity.toUpperCase()} severity の所見が残っており、侵害影響の特定が必要です。`;
  }
  if ($hypotheses.active.length > 0) {
    return "仮説は残っていますが、確定的な所見はまだ不足しています。";
  }
  return "現時点で重大な未解決所見は見えていません。";
});

export const nextAction = derived([reportSections, hypotheses], ([$reportSections, $hypotheses]) => {
  const writing = $reportSections.find((section) => section.is_writing);
  if (writing) return `${writing.title} を記入中です。`;
  const gapSection = $reportSections.find((section) => section.gap_count > 0);
  if (gapSection) return `${gapSection.title} の gap を埋めるため追加確認が必要です。`;
  const active = $hypotheses.active[0];
  if (active) return `次は仮説「${active.description}」の検証です。`;
  return "追加作業は見当たりません。";
});

export const activeHypothesesView = derived([hypotheses], ([$hypotheses]) =>
  $hypotheses.active.map((item) => ({
    id: item.hypothesis_id,
    description: item.description,
    status: item.status,
    summary: item.summary || "要約なし"
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
