import { derived } from "svelte/store";

import { progress } from "../stores";
import { formatStage } from "../format";

function payloadRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

export const currentTask = derived(progress, ($progress) => {
  if (!$progress) {
    return {
      stageLabel: "待機",
      summary: "調査イベント待ちです",
      iteration: 0
    };
  }
  return {
    stageLabel: formatStage($progress.stage),
    summary: $progress.summary ?? "進捗更新",
    iteration: $progress.iteration ?? 0
  };
});

export const runningQuery = derived(progress, ($progress) => {
  if (!$progress) return null;
  const payload = payloadRecord($progress.payload);
  const queryId = typeof $progress.current_query === "string" ? $progress.current_query : null;
  const focusHypothesisId = typeof payload.focus_hypothesis_id === "string" ? payload.focus_hypothesis_id : null;
  return {
    queryId,
    focusHypothesisId,
    stage: $progress.stage ?? null
  };
});
