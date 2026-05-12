export function formatVerdict(value: string | null | undefined): string {
  if (value === "confirmed") return "確認済み";
  if (value === "refuted") return "棄却";
  if (value === "inconclusive") return "判断保留";
  if (value === "new_finding") return "新規所見";
  return "未判定";
}


export function formatPhase(value: string | null | undefined): string {
  if (value === "active") return "調査中";
  if (value === "confirmed") return "確認済み";
  if (value === "refuted") return "棄却済み";
  return "待機";
}


export function formatStatus(value: string | null | undefined): string {
  if (value === "suppressed") return "除外";
  if (value === "accepted") return "採用";
  if (value === "completed") return "完了";
  if (value === "running") return "実行中";
  return value ?? "-";
}


export function formatStage(value: string | null | undefined): string {
  if (!value) return "待機";
  const map: Record<string, string> = {
    investigate: "調査",
    "investigate/plan": "仮説計画",
    "investigate/hypothesis": "仮説追跡",
    "investigate/do": "照会実行",
    "investigate/check": "評価",
    "investigate/act": "更新",
    "investigate/report-section": "報告書記入",
    "investigate/report-section-done": "報告書更新",
    "investigate/report-cycle-done": "報告書サイクル完了",
    "investigate/llm": "推論",
    analyze: "ルール分析",
    normalize: "正規化",
    ingest: "取込"
  };
  return map[value] ?? value;
}

export function formatActionVerb(value: string | null | undefined): string {
  if (!value) return "待機中";
  const map: Record<string, string> = {
    investigate: "調査サイクルを進行中",
    "investigate/plan": "次に調べる仮説を計画中",
    "investigate/hypothesis": "仮説を追跡中",
    "investigate/do": "DuckDB に SQL を発行中",
    "investigate/check": "結果を AI が評価中",
    "investigate/act": "メモリと AI Review を更新中",
    "investigate/report-section": "報告書セクションを記入中",
    "investigate/report-section-done": "セクション完了",
    "investigate/report-cycle-done": "報告書サイクルを締めくくり中",
    "investigate/llm": "LLM が推論中",
    analyze: "ルールを実行中",
    normalize: "ログを正規化中",
    ingest: "ログを取込中"
  };
  return map[value] ?? value;
}

export function getPipelinePhase(value: string | null | undefined): { index: number; total: number; label: string } {
  if (!value) {
    return { index: 0, total: 4, label: "待機" };
  }
  if (value.startsWith("ingest")) {
    return { index: 1, total: 4, label: "取込" };
  }
  if (value.startsWith("normalize")) {
    return { index: 2, total: 4, label: "正規化" };
  }
  if (value.startsWith("analyze")) {
    return { index: 3, total: 4, label: "分析" };
  }
  if (value.startsWith("investigate")) {
    return { index: 4, total: 4, label: "調査" };
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
