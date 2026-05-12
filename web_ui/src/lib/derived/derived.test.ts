import { describe, expect, it } from "vitest";
import { get } from "svelte/store";

import { formatPhase, formatStatus, formatVerdict } from "../format";
import { currentTask } from "./ai_activity";
import { currentHypothesis, nextAction, whatWeKnow } from "./cockpit";
import { reportProgress } from "./report_progress";
import { findings, hypotheses, progress, reportSections } from "../stores";

describe("cockpit derived", () => {
  it("formats verdicts for humans", () => {
    expect(formatVerdict("inconclusive")).toBe("判断保留");
    expect(formatVerdict("confirmed")).toBe("確認済み");
  });

  it("formats phase and status labels", () => {
    expect(formatPhase("active")).toBe("調査中");
    expect(formatStatus("suppressed")).toBe("除外");
  });

  it("builds current ai task from progress", () => {
    progress.set({
      event_index: 1,
      stage: "investigate/report-section",
      summary: "[report] 1_overview writing...",
      payload: {},
      iteration: 2
    });
    expect(get(currentTask).stageLabel).toBe("報告書記入");
    expect(get(currentTask).iteration).toBe(2);
  });

  it("builds report progress counters", () => {
    reportSections.set([
      { section_key: "1", title: "A", body: "abc", confidence: 0.9, status: "approved", update_count: 3, gaps: [], gap_count: 0, is_writing: false, is_highlighted: false },
      { section_key: "2", title: "B", body: "", confidence: 0.4, status: "draft", update_count: 1, gaps: ["x"], gap_count: 1, is_writing: true, is_highlighted: false }
    ]);
    expect(get(reportProgress).approved).toBe(1);
    expect(get(reportProgress).draft).toBe(1);
    expect(get(reportProgress).gaps).toBe(1);
    expect(get(reportProgress).writing).toBe("2");
  });

  it("builds cockpit summaries from findings and hypotheses", () => {
    findings.set([
      { finding_id: "F1", title: "RDP logon", summary: "x", severity: "high", status: "accepted" },
      { finding_id: "F2", title: "Suppressed", summary: "y", severity: "low", status: "suppressed" }
    ]);
    hypotheses.set({
      active: [{ hypothesis_id: "H1", description: "Investigate lateral movement", status: "active", summary: "" }],
      resolved: []
    });
    reportSections.set([{ section_key: "7", title: "Gaps", body: "", confidence: 0.2, status: "draft", update_count: 1, gaps: ["Need more logs"], gap_count: 1, is_writing: false, is_highlighted: false }]);
    expect(get(whatWeKnow)[0]).toContain("RDP logon");
    expect(get(currentHypothesis).title).toContain("Investigate lateral movement");
    expect(get(nextAction)).toContain("Gaps");
  });
});
