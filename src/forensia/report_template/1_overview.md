---
section: 1_overview
title: "調査概要"
prompt: |
  以下の調査データを使って「調査概要」セクションを記述してください。
  必ず含めること:
    1. インシデントの概要（何が、いつ、どこで起きたか。1〜3段落）
    2. 調査期間（ログの最古〜最新タイムスタンプ）
    3. 調査対象ホスト一覧（コンピュータ名と概要）
    4. 確認されたFirst Evidence of Compromise（FEC）の日時とホスト
  証拠がなく記述できない箇所は「【調査不足: 〇〇が確認できなかったため】」と明示してください。
  推測は禁止。証拠に基づいた記述のみ行ってください。
evidence_queries:
  - "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events"
  - "SELECT computer, COUNT(*) AS event_count FROM evtx_events WHERE computer IS NOT NULL GROUP BY computer ORDER BY event_count DESC LIMIT 20"
  - "SELECT finding_id, title, severity, confidence FROM findings WHERE severity IN ('critical','high') ORDER BY confidence DESC LIMIT 10"
---

# 調査概要

**調査期間**: <!-- ログの最古〜最新タイムスタンプ -->

**調査対象ホスト**:

| ホスト名 | 役割 | 侵害状況 |
|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## インシデントの概要

<!-- 何が起きたか。攻撃の全体像を証拠に基づいて1〜3段落で記述 -->

---

## 最初の侵害痕跡 (First Evidence of Compromise)

- **日時**: <!-- 記入 -->
- **ホスト**: <!-- 記入 -->
- **イベント**: <!-- 記入 -->
- **evidence_id**: <!-- 記入 -->
