---
section: 7_gaps
title: "調査上の限界・不足事項"
prompt: |
  前のセクション（1〜6）で「【調査不足】」と記されたすべての箇所をリストアップし、
  「調査上の限界・不足事項」セクションを記述してください。
  各不足事項について以下を含めること:
    1. 何が不明か（具体的に）
    2. なぜ不明か（ログが存在しない / 期間外 / ログが消去された / 証拠が断片的 等）
    3. 追加調査で解明できるか、またその方法（追加のEvtxファイル取得・メモリフォレンジック等）
    4. この不足が調査結論に与える影響度（high / medium / low）
  さらに、現在の証拠から見て「追加で調査すべき仮説」を提案してください。
  これが次のPDCAサイクルの入力になります。
evidence_queries:
  - "SELECT COUNT(*) AS total_events, MIN(timestamp) AS first, MAX(timestamp) AS last FROM evtx_events"
  - "SELECT channel, COUNT(*) AS count FROM evtx_events GROUP BY channel ORDER BY count DESC"
  - "SELECT event_id, COUNT(*) AS count FROM evtx_events WHERE event_id IN (1102,104,4719) GROUP BY event_id"
---

# 調査上の限界・不足事項

## ログの欠損・信頼性

<!-- ログクリア(1102/104)や欠損期間があれば記述。「確認されず」も可 -->

## 未解明事項

| # | 不明な点 | 理由 | 影響度 | 追加調査の方法 |
|---|---|---|---|---|
| 1 | <!-- 記入 --> | <!-- 記入 --> | high/medium/low | <!-- 記入 --> |
| 2 | <!-- 記入 --> | <!-- 記入 --> | high/medium/low | <!-- 記入 --> |

---

## 次のPDCAサイクルで調査すべき仮説

> ここに記述された仮説は、`forensia investigate` の次回実行時に調査起点として使用されます。

1. <!-- 仮説1: 具体的に「〇〇ホストで〇〇が行われた可能性。確認SQL: SELECT ...」 -->
2. <!-- 仮説2 -->
3. <!-- 仮説3 -->
