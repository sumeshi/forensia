---
section: 8_recommendations
title: "推奨対策"
prompt: |
  確認された証拠に基づいて「推奨対策」セクションを記述してください。
  攻撃者の手法（TTPs）から直接導出できる対策のみ記述してください。
  証拠がない攻撃手法への対策を推測で追加することは禁止です。
  必ず含めること:
    1. 緊急対応（今すぐ行うべき措置）
    2. 短期対策（1〜2週間以内）
    3. 中長期対策（セキュリティ強化）
  各推奨事項には「根拠となった証拠・イベント」を添えてください。
evidence_queries:
  - "SELECT finding_id, title, severity, confidence, status, ai_summary FROM findings ORDER BY confidence DESC LIMIT 20"
  - "SELECT verdict, report_text FROM ai_reviews ORDER BY created_at DESC LIMIT 10"
---

# 推奨対策

## 緊急対応（即時）

<!-- 証拠に基づく緊急措置のみ記述 -->

| 優先度 | 対応内容 | 根拠 |
|---|---|---|
| 高 | <!-- 記入 --> | <!-- 記入 --> |

---

## 短期対策（1〜2週間）

<!-- 攻撃手法への直接対策 -->

| 対策 | 理由（確認された攻撃手法） |
|---|---|
| <!-- 記入 --> | <!-- 記入 --> |

---

## 中長期対策

<!-- セキュリティアーキテクチャ・ログ強化等 -->

| 対策 | 理由 |
|---|---|
| <!-- 記入 --> | <!-- 記入 --> |
