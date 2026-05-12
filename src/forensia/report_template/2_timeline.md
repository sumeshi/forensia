---
section: 2_timeline
title: "攻撃タイムライン"
prompt: |
  以下の調査データを使って「攻撃タイムライン」セクションを記述してください。
  必ず含めること:
    1. 時系列の攻撃ステップ一覧（日時・ホスト・イベント・evidence_idを含む）
    2. 各ステップに ATT&CK フェーズを割り当てる（Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Lateral Movement / Collection / Exfiltration / Impact）
    3. ログが欠損している時間帯があれば明記する
  evidence_id が確認できたものだけ記述してください。推測は禁止。
  不明な箇所は「【調査不足: 〇〇の証拠なし】」と明示してください。
evidence_queries:
  - "SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id FROM evtx_events WHERE severity IN ('critical','high') ORDER BY timestamp LIMIT 50"
  - "SELECT timestamp, timestamp_type, file_path, description FROM mft_timeline ORDER BY timestamp LIMIT 30"
  - "SELECT title, severity, confidence, status FROM findings ORDER BY confidence DESC LIMIT 20"
  - "SELECT timestamp, computer, target_user, src_ip FROM evtx_events WHERE event_id IN (1102, 104) ORDER BY timestamp"
---

# 攻撃タイムライン

> ログ欠損期間: <!-- 確認されたログクリア日時や欠損がある場合に記入。なければ「確認されず」 -->

## タイムライン

| 日時 (UTC) | ホスト | フェーズ | イベント | evidence_id |
|---|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## フェーズ別サマリー

### Initial Access（初期侵入）
<!-- 記入。証拠がなければ「【調査不足】」 -->

### Lateral Movement（横展開）
<!-- 記入。証拠がなければ「【調査不足】」 -->

### Persistence（永続化）
<!-- 記入。証拠がなければ「【調査不足】」 -->

### Defense Evasion（防御回避）
<!-- 記入。証拠がなければ「【調査不足】」 -->

### Impact（影響）
<!-- 記入。証拠がなければ「【調査不足】」 -->
