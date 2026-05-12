---
section: 3_hosts
title: "侵害ホスト詳細"
prompt: |
  以下の調査データを使って「侵害ホスト詳細」セクションを記述してください。
  ホストごとにサブセクションを作成し、以下を含めること:
    1. 侵害の確度（confirmed / suspected / clean）とその根拠（evidence_id）
    2. そのホストで確認されたイベントの概要（ログオン・プロセス実行・永続化等）
    3. 攻撃者がそのホストで行った操作の推定（証拠に基づくもののみ）
    4. 送信元IP（攻撃者IPまたは前段ホスト）
  証拠のないホストは「侵害の証拠なし」と明記してください。
  推測は禁止。証拠に基づいた記述のみ。
evidence_queries:
  - "SELECT computer, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen FROM evtx_events WHERE event_id IN (4624,4625,4648,4688,4697,4698,5140,1102) GROUP BY computer ORDER BY events DESC LIMIT 20"
  - "SELECT computer, src_ip, target_user, logon_type, timestamp, evidence_id FROM evtx_events WHERE event_id = 4624 AND logon_type IN ('3','10','9') ORDER BY timestamp LIMIT 40"
  - "SELECT computer, process_name, command_line, target_user, timestamp, evidence_id FROM evtx_events WHERE event_id IN (4688,4104) ORDER BY timestamp LIMIT 30"
  - "SELECT computer, service_name, target_user, timestamp, evidence_id FROM evtx_events WHERE event_id IN (4697,7045,4698) ORDER BY timestamp"
---

# 侵害ホスト詳細

<!-- ホストごとにサブセクションを追加。侵害が確認されたホストを先に記述 -->

---

## ホスト: <!-- ホスト名 -->

**侵害確度**: <!-- confirmed / suspected / clean -->
**最初の侵害確認**: <!-- 日時 -->
**送信元IP（攻撃起点）**: <!-- 記入 -->

### 確認されたアクティビティ

| 日時 | イベント | 詳細 | evidence_id |
|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

### 攻撃者の推定行動

<!-- 証拠に基づいてそのホストで攻撃者が何をしたかを記述 -->

---

## ホスト: <!-- ホスト名（2台目） -->

**侵害確度**: <!-- confirmed / suspected / clean -->

<!-- 同様に記入 -->
