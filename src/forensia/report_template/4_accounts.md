---
section: 4_accounts
title: "侵害アカウント・認証"
prompt: |
  以下の調査データを使って「侵害アカウント・認証」セクションを記述してください。
  必ず含めること:
    1. 侵害が確認または疑われるアカウント一覧（根拠のevidence_idを含む）
    2. 各アカウントの侵害手法（Pass-the-Hash / ブルートフォース / 資格情報窃取 等）
    3. 不審なログオン一覧（時刻・送信元IP・ターゲットホスト・LogonType）
    4. 攻撃者が使用したLogonTypeとその意味（3=ネットワーク認証、10=RDP等）
    5. 特権アカウントの悪用状況（4672: 特権アサイン）
  LogonType=3 は一般的にも発生するため、管理共有アクセス・業務時間外・外部IP等の
  追加条件と組み合わせて「不審」と判断したものだけを記述してください。
evidence_queries:
  - "SELECT target_user, src_ip, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last FROM evtx_events WHERE event_id = 4624 AND logon_type IN ('3','9','10') AND target_user NOT LIKE '%$' GROUP BY target_user, src_ip, computer, logon_type ORDER BY count DESC LIMIT 30"
  - "SELECT src_ip, target_user, computer, COUNT(*) AS fail_count FROM evtx_events WHERE event_id = 4625 GROUP BY src_ip, target_user, computer HAVING COUNT(*) >= 5 ORDER BY fail_count DESC LIMIT 20"
  - "SELECT timestamp, computer, target_user, subject_user, evidence_id FROM evtx_events WHERE event_id IN (4720,4726,4732,4728,4724) ORDER BY timestamp"
  - "SELECT timestamp, computer, target_user, subject_user, evidence_id FROM evtx_events WHERE event_id = 4648 ORDER BY timestamp LIMIT 20"
---

# 侵害アカウント・認証

## 侵害アカウント一覧

| アカウント | 侵害手法 | 初回確認日時 | 根拠 (evidence_id) |
|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## 不審なログオン詳細

| 日時 | 送信元IP | ターゲットホスト | アカウント | LogonType | 不審な理由 |
|---|---|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## ブルートフォース / パスワードスプレー

<!-- 4625の集計から確認されたブルートフォース攻撃の記述。なければ「確認されず」 -->

---

## アカウント操作（作成・削除・グループ追加）

<!-- 4720/4726/4732/4728/4724 の確認内容。なければ「確認されず」 -->
