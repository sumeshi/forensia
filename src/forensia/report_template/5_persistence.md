---
section: 5_persistence
title: "永続化・実行"
prompt: |
  以下の調査データを使って「永続化・実行」セクションを記述してください。
  必ず含めること:
    1. 確認されたサービスインストール（4697/7045）の詳細（サービス名・実行ファイルパス・作成ユーザ）
    2. スケジュールタスクの作成・削除（4698/4699）の詳細
    3. PowerShellおよびLOLBas系ツールの実行（4688/4104）の詳細
    4. Defenderの無効化（5001）やAV関連サービスの停止（7040）が確認された場合
    5. 各項目に evidence_id を必ず含める
  証拠がない項目は「確認されず」と明記してください。
evidence_queries:
  - "SELECT timestamp, computer, service_name, subject_user, message, evidence_id FROM evtx_events WHERE event_id IN (4697,7045) ORDER BY timestamp"
  - "SELECT timestamp, computer, subject_user, message, evidence_id FROM evtx_events WHERE event_id IN (4698,4699) ORDER BY timestamp"
  - "SELECT timestamp, computer, target_user, process_name, command_line, evidence_id FROM evtx_events WHERE event_id = 4688 AND (LOWER(process_name) LIKE '%powershell%' OR LOWER(process_name) LIKE '%pwsh%' OR LOWER(process_name) LIKE '%certutil%' OR LOWER(process_name) LIKE '%mshta%' OR LOWER(process_name) LIKE '%rundll32%' OR LOWER(process_name) LIKE '%wscript%' OR LOWER(process_name) LIKE '%cscript%') ORDER BY timestamp LIMIT 30"
  - "SELECT timestamp, computer, evidence_id, message FROM evtx_events WHERE event_id IN (5001,7040,1116) ORDER BY timestamp"
---

# 永続化・実行

## サービスインストール (4697 / 7045)

| 日時 | ホスト | サービス名 | 実行パス | 作成ユーザ | evidence_id |
|---|---|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

> 確認されない場合:「確認されず」

---

## スケジュールタスク (4698 / 4699)

| 日時 | ホスト | 操作 | 作成ユーザ | evidence_id |
|---|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | 作成/削除 | <!-- 記入 --> | <!-- 記入 --> |

> 確認されない場合:「確認されず」

---

## PowerShell / LOLBas 実行 (4688 / 4104)

| 日時 | ホスト | プロセス | コマンドライン | ユーザ | evidence_id |
|---|---|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## 防御機能の無効化

<!-- 5001(Defenderリアルタイム保護無効)・7040(サービス停止)・1116(マルウェア検知)の確認内容。なければ「確認されず」 -->
