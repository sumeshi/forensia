---
section: 6_ioc
title: "侵害指標 (IOC)"
prompt: |
  以下の調査データを使って「侵害指標 (IOC)」セクションを記述してください。
  必ず含めること:
    1. 攻撃者が使用したIPアドレス（evidence_idで確認されたもののみ）
    2. 不審なプロセス名・実行ファイルパス
    3. 不審なサービス名・スケジュールタスク名
    4. 不審なアカウント名（攻撃者が作成したもの等）
    5. 不審なファイルパス（MFTタイムラインから確認されたもの）
  各IOCに必ず evidence_id または確認された日時・ホストを付記してください。
  推測でIOCを追加することは禁止です。
evidence_queries:
  - "SELECT DISTINCT src_ip, COUNT(*) AS count FROM evtx_events WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','127.0.0.1','::1','-') GROUP BY src_ip ORDER BY count DESC LIMIT 30"
  - "SELECT DISTINCT process_name, command_line, computer, evidence_id FROM evtx_events WHERE event_id IN (4688,4104) AND process_name IS NOT NULL ORDER BY timestamp LIMIT 30"
  - "SELECT DISTINCT service_name, computer, evidence_id FROM evtx_events WHERE event_id IN (4697,7045) AND service_name IS NOT NULL"
  - "SELECT file_path, si_created, si_modified, is_deleted, evidence_id FROM mft_entries WHERE (LOWER(file_path) LIKE '%temp%' OR LOWER(file_path) LIKE '%appdata%' OR LOWER(file_path) LIKE '%public%') AND si_created IS NOT NULL ORDER BY si_created DESC LIMIT 30"
---

# 侵害指標 (IOC)

## IPアドレス

| IPアドレス | 用途 | 確認日時 | 確認ホスト | evidence_id |
|---|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## プロセス / 実行ファイル

| プロセス名 / パス | コマンドライン（要約） | 確認ホスト | evidence_id |
|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |

---

## サービス / タスク名

| 名称 | 種別 | 確認ホスト | evidence_id |
|---|---|---|---|
| <!-- 記入 --> | service / task | <!-- 記入 --> | <!-- 記入 --> |

---

## 不審なファイル (MFT)

| パス | 作成日時 | 削除済み | evidence_id |
|---|---|---|---|
| <!-- 記入 --> | <!-- 記入 --> | yes / no | <!-- 記入 --> |

---

## 不審アカウント

| アカウント名 | 操作 | 作成者 | 日時 | evidence_id |
|---|---|---|---|---|
| <!-- 記入 --> | 作成/削除/グループ追加 | <!-- 記入 --> | <!-- 記入 --> | <!-- 記入 --> |
