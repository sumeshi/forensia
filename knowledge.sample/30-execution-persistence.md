---
type: knowledge
title: プロセス実行・永続化イベント
description: プロセス作成、PowerShell、WMI、サービス、スケジュールタスク、アカウント操作の主要イベントID。
tags: [windows, eventlog, execution, powershell, wmi, service, scheduled-task, persistence, account]
timestamp: 2026-07-13
---
# プロセス実行・永続化イベント

## プロセス実行

- Security.evtx
  - 4688: プロセス作成 / 4689: プロセス終了

4688は「Audit Process Creation」有効時のみ記録。コマンドラインは別途「Include command line in process creation events」の有効化が必要。無効環境が多いので、記録されていれば儲けもの。

## PowerShell

設定依存だが、記録されていれば必ず見る。定期実行によるノイズに注意。

- Windows PowerShell.evtx
  - 400: エンジン開始 / 403: エンジン終了
- Microsoft-Windows-PowerShell%4Operational.evtx
  - 4103: モジュールログ
  - 4104: スクリプトブロックログ（実行内容そのものが残る。最重要）

## WMI

ノイズ多め。永続化（EventFilter/Consumer）に使われることがある。

- Microsoft-Windows-WMI-Activity%4Operational.evtx
  - 5857: WMI操作開始 / 5858: WMIクエリ失敗

## サービス変更

PsExec系ツール、永続化、EDR/AV停止、バックアップ製品停止の痕跡が残ることがある。

- Security.evtx
  - 4697: サービスインストール
- System.evtx
  - 7036: サービス開始/停止 / 7040: 開始種別変更 / 7045: サービスインストール

## スケジュールタスク

マルウェアの永続化・遅延実行の定番。タスク名、実行コマンド、作成者、作成時刻を見る。

- Security.evtx
  - 4698: 作成 / 4699: 削除 / 4700: 有効化 / 4701: 無効化 / 4702: 更新
- Microsoft-Windows-TaskScheduler%4Operational.evtx
  - 106: 登録 / 141: 削除 / 129: プロセス作成 / 100: 開始 / 102: 完了

## アカウント・グループ・ポリシー変更

長期侵害では不審なアカウントが追加されていることが多い（MITRE T1136）。

- Security.evtx
  - 4720: アカウント作成 / 4722: 有効化 / 4726: 削除
  - 4723 / 4724: パスワード変更・リセット試行
  - 4728 / 4732 / 4756: グループへのメンバー追加（特に管理者グループ）
  - 4719: 監査ポリシー変更 / 4740: ロックアウト
