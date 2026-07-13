---
type: knowledge
title: SMB・横展開イベント
description: 共有アクセス、管理共有、SMB経由のファイル操作・リモート操作の主要イベントID。
tags: [windows, eventlog, smb, share, lateral-movement]
timestamp: 2026-07-13
---
# SMB・横展開イベント

共有アクセス、管理共有（ADMIN$, C$）、SMB経由のリモート操作の痕跡を見る。
ランサムウェア事案などで悪用されることが多いため要チェック。

## Security.evtx

- 5140: ネットワーク共有オブジェクトにアクセス
- 5142 / 5143 / 5144: 共有の追加 / 変更 / 削除
- 5145: 共有オブジェクト詳細アクセス（対象ファイル名・アクセス種別が残る）

## Microsoft-Windows-SMBClient%4Connectivity.evtx（接続元側）

- 30800: サーバ名を解決できない
- 30803: ネットワーク接続失敗
- 30806: セッション再確立

## Microsoft-Windows-SMBServer%4Security.evtx（接続先側）

- 551: SMBセッション認証失敗
- 1006: 共有がアクセスを拒否
- 1009: 匿名アクセスを拒否

## 補足

- 5140/5145 は監査設定依存。無効な環境も多い。
- 接続先がWindows以外の可能性を示すもの: SMBClient%4Security.evtx の 32000 / 32002（SMBv1関連）。
