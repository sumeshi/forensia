---
type: knowledge
title: RDP・リモートアクセスイベント
description: RDP接続の試行・認証・セッション開始・切断・再接続の主要イベントID。
tags: [windows, eventlog, rdp, terminal-services, remote-access, lateral-movement]
timestamp: 2026-07-13
---
# RDP・リモートアクセスイベント

Securityログが消されていても、RDP関連ログが残っていることは割とある。こちらから流れを追える場合がある。

## Security.evtx

- 4778: ターミナルサーバセッションに再接続
- 4779: ログオフせずにセッションを切断

## Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx

- 21: セッションログオン成功
- 22: シェル開始通知
- 23: セッションログオフ成功
- 24: セッション切断
- 25: セッション再接続成功

## Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx

- 261: リスナー RDP-Tcp で接続を受信
- 1148: セッション接続失敗
- 1149: ユーザ認証成功（これ単体でRDPログオン成功と断定してはいけない）

## Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx（接続元側）

- 1024: RDPクライアントがサーバへ接続試行（接続先が記録される。踏み台調査で有用）
- 1026: RDPクライアント切断

## System.evtx

- 9009: デスクトップウィンドウマネージャ終了（RDPセッション切断など）
