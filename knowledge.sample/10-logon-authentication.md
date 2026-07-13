---
type: knowledge
title: ログオン・認証イベント
description: ログオン成功/失敗、LogonType、Kerberos/NTLM認証の主要イベントIDと解釈。
tags: [windows, eventlog, logon, authentication, kerberos, ntlm, lateral-movement]
timestamp: 2026-07-13
---
# ログオン・認証イベント

誰が、いつ、どこから、どの端末へログオンしたのか（横展開）を見る。
記録されるイベントがログオン元・ログオン先どちらのものかを常に意識する。

## Security.evtx

- 4624: ログオン成功
- 4625: ログオン失敗
- 4634 / 4647: ログオフ
- 4648: 明示的な資格情報を使用したログオン（runas等）
- 4672: 新しいログオンに特権が割り当てられた（管理者相当ログオンの目印）

## LogonType（4624/4625）

基本は 3(Network), 10(RemoteInteractive) を中心に、9(NewCredentials), 12(CachedRemoteInteractive) を補助的に見る。

- 2: Interactive。コンソールログオン、RUNAS、KVMなど。
- 3: Network。共有アクセス、WinRM、PsExec、IIS統合認証など。原則として再利用可能な資格情報は宛先に残らない。
- 4: Batch。スケジュールタスクなど。
- 5: Service。サービス起動。資格情報がLSAセッションに残り得る。
- 7: Unlock。ロック解除。
- 8: NetworkCleartext。IIS Basic認証、CredSSP経由WinRMなど。資格情報窃取リスクが高い。
- 9: NewCredentials。`RUNAS /NETWORK` 等。ネットワーク接続時のみ別資格情報を使用。
- 10: RemoteInteractive。RDP。資格情報が宛先LSAに残るため、侵害端末への特権RDPは危険。
- 11: CachedInteractive。キャッシュ資格情報での対話ログオン。DC認証とは限らない。
- 12: CachedRemoteInteractive。RDPのキャッシュ版。

## ログオン失敗の解釈（4625）

ログオンエラーコード（SubStatus）で失敗理由がわかる（ユーザ名が存在しない / パスワード誤り 等）。
攻撃者がその時点でどの程度の情報を持っていたかの推定に使える。
一発でログオン成功しているなら、事前に資格情報をダンプ済み、または使い回しの可能性がある。

## Kerberos / NTLM（DC上で見る）

端末単体の調査では基本見なくてよい。DCがある場合に、どのアカウントがどのサービスに認証したかを見る。

- Security.evtx
  - 4768: TGT要求 / 4769: サービスチケット要求 / 4771: 事前認証失敗
  - 4776: NTLM認証試行
- Microsoft-Windows-NTLM%4Operational.evtx
  - 4020-4023: クライアント/サーバのNTLM認証試行（Win11 24H2以降で拡張）
