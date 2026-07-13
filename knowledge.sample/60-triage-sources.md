---
type: knowledge
title: 優先して見るべきログソース
description: トリアージ時にProvider/Channelで絞ってパラ読みすべきevtxファイルの一覧とSysmonの扱い。
tags: [windows, eventlog, triage, sources, sysmon]
timestamp: 2026-07-13
---
# 優先して見るべきログソース

何もアテがないときに、Provider/Channelで件数を絞ってパラ読みする際の中心。

- Security.evtx / System.evtx / Application.evtx / Setup.evtx
- Windows PowerShell.evtx
- Microsoft-Windows-PowerShell%4Operational.evtx
- Microsoft-Windows-TaskScheduler%4Operational.evtx
- Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
- Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
- Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
- Microsoft-Windows-SMBServer%4Security.evtx / %4Operational.evtx
- Microsoft-Windows-SmbClient%4Connectivity.evtx
- Microsoft-Windows-NTLM%4Operational.evtx
- Microsoft-Windows-WinRM%4Operational.evtx
- Microsoft-Windows-WMI-Activity%4Operational.evtx
- Microsoft-Windows-Windows Defender%4Operational.evtx
- Microsoft-Windows-Bits-Client%4Operational.evtx
- Microsoft-Windows-AppLocker%4* (EXE and DLL / MSI and Script)
- Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
- Microsoft-Windows-Sysmon%4Operational.evtx
- OpenSSH%4Admin.evtx / OpenSSH%4Operational.evtx
- DC/サーバの場合: Directory Service.evtx, DNS Server.evtx, Microsoft-Windows-DNSServer%4Audit.evtx, ActiveDirectoryWebService.evtx, DFS Replication.evtx

## Sysmon

入っていれば、Sysmonとログオンイベントだけでかなりの調査ができる（1: プロセス作成, 3: ネットワーク接続, 11: ファイル作成, 22: DNSクエリ あたりが中心）。
ただし、ほとんどの環境では入っていない。期待しないこと。
