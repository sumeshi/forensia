---
type: knowledge
title: Log sources to check first
description: The evtx files worth skimming (filtered by Provider/Channel) during triage, and how to treat Sysmon.
tags: [windows, eventlog, triage, sources, sysmon]
timestamp: 2026-07-13
---
# Log sources to check first

## Core evtx files

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
- For DCs/servers: Directory Service.evtx, DNS Server.evtx, Microsoft-Windows-DNSServer%4Audit.evtx, ActiveDirectoryWebService.evtx, DFS Replication.evtx

## Sysmon

If present, Sysmon plus logon events alone can carry much of the investigation (mainly 1: process creation, 3: network connection, 11: file creation, 22: DNS query).
However, most environments do not have it. Do not count on it.
