---
type: knowledge
title: Process execution and persistence events
description: Key event IDs for process creation, PowerShell, WMI, services, scheduled tasks, and account manipulation.
tags: [windows, eventlog, execution, powershell, wmi, service, scheduled-task, persistence, account]
timestamp: 2026-07-13
---
# Process execution and persistence events

## Process execution

- Security.evtx
  - 4688: process creation / 4689: process termination

4688 is recorded only when "Audit Process Creation" is enabled. Command lines additionally require "Include command line in process creation events". Many environments have this disabled, so treat its presence as a bonus.

## PowerShell

Configuration-dependent, but always check it when recorded. Watch out for noise from scheduled executions.

- Windows PowerShell.evtx
  - 400: engine started / 403: engine stopped
- Microsoft-Windows-PowerShell%4Operational.evtx
  - 4103: module logging
  - 4104: script block logging (records the executed content itself; the most important)

## WMI

Noisy. Sometimes used for persistence (EventFilter/Consumer).

- Microsoft-Windows-WMI-Activity%4Operational.evtx
  - 5857: WMI operation started / 5858: WMI query failed

## Service changes

May hold traces of PsExec-style tools, persistence, EDR/AV shutdown, and backup product shutdown.

- Security.evtx
  - 4697: service installed
- System.evtx
  - 7036: service start/stop / 7040: start type changed / 7045: service installed

## Scheduled tasks

A staple for malware persistence and delayed execution. Check task name, command, author, and creation time.

- Security.evtx
  - 4698: created / 4699: deleted / 4700: enabled / 4701: disabled / 4702: updated
- Microsoft-Windows-TaskScheduler%4Operational.evtx
  - 106: registered / 141: deleted / 129: process created / 100: started / 102: completed

## Account, group, and policy changes

In long-term compromises a suspicious account has often been added (MITRE T1136).

- Security.evtx
  - 4720: account created / 4722: enabled / 4726: deleted
  - 4723 / 4724: password change / reset attempts
  - 4728 / 4732 / 4756: member added to a group (especially administrator groups)
  - 4719: audit policy changed / 4740: account locked out
