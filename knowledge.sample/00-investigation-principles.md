---
type: knowledge
title: Event log investigation principles
description: General principles for Windows event log investigations — assumptions, goal setting, and how to scope the work.
tags: [windows, eventlog, methodology, principles]
timestamp: 2026-07-13
---
# Event log investigation principles

## Assumptions

- Event logs only show what survived. Many events are not recorded by default (audit-policy dependent), old events are overwritten depending on rotation settings, and an intruder may have deleted logs.
- The Security log rotates quickly. In some cases only a few hours remain (e.g. flooded with failed logons).
- Do not casually conclude that missing logs mean "deleted by the intruder". Check rotation settings and retention first.

## Clarify the goal

You cannot investigate logs without knowing what you are trying to confirm. Break the investigation goal down:

- Did a compromise occur? (detection)
- Where did the intruder get in? (initial access)
- How did it spread? (lateral movement / persistence)
- What was done? (activity)
- What was affected? (impact)
- Why was it possible? (root cause)

If the question is "was data exfiltrated?", no log will say "data was exfiltrated". Look for the behaviors that lead to exfiltration: suspicious logons, file access, outbound connections, removable media, admin share access, suspicious tool execution.

## Scope

Cut the scope first. If it turns out too narrow, widen it based on what you find.

- Which hosts (servers / clients)
- Which period (the suspected compromise window)
- Which logs (Security / System / PowerShell / TaskScheduler, etc.)
- Which users (administrators / regular users / service accounts)
- Which event IDs

## How to proceed

- Do not try to collect everything; find a foothold. Once you have a suspicious starting event, follow the timeline around it.
- At the start, list which logs exist and what period each covers. Before reporting "no suspicious logons", always check how far back the Security log goes.
- Knowing how the machine is used in normal times, and which events it records, is the first step in cutting noise.
