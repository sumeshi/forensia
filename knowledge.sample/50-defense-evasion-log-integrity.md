---
type: knowledge
title: Defense evasion and log integrity events
description: Key event IDs and interpretation for Defender detections/disabling, log clearing, log rotation, and time/power events.
tags: [windows, eventlog, defender, log-tampering, anti-forensics, log-rotation, integrity]
timestamp: 2026-07-13
---
# Defense evasion and log integrity events

## Microsoft Defender

Check detection names, target paths, actions taken, and when protection was turned off.
Cases where "it was detected but executed anyway without removal or quarantine" are not rare. The evtx file name can differ by environment.

- Microsoft-Windows-Windows Defender%4Operational.evtx
  - 1116: malware detected
  - 1117: action taken against a threat
  - 5001: real-time protection disabled

## Log clearing and trace removal

- Security.evtx
  - 1102: Security log cleared
  - 1100: Event Log service shutdown
  - 1101: audit events dropped
- System.evtx
  - 104: other log cleared

## Log rotation

Use this to explain missing logs. Each channel has a maximum size and a when-full behavior.

- "Overwrite as needed": FIFO reuse of the oldest area. Old RecordIDs appear to be missing. Do not confuse this with deletion by an intruder.
- "Archive when full": event 1105 is recorded in the Security log.
- "Do not overwrite": nothing is recorded once full. Event 1104 is recorded in the Security log.

- Security.evtx
  - 1104: security log is full
  - 1105: event log was automatically backed up

## Time, power, and reboot

Check the log's clock settings and mismatches between power state and other traces. If something is recorded at a time when the machine should have been off, one of the two is wrong.

- Security.evtx
  - 4616: system time was changed
- System.evtx
  - 12: OS started / 13: shutdown started
  - 41: reboot without clean shutdown
  - 1074: shutdown/restart initiated by a process or user
  - 6005 / 6006: Event Log service started / stopped
  - 6008: previous shutdown was unexpected
