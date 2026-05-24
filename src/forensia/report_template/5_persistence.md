---
section: 5_persistence
title: "Persistence and Execution"
prompt: |
  Write the "Persistence and Execution" section using the investigation data below.
  You must include:
    1. Confirmed service installation details for 4697 and 7045, including service name, executable path, and creating user
    2. Confirmed scheduled task creation or deletion details for 4698 and 4699
    3. Confirmed PowerShell and LOLBas execution details from 4688 and 4104
    4. Defender disablement (5001) or AV-related service control events (7040) when observed
    5. evidence_id values for every listed item
  If an item is not supported by evidence, explicitly say "Not observed."
evidence_queries:
  - "SELECT timestamp, computer, service_name, subject_user, message, evidence_id FROM evtx_events WHERE event_id IN (4697,7045) ORDER BY timestamp"
  - "SELECT timestamp, computer, subject_user, message, evidence_id FROM evtx_events WHERE event_id IN (4698,4699) ORDER BY timestamp"
  - "SELECT timestamp, computer, target_user, process_name, command_line, evidence_id FROM evtx_events WHERE event_id = 4688 AND (LOWER(process_name) LIKE '%powershell%' OR LOWER(process_name) LIKE '%pwsh%' OR LOWER(process_name) LIKE '%certutil%' OR LOWER(process_name) LIKE '%mshta%' OR LOWER(process_name) LIKE '%rundll32%' OR LOWER(process_name) LIKE '%wscript%' OR LOWER(process_name) LIKE '%cscript%') ORDER BY timestamp LIMIT 30"
  - "SELECT timestamp, computer, evidence_id, message FROM evtx_events WHERE event_id IN (5001,7040,1116) ORDER BY timestamp"
---

# Persistence and Execution

## Service Installation (4697 / 7045)

| Timestamp | Host | Service Name | Execution Path | Creating User | evidence_id |
|---|---|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

> If unsupported, write: "Not observed."

---

## Scheduled Tasks (4698 / 4699)

| Timestamp | Host | Action | Creating User | evidence_id |
|---|---|---|---|---|
| <!-- fill --> | <!-- fill --> | Created / Deleted | <!-- fill --> | <!-- fill --> |

> If unsupported, write: "Not observed."

---

## PowerShell / LOLBas Execution (4688 / 4104)

| Timestamp | Host | Process | Command Line | User | evidence_id |
|---|---|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Defensive Control Disablement

<!-- Describe confirmed 5001, 7040, and 1116 activity here. If not observed, write "Not observed." -->
