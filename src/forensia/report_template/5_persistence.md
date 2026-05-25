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
    6. Distinguish suspicious, benign-known, and unknown service creation rather than treating every service as persistence
    7. Do not classify GOOGLEDRIVESYNC.EXE as a browser
    8. Classify SCHTASKS.EXE as a potential persistence tool, UNINST.EXE as an uninstaller, and CONSENT.EXE as a UAC-related process unless stronger evidence says otherwise
    9. If a conclusion is based only on correlation, label it as hypothesis or needs review, not confirmed persistence
  If an item is not supported by evidence, explicitly say "Not observed."
keypoints:
  - top_keypoints
  - persistence_services
  - persistence_tasks
  - persistence_lolbas
  - persistence_defender
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

## Service / Tool Triage

- **Suspicious**: <!-- fill or "Not observed" -->
- **Benign-Known**: <!-- fill or "Not observed" -->
- **Unknown / Needs Review**: <!-- fill or "Not observed" -->

---

## Defensive Control Disablement

<!-- Describe confirmed 5001, 7040, and 1116 activity here. If not observed, write "Not observed." -->
