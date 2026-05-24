---
section: 6_ioc
title: "Indicators of Compromise (IOC)"
prompt: |
  Write the "Indicators of Compromise (IOC)" section using the investigation data below.
  You must include:
    1. IP addresses used by the attacker, but only when supported by evidence_id or directly observed context
    2. Suspicious process names and executable paths
    3. Suspicious service names and scheduled task names
    4. Suspicious account names, such as attacker-created accounts
    5. Suspicious file paths confirmed from the MFT timeline or MFT entries
  Every IOC must include either evidence_id or an observed timestamp and host.
  Do not add speculative IOCs.
evidence_queries:
  - "SELECT DISTINCT src_ip, COUNT(*) AS count FROM evtx_events WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','127.0.0.1','::1','-') GROUP BY src_ip ORDER BY count DESC LIMIT 30"
  - "SELECT DISTINCT process_name, command_line, computer, evidence_id FROM evtx_events WHERE event_id IN (4688,4104) AND process_name IS NOT NULL ORDER BY timestamp LIMIT 30"
  - "SELECT DISTINCT service_name, computer, evidence_id FROM evtx_events WHERE event_id IN (4697,7045) AND service_name IS NOT NULL"
  - "SELECT file_path, si_created, si_modified, is_deleted, evidence_id FROM mft_entries WHERE (LOWER(file_path) LIKE '%temp%' OR LOWER(file_path) LIKE '%appdata%' OR LOWER(file_path) LIKE '%public%') AND si_created IS NOT NULL ORDER BY si_created DESC LIMIT 30"
---

# Indicators of Compromise (IOC)

## IP Addresses

| IP Address | Purpose | Observed Time | Observed Host | evidence_id |
|---|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Processes / Executables

| Process Name / Path | Command Line Summary | Observed Host | evidence_id |
|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Services / Task Names

| Name | Type | Observed Host | evidence_id |
|---|---|---|---|
| <!-- fill --> | service / task | <!-- fill --> | <!-- fill --> |

---

## Suspicious Files (MFT)

| Path | Created Time | Deleted | evidence_id |
|---|---|---|---|
| <!-- fill --> | <!-- fill --> | yes / no | <!-- fill --> |

---

## Suspicious Accounts

| Account Name | Action | Actor | Timestamp | evidence_id |
|---|---|---|---|---|
| <!-- fill --> | created / deleted / group-added | <!-- fill --> | <!-- fill --> | <!-- fill --> |
