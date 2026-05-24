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
keypoints:
  - top_keypoints
  - ioc_ips
  - ioc_processes
  - ioc_services
  - ioc_mft_paths
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
