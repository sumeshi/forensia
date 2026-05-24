---
section: 2_timeline
title: "Attack Timeline"
prompt: |
  Write the "Attack Timeline" section using the investigation data below.
  You must include:
    1. A chronological list of attack steps including timestamp, host, event, and evidence_id
    2. An ATT&CK phase for each step (Initial Access / Execution / Persistence / Privilege Escalation / Defense Evasion / Credential Access / Lateral Movement / Collection / Exfiltration / Impact)
    3. Any confirmed log gap or period of missing visibility
  Only describe steps that have confirmed evidence_id values. Do not speculate.
  If a required statement cannot be supported, explicitly write "[INSUFFICIENT EVIDENCE: reason]".
evidence_queries:
  - "SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id FROM evtx_events WHERE severity IN ('critical','high') ORDER BY timestamp LIMIT 50"
  - "SELECT timestamp, timestamp_type, file_path, description FROM mft_timeline ORDER BY timestamp LIMIT 30"
  - "SELECT title, severity, confidence, status FROM findings ORDER BY confidence DESC LIMIT 20"
  - "SELECT timestamp, computer, target_user, src_ip FROM evtx_events WHERE event_id IN (1102, 104) ORDER BY timestamp"
---

# Attack Timeline

> Log gap window: <!-- If confirmed log clearing or missing periods exist, describe them here. Otherwise write "Not observed." -->

## Timeline

| Timestamp (UTC) | Host | Phase | Event | evidence_id |
|---|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Phase Summary

### Initial Access
<!-- Fill in. If unsupported, write "[INSUFFICIENT EVIDENCE: reason]" -->

### Lateral Movement
<!-- Fill in. If unsupported, write "[INSUFFICIENT EVIDENCE: reason]" -->

### Persistence
<!-- Fill in. If unsupported, write "[INSUFFICIENT EVIDENCE: reason]" -->

### Defense Evasion
<!-- Fill in. If unsupported, write "[INSUFFICIENT EVIDENCE: reason]" -->

### Impact
<!-- Fill in. If unsupported, write "[INSUFFICIENT EVIDENCE: reason]" -->
