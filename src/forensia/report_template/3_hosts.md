---
section: 3_hosts
title: "Compromised Host Details"
prompt: |
  Write the "Compromised Host Details" section using the investigation data below.
  Create a subsection for each host and include:
    1. Compromise confidence as confirmed / suspected / clean, with supporting evidence_id values
    2. A summary of notable observed activity on that host such as logons, process execution, or persistence
    3. The attacker actions inferred for that host, but only when supported by evidence
    4. The source IP associated with the attacker or previous pivot host
  If a host has no evidence of compromise, explicitly say "No evidence of compromise observed."
  Do not speculate. Write only evidence-based statements.
evidence_queries:
  - "SELECT computer, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen FROM evtx_events WHERE event_id IN (4624,4625,4648,4688,4697,4698,5140,1102) GROUP BY computer ORDER BY events DESC LIMIT 20"
  - "SELECT computer, src_ip, target_user, logon_type, timestamp, evidence_id FROM evtx_events WHERE event_id = 4624 AND logon_type IN ('3','10','9') ORDER BY timestamp LIMIT 40"
  - "SELECT computer, process_name, command_line, target_user, timestamp, evidence_id FROM evtx_events WHERE event_id IN (4688,4104) ORDER BY timestamp LIMIT 30"
  - "SELECT computer, service_name, target_user, timestamp, evidence_id FROM evtx_events WHERE event_id IN (4697,7045,4698) ORDER BY timestamp"
---

# Compromised Host Details

<!-- Add one subsection per host. Describe confirmed compromised hosts first. -->

---

## Host: <!-- host name -->

**Compromise Confidence**: <!-- confirmed / suspected / clean -->
**First Confirmed Evidence**: <!-- timestamp -->
**Source IP / Pivot Origin**: <!-- fill -->

### Observed Activity

| Timestamp | Event | Details | evidence_id |
|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

### Inferred Attacker Actions

<!-- Describe what the attacker did on this host, based only on evidence -->

---

## Host: <!-- host name (second host if applicable) -->

**Compromise Confidence**: <!-- confirmed / suspected / clean -->

<!-- Repeat the same structure as needed -->
