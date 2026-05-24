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
keypoints:
  - top_keypoints
  - hosts_summary
  - hosts_logons
  - hosts_processes
  - hosts_services
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
