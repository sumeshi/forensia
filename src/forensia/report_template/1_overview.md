---
section: 1_overview
title: "Investigation Overview"
prompt: |
  Write the "Investigation Overview" section using the investigation data below.
  You must include:
    1. An incident summary describing what happened, when, and where, in 1 to 3 paragraphs
    2. The investigation time range from the earliest to the latest available log timestamp
    3. A list of in-scope hosts with a short description of each
    4. The confirmed First Evidence of Compromise (FEC), including timestamp and host
  If a required statement cannot be supported, explicitly write "[INSUFFICIENT EVIDENCE: reason]".
  Do not speculate. Write only evidence-based statements.
evidence_queries:
  - "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events"
  - "SELECT computer, COUNT(*) AS event_count FROM evtx_events WHERE computer IS NOT NULL GROUP BY computer ORDER BY event_count DESC LIMIT 20"
  - "SELECT finding_id, title, severity, confidence FROM findings WHERE severity IN ('critical','high') ORDER BY confidence DESC LIMIT 10"
---

# Investigation Overview

**Investigation Time Range**: <!-- Earliest to latest available log timestamp -->

**In-Scope Hosts**:

| Host | Role | Compromise Status |
|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Incident Summary

<!-- Describe what happened in 1 to 3 evidence-based paragraphs -->

---

## First Evidence of Compromise (FEC)

- **Timestamp**: <!-- fill -->
- **Host**: <!-- fill -->
- **Event**: <!-- fill -->
- **evidence_id**: <!-- fill -->
