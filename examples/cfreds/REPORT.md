---
instructions: |
  State the investigation objective and scope, and describe activity supported by evidence.
  Distinguish observations from interpretations. Include evidence references and material limitations for each claim.
  Do not assume compromise or impact. Keep unresolved matters explicitly unresolved.
  Explain timestamp meanings and timezones, and distinguish recommended work from completed work.
---
# Investigation overview and scope

## Objective and scope
<!-- mode: narrative -->
<!-- evidence_keypoints: overview_top_findings, resolved_hypotheses_with_evidence, overview_hosts, overview_event_range -->
<!-- Describe the requested objective, evidence examined, time range, and exclusions. Do not infer unspecified details. -->

## Evidence ingestion and coverage
<!-- mode: table; builder: overview_evidence_scope -->

## Key findings
<!-- mode: table; builder: overview_key_findings -->

# Timeline

## Time basis and scope
<!-- mode: narrative -->
<!-- evidence_keypoints: timeline_high_signal_events, timeline_system_events, timeline_log_clearing, timeline_case_assembled -->
<!-- Distinguish observed timestamps from inferred ordering. Explain the timezone evidence, observed period, and missing or conflicting timestamps. -->

## Observed events
<!-- mode: table; builder: timeline_chronological -->

# Analysis

## Evidence and interpretation
<!-- mode: narrative -->
<!-- evidence_keypoints: host_execution_activity, host_persistence_activity, account_logon_patterns, ioc_source_ips -->
<!-- Show the evidence for each finding and the related systems, accounts, and artifacts. Separate direct observations from interpretations and record alternative explanations that remain possible. -->

## Systems and accounts
<!-- mode: table; builder: technical_accounts -->

## Execution records
<!-- mode: table; builder: technical_execution -->

## Network records
<!-- mode: table; builder: technical_network -->

## Related files
<!-- mode: table; builder: technical_files -->

# Limitations and unresolved questions

## Scope and limitations
<!-- mode: narrative -->
<!-- evidence_keypoints: unresolved_hypotheses_summary, gaps_event_coverage, gaps_channel_coverage -->
<!-- Explain which conclusions are limited by missing, incomplete, or conflicting evidence. Insufficient evidence does not establish that an activity was absent. -->

## Unresolved hypotheses
<!-- mode: table; builder: gaps_unresolved -->

## Evidence gaps
<!-- mode: table; builder: gaps_evidence -->

# Follow-up work

## Proposed verification steps
<!-- mode: narrative -->
<!-- evidence_keypoints: recommendations_findings, recommendations_recent_reviews -->
<!-- Propose concrete, testable next steps for the findings and unresolved questions. Explain what each step would verify. -->

## Action plan
<!-- mode: table; builder: recommendations_action_plan -->

# CFReDS investigation questions

For each question, show the answer, evidence references, scope, and remaining limitations.
Explicitly identify partial lists and inferred candidates.
Use the timezone established from evidence for the local time window in Q13. If it is unknown, do not claim that the time constraint has been met.
Displayed answer statuses are not benchmark scores.

## Q6. What is the computer name?
<!-- question -->
<!-- answer_id: Q6 -->

## Q8. Who was the last user to log on to the PC?
<!-- question -->
<!-- answer_id: Q8 -->

## Q9. When was the last recorded shutdown date/time?
<!-- question -->
<!-- answer_id: Q9 -->

## Q12. List application execution logs.
<!-- question -->
<!-- answer_id: Q12 -->

- executable path
- execution time
- execution count

## Q13. List all traces related to system startup/shutdown and user logon/logoff.
<!-- question -->
<!-- answer_id: Q13 -->

- Consider only the time range between 09:00 and 18:00 in the timezone identified above.

## Q14. What web browsers were used?
<!-- question -->
<!-- answer_id: Q14 -->

## Q19. What application was used for e-mail communication?
<!-- question -->
<!-- answer_id: Q19 -->

## Q20. Where is the e-mail file located?
<!-- question -->
<!-- answer_id: Q20 -->

## Q24. Identify all traces related to renaming files on the Windows Desktop.
<!-- question -->
<!-- answer_id: Q24 -->

- Consider only the date range between 2015-03-23 and 2015-03-24.
- Hint: the parent directories of renamed files were deleted and their MFT entries were also overwritten, so full paths may not be recoverable.

## Q25. Find traces related to cloud services on the PC.
<!-- question -->
<!-- answer_id: Q25 -->

- service name
- log files

## Q28. Identify all timestamps related to a resignation file on the Windows Desktop.
<!-- question -->
<!-- answer_id: Q28 -->

- Hint: the resignation file is a DOCX file in the NTFS file system.

## Q45. What actions were performed for anti-forensics on the PC on the last day, 2015-03-25?
<!-- question -->
<!-- answer_id: Q45 -->
