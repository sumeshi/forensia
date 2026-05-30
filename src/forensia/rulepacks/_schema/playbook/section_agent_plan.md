## Section Evidence Gathering Principles

<CRITICAL_RULES>
- You MUST prefer keypoint actions — they are pre-built queries for common report blocks.
- You MUST use template actions when a matching template exists and no keypoint covers the topic.
- You MUST write raw SQL only when no keypoint or template fits the block question.
- After 2 consecutive zero-row OR query_error results, the next action MUST be 'keypoint'. Do NOT retry SQL.
- After a query_error, do NOT retry SQL — switch to keypoint or template immediately.
</CRITICAL_RULES>

<SCHEMA_CONSTRAINTS>
- prefetch_executions has NO computer column — do NOT use computer in WHERE clause.
- user_name/target_user/subject_user may be NULL — use json_extract_string(raw_json, '$.TargetUserName') as fallback.
- Do NOT use datetime('now') — case time may be from a different year.
</SCHEMA_CONSTRAINTS>

### Fallback Strategy
- For benchmark/appendix blocks: avoid broad suffix-only LIKE filters like '%lnk%', '%document%' unless paired with a topic-specific positive predicate.
- Evidence chain fallback: when primary returns 0 rows, try keypoint action, then try a DIFFERENT keypoint from a different artifact family.

<!-- AUTO-FROM: event_ids.yaml -->
- Event 4720 (Account created) | query columns: subject_user, target_user | may claim: new account was created; account creation was observed | DO NOT claim: attacker-created; backdoor; privilege escalation
- Event 4732 (Member added to local group) | query columns: subject_user, member, target_group | may claim: account added to local group; group membership change was observed | DO NOT claim: privilege escalation; persistence
<!-- END-AUTO -->

<!-- AUTO-FROM: app_catalog.yaml -->
- CONSENT.EXE: uac_related — UAC consent dialog
- GOOGLEDRIVESYNC.EXE: cloud_sync — Google Drive sync client
- SCHTASKS.EXE: persistence_tool — Windows task scheduler CLI
- UNINST.EXE: uninstaller — Uninstaller launcher
<!-- END-AUTO -->
