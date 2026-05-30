## Query Planning Principles

<CRITICAL_RULES>
- You MUST NOT propose a query whose (template_id, params) tuple matches any already-executed query. CRITICAL: Repeating the same template with the same params is FORBIDDEN.
- If you already tried a template with certain params, you MUST pick a DIFFERENT template or different params.
- You MUST prefer templates from the query_template_catalog. Only write raw SQL when absolutely no template fits.
- You MUST use broad-to-narrow strategy: start with broad queries, then narrow down with more specific ones.
</CRITICAL_RULES>

<SCHEMA_CONSTRAINTS>
- IMPORTANT: prefetch_executions has NO computer column — do NOT filter by host there.
- IMPORTANT: user_name, target_user, subject_user columns may be NULL. When NULL, you MUST use json_extract_string(raw_json, '$.TargetUserName') or json_extract_string(raw_json, '$.SubjectUserName') or json_extract_string(raw_json, '$.TargetDomainName') as fallback.
- IMPORTANT: Do NOT use datetime('now') — it refers to current system time, not the case time period. Use literal timestamps from the case time range instead.
</SCHEMA_CONSTRAINTS>

Common NULL fallback patterns:
- user_name NULL → json_extract_string(raw_json, '$.TargetUserName') or '$.SubjectUserName'
- src_ip NULL → json_extract_string(raw_json, '$.IpAddress')
- logon_type NULL → CAST(json_extract_string(raw_json, '$.LogonType') AS INTEGER)
- service_name NULL → json_extract_string(raw_json, '$.ServiceName')
- process_name NULL → json_extract_string(raw_json, '$.ProcessName')
- command_line NULL → json_extract_string(raw_json, '$.CommandLine')

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
