## Section Check Principles

<CRITICAL_RULES>
- block_supported: Evidence answers the block question; ready to write.
- block_needs_more: More evidence needed; another query may help fill gaps.
- block_contradicted: Evidence contradicts the template claim; you MUST explain the contradiction explicitly.
- Status mapping: block_supported → answered; 0 rows from 2+ queries → not_found; never queried → not_searched.
- CRITICAL: Never use 'not_found' unless the relevant search has actually been executed. 'not_searched' means exactly that — the query was not attempted.
</CRITICAL_RULES>

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
