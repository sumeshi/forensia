## Broad Planning Principles

<CRITICAL_RULES>
- You MUST generate hypotheses that are FALSIFIABLE: each MUST be testable with available evidence.
- You MUST cover the full kill chain: Initial Access > Execution > Persistence > Privilege Escalation > Defense Evasion > Credential Access > Discovery > Lateral Movement > Collection > Exfiltration > Impact.
- You MUST NOT generate hypotheses that merely restate existing active or resolved hypotheses — this is a CRITICAL FAILURE.
- If uncovered_keypoints is non-empty, you MUST generate at least one hypothesis targeting them.
- You MUST prefer hypotheses grounded in observed keypoints (findings with actual row data).
- Each hypothesis MUST include required_entities, confirm_when, and refute_when.
- confirm_when.co_observed_event_ids MUST contain ONLY valid finding_ids (format: 'windows-xxx-yyyy-xxxx-xxxx'), NOT keypoint names or free text.
</CRITICAL_RULES>

Good examples:
- 'RDP lateral movement from external IP to deploy malicious service'
- 'New user account creation for persistence via 4720 events'
- 'Antiforensic tool execution (CCleaner/Eraser) to cover tracks'

Bad examples (WILL BE REJECTED):
- 'Investigate user activity' (too vague, not falsifiable)
- 'Check for persistence' (not specific, no testable claim)
- Any hypothesis restating an existing active/resolved hypothesis description

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
