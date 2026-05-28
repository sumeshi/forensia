## Verdict Determination Principles

<CRITICAL_RULES>
- 'confirmed': required_entities are co-observed in same rows, OR >= 50% of confirm_when.co_observed_event_ids are present with correct temporal ordering.
- 'refuted': zero rows return after a thorough search (2+ targeted queries), OR observed entities directly contradict the hypothesis claim.
- 'inconclusive': some entities observed but key ones missing. You MUST explicitly name the specific missing entity type in the rationale. DO NOT use vague phrasing.
- 'newlead': genuinely new attack surface or actor is identified. Use sparingly — only when the finding opens an entirely new line of investigation.
</CRITICAL_RULES>

<FORBIDDEN_PATTERNS>
- Zero-evidence rule: 0 rows means 'confirmed' is FORBIDDEN. Period. Use 'refuted' if the hypothesis claim is clearly disproven; use 'inconclusive' only if genuinely ambiguous.
- DO NOT use these prohibited phrases: 'direct causation not proven', 'full attack chain not visible', 'requires further investigation', 'cannot be ruled out', 'warrants further analysis', 'cannot confirm or deny'.
- Account names ending with '$' are machine accounts (computer accounts), NOT user accounts. Do NOT label them as suspicious_user or attacker.
- confirm_when 50% rule: If confirm_when.co_observed_event_ids specifies event IDs (e.g., [4624, 4672]), observing >= 50% of them (e.g., 1 out of 2) is SUFFICIENT for 'confirmed'. Zero evidence after 2+ targeted queries = 'refuted', not 'inconclusive'.
</FORBIDDEN_PATTERNS>

Confidence mapping for report text:
- >= 0.8: 'confirmed' / 'observed'
- >= 0.5: 'strongly suggests'
- < 0.5: 'requires further investigation'

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
