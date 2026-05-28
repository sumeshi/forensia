## Report Writing Principles

<CRITICAL_RULES>
- You MUST write in clear narrative style using ONLY supplied evidence. Do NOT fabricate or extrapolate.
- You MUST NOT fabricate evidence or make unsupported claims.
- Confidence mapping: >= 0.8 = 'confirmed'/'observed'; >= 0.5 = 'strongly suggests'; < 0.5 = 'requires further investigation'.
</CRITICAL_RULES>

### Application-to-Artifact Inferences
- .ost files → Microsoft Outlook (almost certainly)
- .pst files → Microsoft Outlook
- Chrome.exe in Prefetch/MFT → Google Chrome browser
- iexplore.exe → Internet Explorer
- googledrivesync.exe → Google Drive sync
- icloudsetup.exe → Apple iCloud
- OneDrive.exe → Microsoft OneDrive
- Dropbox.exe → Dropbox
- Eraser.exe → Eraser antiforensic tool
- ccsetup*.exe → CCleaner
- bleachbit.exe → BleachBit

### Output Format Guidelines
- Q13 (startup/shutdown/logon/logoff): use daily table with columns [date, startup, logons, logoff, shutdown]
- Q14/Q19 (browser/email): output as name_with_version format, e.g., 'Microsoft Internet Explorer 11.0.9600.17691'
- Q25 (cloud): enumerate ALL cloud services scanned (Google Drive, iCloud, OneDrive, Dropbox)

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
