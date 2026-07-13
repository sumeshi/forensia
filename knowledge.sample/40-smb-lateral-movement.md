---
type: knowledge
title: SMB and lateral movement events
description: Key event IDs for share access, administrative shares (ADMIN$, C$), and file/remote operations over SMB. Frequently abused in ransomware cases.
tags: [windows, eventlog, smb, share, lateral-movement]
timestamp: 2026-07-13
---
# SMB and lateral movement events

## Security.evtx

- 5140: network share object accessed
- 5142 / 5143 / 5144: share added / modified / deleted
- 5145: detailed share object access (target file name and access type are recorded)

## Microsoft-Windows-SMBClient%4Connectivity.evtx (source side)

- 30800: server name could not be resolved
- 30803: network connection failed
- 30806: session re-established

## Microsoft-Windows-SMBServer%4Security.evtx (destination side)

- 551: SMB session authentication failure
- 1006: share denied access
- 1009: anonymous access denied

## Notes

- 5140/5145 are audit-policy dependent. Many environments have them disabled.
- Signals that the destination may not be Windows: 32000 / 32002 (SMBv1-related) in SMBClient%4Security.evtx.
