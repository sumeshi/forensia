---
type: knowledge
title: Logon and authentication events
description: Key event IDs and interpretation for logon success/failure, LogonType, and Kerberos/NTLM authentication. Always be aware of whether an event is recorded on the logon source or the logon destination.
tags: [windows, eventlog, logon, authentication, kerberos, ntlm, lateral-movement]
timestamp: 2026-07-13
---
# Logon and authentication events

## Security.evtx

- 4624: logon success
- 4625: logon failure
- 4634 / 4647: logoff
- 4648: logon with explicit credentials (runas, etc.)
- 4672: special privileges assigned to new logon (marker for administrator-level logons)

## LogonType (4624/4625)

Focus on 3 (Network) and 10 (RemoteInteractive), with 9 (NewCredentials) and 12 (CachedRemoteInteractive) as secondary signals.

- 2: Interactive. Console logon, RUNAS, KVM, etc.
- 3: Network. Share access, WinRM, PsExec, IIS integrated auth, etc. As a rule, reusable credentials do not remain on the destination.
- 4: Batch. Scheduled tasks, etc.
- 5: Service. Service start. Credentials may remain in the LSA session.
- 7: Unlock.
- 8: NetworkCleartext. IIS Basic auth, WinRM over CredSSP, etc. High credential-theft risk.
- 9: NewCredentials. `RUNAS /NETWORK` etc.; alternate credentials used only for network connections.
- 10: RemoteInteractive. RDP. Credentials remain in the destination LSA, so privileged RDP into a compromised host is dangerous.
- 11: CachedInteractive. Interactive logon with cached credentials; not necessarily authenticated against a DC.
- 12: CachedRemoteInteractive. Cached variant of RDP.

## Interpreting logon failures (4625)

The logon error code (SubStatus) tells you why it failed (nonexistent user name / wrong password, etc.).
Useful for estimating how much the attacker already knew at that point.
A first-try successful logon suggests credentials were dumped beforehand or reused.

## Kerberos / NTLM (viewed on the DC)

Usually not needed when investigating a single endpoint. When a DC is available, use these to see which account authenticated to which service.

- Security.evtx
  - 4768: TGT request / 4769: service ticket request / 4771: pre-authentication failure
  - 4776: NTLM authentication attempt
- Microsoft-Windows-NTLM%4Operational.evtx
  - 4020-4023: client/server NTLM authentication attempts (extended in Win11 24H2+)
