---
type: knowledge
title: RDP and remote access events
description: Key event IDs for RDP connection attempts, authentication, session start, disconnect, and reconnect. RDP-related logs often survive even when the Security log has been cleared.
tags: [windows, eventlog, rdp, terminal-services, remote-access, lateral-movement]
timestamp: 2026-07-13
---
# RDP and remote access events

## Security.evtx

- 4778: session reconnected to a terminal server session
- 4779: session disconnected without logging off

## Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx

- 21: session logon succeeded
- 22: shell start notification
- 23: session logoff succeeded
- 24: session disconnected
- 25: session reconnection succeeded

## Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx

- 261: connection received on listener RDP-Tcp
- 1148: session connection failed
- 1149: user authentication succeeded (do not conclude a successful RDP logon from this alone)

## Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx (source side)

- 1024: RDP client attempted to connect to a server (the destination is recorded; useful for tracing pivot hosts)
- 1026: RDP client disconnected

## System.evtx

- 9009: Desktop Window Manager exited (RDP session disconnect, etc.)
