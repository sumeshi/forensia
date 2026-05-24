---
section: 4_accounts
title: "Compromised Accounts and Authentication"
prompt: |
  Write the "Compromised Accounts and Authentication" section using the investigation data below.
  You must include:
    1. Accounts confirmed or suspected to be compromised, including supporting evidence_id values
    2. The apparent compromise method for each account, such as Pass-the-Hash, brute force, or credential theft
    3. Suspicious logons with timestamp, source IP, target host, and LogonType
    4. The LogonType values used by the attacker and their meaning, such as 3 = network logon and 10 = RDP
    5. Abuse of privileged accounts, including 4672 privileged logon indicators when applicable
  LogonType=3 is common and should be described as suspicious only when combined with additional indicators such as administrative share access, off-hours activity, or unusual external IPs.
keypoints:
  - top_keypoints
  - accounts_logon_summary
  - accounts_failed_logons
  - accounts_changes
  - accounts_explicit_credentials
---

# Compromised Accounts and Authentication

## Compromised Account List

| Account | Compromise Method | First Seen | Supporting Evidence (evidence_id) |
|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Suspicious Logon Details

| Timestamp | Source IP | Target Host | Account | LogonType | Why It Is Suspicious |
|---|---|---|---|---|---|
| <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> | <!-- fill --> |

---

## Brute Force / Password Spray

<!-- Describe confirmed 4625 clustering here. If not observed, write "Not observed." -->

---

## Account Operations (Create / Delete / Group Membership Changes)

<!-- Describe confirmed 4720 / 4726 / 4732 / 4728 / 4724 activity here. If not observed, write "Not observed." -->
