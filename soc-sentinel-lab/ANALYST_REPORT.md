# SOC Analyst Incident Report

**Case ID:** SOC-2026-001  
**Status:** Closed – simulated training case  
**Priority:** Critical  
**Data source:** Authentication event logs  

## Executive summary

The detection pipeline identified a likely account-compromise sequence against `arun`. A single external IP, `185.220.101.4`, generated five failed authentication attempts over four minutes and subsequently logged in successfully to the same account. This pattern is consistent with password guessing followed by use of valid credentials.

Two additional events were identified: a possible impossible-travel sign-in for `priya`, and a privileged login by `secadmin`. These need validation but are not automatically malicious.

## Alert triage

| Priority | Alert | Why it matters | Analyst disposition |
| --- | --- | --- | --- |
| Critical | Successful login after repeated failures – `arun` | Five failures followed by success from the same IP | Escalate and contain |
| High | Brute-force activity – `185.220.101.4` | Multiple failures against more than one user | Block / rate-limit source IP |
| High | Impossible travel – `priya` | India and United States logins occurred 35 minutes apart | Contact user to validate |
| Medium | Privileged login – `secadmin` | Admin account signed in from Singapore | Confirm approved administrative work |

## Investigation timeline (UTC)

| Time | Event |
| --- | --- |
| 08:01–08:05 | `185.220.101.4` creates five failed-login events across `arun` and `meera`. |
| 08:08 | `arun` successfully authenticates from the same IP. Critical alert generated. |
| 09:00 | `priya` signs in from India. |
| 09:35 | `priya` signs in from the United States. Impossible-travel alert generated. |
| 10:10 | `secadmin` signs in from Singapore. Privileged-login alert generated. |

## Recommended response

1. Disable or reset `arun`'s account and revoke active sessions.
2. Block or challenge `185.220.101.4` at the identity provider or perimeter.
3. Review `arun`'s recent mailbox, VPN, and cloud activity for post-login actions.
4. Contact `priya` through a trusted channel to confirm both sign-ins.
5. Verify `secadmin`'s activity against a change ticket or maintenance window.
6. Preserve relevant logs and document final findings in the incident ticket.

## Lessons learned

- Multifactor authentication and conditional-access policies reduce risk from guessed or reused passwords.
- Failed-logon events should be correlated with later successes; treating them separately can miss account takeover.
- Privileged sign-ins need baseline context, such as approved locations and change records.
