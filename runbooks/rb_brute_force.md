# Runbook: Brute force with successful access

**MITRE tactic:** Credential Access (TA0006), T1110 Brute Force; Privilege Escalation T1078.

## Indicators
- Burst of 4625 events (failed logon) for one account from the same IP.
- Followed by 4624 (success) and 4672 (special privileges).
- Service accounts or external IPs (Tor nodes, hosting providers) raise the severity.

## Steps
1. Disable or rotate the credential of the affected account.
2. Review what the account did after access: AUTH_ACTIVITY and NETWORK_ACTIVITY in the following 24 h.
3. Check the source IP against IOCs and block it at the perimeter.
4. If it is a service account: verify that interactive logon is not allowed.
5. Escalate to CSIRT if privileges were used.
