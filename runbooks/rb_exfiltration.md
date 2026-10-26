# Runbook: Data exfiltration

**MITRE tactic:** Exfiltration (TA0010), T1041 / T1567.

## Indicators
- A host's daily outbound bytes far above its baseline (more than 20 times).
- Unusual external destination, often on port 443.
- IDS alert for a large TLS transfer to a rare destination.

## Steps
1. Confirm the volume and destination in NETWORK_ACTIVITY; check the destination against IOCs.
2. Identify the process and user on the host (EDR).
3. Block the destination on the firewall and isolate the host.
4. Determine what data left (DLP, prior file access).
5. Assess notification to the data protection authority (72 h, GDPR) with the DPO.
