# Runbook: Suspected DNS tunnel / DGA

**MITRE tactic:** Command and Control (TA0011), T1071.004 DNS; Exfiltration T1048.

## Indicators
- Many unique, long subdomains (more than 30 characters, base32/hex look) toward the same domain.
- High volume of TXT queries from a single host.
- Newly registered domain or one present in threat intelligence (CTI) feeds.

## Steps
1. Identify the source host and the associated user (AUTH_ACTIVITY in the same time window).
2. Check the domain against IOCs and its age.
3. Review the host's NETWORK_ACTIVITY: connections to rare destinations or anomalous outbound volume.
4. If confirmed: isolate the host from the EDR and block the domain on the internal resolver.
5. Preserve evidence: export the raw events (BRONZE.DNS_RAW) for the period.

## Previous case
March 2026: DNS tunnel on a development server, dnscat2-type malware. Contained in 2 h by
isolating the host and blocking the domain.
