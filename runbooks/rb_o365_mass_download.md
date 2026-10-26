# Runbook: Mass download in Office 365 / SharePoint

**MITRE tactic:** Collection (TA0009), T1530 Data from Cloud Storage.

## Indicators
- More than 100 FileDownloaded per user per hour.
- Source IP new for the user, outside working hours, or from another country.

## Steps
1. Revoke the user's sessions and tokens in Entra ID; force a password change and MFA.
2. Check whether the source IP matches an IOC or a previous suspicious sign-in.
3. List the downloaded files and their sensitivity classification.
4. Contact the user and their manager to validate the activity.
5. If not legitimate: treat it as a data leak incident.
