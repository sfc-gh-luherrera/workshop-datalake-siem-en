SELECT detection, COUNT(*) AS alerts, MIN(event_time) AS first_ev, MAX(event_time) AS last_ev, COUNT_IF(triage IS NOT NULL) AS triaged
FROM SECURITY_LAKE.GOLD.ALERTS GROUP BY detection ORDER BY alerts DESC;
