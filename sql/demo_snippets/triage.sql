SELECT detection, entity, unit, LEFT(triage::STRING, 300) AS triage_ia
FROM SECURITY_LAKE.GOLD.ALERTS WHERE triage IS NOT NULL LIMIT 10;
