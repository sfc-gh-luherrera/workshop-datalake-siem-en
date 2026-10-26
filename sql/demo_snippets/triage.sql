SELECT detection, entity, unit, LEFT(triage::STRING, 300) AS ai_triage
FROM SECURITY_LAKE.GOLD.ALERTS WHERE triage IS NOT NULL LIMIT 10;
