-- Retroactive hunting: today's IOCs against 12 months of logs
SELECT class, COUNT(*) AS hits, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen, COUNT(DISTINCT src_ip) AS hosts
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS GROUP BY class ORDER BY hits DESC;
