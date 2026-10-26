-- =====================================================================
-- 05 · Hunting over 1 year: raw vs normalized, acceleration, export, cost
-- =====================================================================
USE ROLE THREAT_HUNTER;
USE WAREHOUSE SOC_WH;
ALTER SESSION SET USE_CACHED_RESULT = FALSE;   -- measure without result cache
ALTER SESSION SET QUERY_TAG = 'workshop_hunting';

-- 1) Search on the ORIGINAL, non-normalized event (4.3): free text over the VARIANT
--    "Did anyone ever resolve this domain in the last year?"
SELECT raw:ts::TIMESTAMP_NTZ AS ts, raw:client_ip::STRING AS host, raw:query::STRING AS query, src_file
FROM SECURITY_LAKE.BRONZE.DNS_RAW
WHERE SEARCH(raw, 'update-check-srv.com')
ORDER BY ts;

--    Same pattern on raw firewall syslog (text)
SELECT raw_line FROM SECURITY_LAKE.BRONZE.FW_RAW
WHERE raw_line ILIKE '%action=deny%' AND raw_line ILIKE '%dport=22%' LIMIT 20;

-- 2) Hunting on the common model (4.4): everything a host touched in 12 months
SELECT class, COUNT(*) AS events, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.SILVER.ALL_EVENTS
WHERE (src_ip = '10.20.8.15' OR dst_ip = '10.20.8.15')
  AND event_time >= DATEADD('month', -12, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY class;

-- 3) Timed query (4.1): top external destinations by volume over 1 year.
--    Note the time (Query History) on XS and repeat on L to show elasticity.
SELECT dst_ip, COUNT(DISTINCT src_ip) AS hosts, SUM(bytes_out) AS bytes_out
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
WHERE source = 'netflow' AND event_time >= DATEADD('year', -1, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY dst_ip ORDER BY bytes_out DESC LIMIT 20;

USE ROLE SOC_ADMIN;
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'LARGE';
-- (repeat query 3)
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'XSMALL';

-- 4) Acceleration (4.8): Search Optimization for point lookups on the raw data
--    Run search 1 before and after; compare "partitions scanned" in the Query Profile.
ALTER TABLE SECURITY_LAKE.BRONZE.DNS_RAW ADD SEARCH OPTIMIZATION ON FULL_TEXT(raw), EQUALITY(raw:client_ip);
-- Build progress (search_optimization_progress = 100 when finished)
SHOW TABLES LIKE 'DNS_RAW' IN SCHEMA SECURITY_LAKE.BRONZE;

-- 5) Export (4.5): results to a stage (CSV) to share with CSIRT/forensics
COPY INTO @SECURITY_LAKE.BRONZE.S3_LOGS/exports/ioc_hits_
  FROM (SELECT * FROM SECURITY_LAKE.GOLD.DET_IOC_HITS)
  FILE_FORMAT = (TYPE = CSV COMPRESSION = GZIP) HEADER = TRUE OVERWRITE = TRUE;
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/exports/;

-- 6) Cost of what we just did (9.8)
SELECT LEFT(query_text, 60) AS query, warehouse_size,
       total_elapsed_time / 1000 AS seconds, bytes_scanned, rows_produced
FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION())
WHERE query_tag = 'workshop_hunting' AND execution_status = 'SUCCESS' AND query_type = 'SELECT'
ORDER BY start_time DESC LIMIT 20;
-- Partitions scanned/total: see Query Profile in Snowsight (before/after Search Optimization)
-- Credits per warehouse (ACCOUNT_USAGE latency ~1-3 h):
SELECT warehouse_name, SUM(credits_used) AS credits
FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
WHERE warehouse_name = 'SOC_WH' AND start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY 1;
