-- =====================================================================
-- 09 · Zero-Copy Clone and Time Travel in day-to-day SOC work
-- Everything destructive runs on the SECURITY_LAKE_DEV clone, never on production.
-- =====================================================================
USE WAREHOUSE SOC_WH;
ALTER SESSION SET QUERY_TAG = 'workshop_09';

-- ---------------------------------------------------------------------
-- A1) Zero-Copy Clone: a development environment identical to production in seconds
--     It copies no data (it shares micro-partitions); you only pay for what changes.
--     SOC_ADMIN does not have CREATE DATABASE: clone with SYSADMIN and transfer ownership.
-- ---------------------------------------------------------------------
USE ROLE SYSADMIN;
CREATE DATABASE SECURITY_LAKE_DEV CLONE SECURITY_LAKE
  COMMENT = 'Development clone (workshop 09) - drop when done';
GRANT OWNERSHIP ON DATABASE SECURITY_LAKE_DEV TO ROLE SOC_ADMIN COPY CURRENT GRANTS;
USE ROLE SOC_ADMIN;

-- What gets cloned and in what state (verified):
--  - Dynamic tables: cloned with data, SUSPENDED (reason CLONED_AUTO_SUSPENDED).
--    Careful: their SQL uses fully qualified names (SECURITY_LAKE.BRONZE...), so if
--    resumed with ALTER DYNAMIC TABLE ... RESUME they would read PRODUCTION BRONZE.
--  - Tasks and alerts: cloned in suspended state (they do not run on their own).
--  - Views with fully qualified names (GOLD.DET_*) still point to SECURITY_LAKE.
--  - Storage lifecycle policies: not applied to the cloned tables.
SHOW DYNAMIC TABLES IN DATABASE SECURITY_LAKE_DEV;   -- scheduling_state = SUSPENDED, is_clone = true
SHOW TASKS IN DATABASE SECURITY_LAKE_DEV;            -- state = suspended
SHOW ALERTS IN DATABASE SECURITY_LAKE_DEV;           -- state = suspended

-- Rule change in DEV: "it's noisy, let's raise the DNS tunnel threshold from 200 to 2000"
-- (original rule in 04_gold_detections.sql, DET_DNS_TUNNEL). Point it at DEV.SILVER.
USE SCHEMA SECURITY_LAKE_DEV.GOLD;
CREATE OR REPLACE VIEW DET_DNS_TUNNEL AS
SELECT src_ip, query_domain, event_time::DATE AS day, COUNT(*) AS queries,
       COUNT(DISTINCT query_label) AS distinct_labels, AVG(LENGTH(query_label)) AS avg_label_len, unit
FROM SECURITY_LAKE_DEV.SILVER.DNS_ACTIVITY
GROUP BY ALL
HAVING COUNT(DISTINCT query_label) > 2000 AND AVG(LENGTH(query_label)) > 30;

-- Recompute in DEV: the cloned procedure writes to the clone's ALERTS
DELETE FROM ALERTS WHERE detection = 'dns_tunnel';
CALL RUN_DETECTIONS();

-- Compare DEV vs PROD: alerts added and removed by the rule change
SELECT COALESCE(d.detection, p.detection) AS detection, COALESCE(d.entity, p.entity) AS entity,
       COALESCE(d.event_time, p.event_time) AS event_time,
       CASE WHEN p.alert_id IS NULL THEN 'NEW in DEV' ELSE 'REMOVED in DEV' END AS change
FROM SECURITY_LAKE_DEV.GOLD.ALERTS d
FULL OUTER JOIN SECURITY_LAKE.GOLD.ALERTS p
  ON d.detection = p.detection AND d.entity = p.entity AND d.event_time = p.event_time
WHERE p.alert_id IS NULL OR d.alert_id IS NULL
ORDER BY event_time;
-- Result: the 2 real alerts for the 10.20.5.77 tunnel (15 and 16-Oct) disappear.
-- Conclusion: the change is NOT promoted to production. Production has not been touched.

-- Summary per detection
SELECT detection, COUNT_IF(env = 'PROD') AS prod, COUNT_IF(env = 'DEV') AS dev
FROM (SELECT 'PROD' AS env, detection FROM SECURITY_LAKE.GOLD.ALERTS
      UNION ALL SELECT 'DEV', detection FROM SECURITY_LAKE_DEV.GOLD.ALERTS)
GROUP BY 1 ORDER BY 1;

-- ---------------------------------------------------------------------
-- A2) Time Travel: "someone deleted the alert queue"
--     ALWAYS on the SECURITY_LAKE_DEV clone, not on production.
-- ---------------------------------------------------------------------
USE SCHEMA SECURITY_LAKE_DEV.GOLD;
-- AT(OFFSET) cannot go further back than the clone's creation (error 000707). Live,
-- more than a minute has already passed; if the script is run in one go, wait:
SELECT SYSTEM$WAIT(60);
SET t_before = CURRENT_TIMESTAMP();

-- The "accident": a filter is missing and all open alerts get deleted
DELETE FROM ALERTS WHERE status = 'NEW';
SET q_delete = LAST_QUERY_ID();

-- What did the table look like? Three ways to travel in time
SELECT (SELECT COUNT(*) FROM ALERTS)                                    AS now_count,
       (SELECT COUNT(*) FROM ALERTS AT(OFFSET => -60))                  AS sixty_seconds_ago,
       (SELECT COUNT(*) FROM ALERTS BEFORE(STATEMENT => $q_delete))     AS just_before_delete,
       (SELECT COUNT(*) FROM ALERTS AT(TIMESTAMP => $t_before))         AS at_t_before;
-- OFFSET is approximate (it may land before or after other changes); STATEMENT is exact.

-- "What did the queue look like at X?" (e.g. for the incident report)
SELECT detection, entity, event_time, status
FROM ALERTS AT(TIMESTAMP => $t_before)
ORDER BY event_time;

-- Recovery option 1: reinsert what was deleted
INSERT INTO ALERTS
SELECT * FROM ALERTS BEFORE(STATEMENT => $q_delete)
WHERE status = 'NEW';

-- Option 2: clone the table as it was (without touching the current one) and compare/replace
CREATE OR REPLACE TABLE ALERTS_BEFORE_DELETE CLONE ALERTS BEFORE(STATEMENT => $q_delete);
SELECT COUNT(*) FROM ALERTS_BEFORE_DELETE;

-- Accidental DROP of a whole table and recovery
DROP TABLE ALERTS_BEFORE_DELETE;
UNDROP TABLE ALERTS_BEFORE_DELETE;
SELECT COUNT(*) FROM ALERTS_BEFORE_DELETE;
DROP TABLE ALERTS_BEFORE_DELETE;

-- Time Travel window per table (days). Default 1; up to 90 on Enterprise.
SELECT table_schema, table_name, table_type, retention_time
FROM SECURITY_LAKE.INFORMATION_SCHEMA.TABLES
WHERE table_schema <> 'INFORMATION_SCHEMA' AND table_type <> 'VIEW'
ORDER BY 1, 2;
-- Extend on critical tables (tested on the clone; in production, a cost decision):
ALTER TABLE SECURITY_LAKE_DEV.GOLD.ALERTS SET DATA_RETENTION_TIME_IN_DAYS = 30;
-- ALTER TABLE SECURITY_LAKE.GOLD.ALERTS SET DATA_RETENTION_TIME_IN_DAYS = 30;
-- After Time Travel, permanent tables have 7 days of Fail-safe: not queryable by the
-- customer, only recoverable by Snowflake Support (last resort).
-- TRANSIENT/TEMPORARY tables have no Fail-safe.

-- Forensic evidence: freeze the lake exactly as it was at a given instant
-- (limited to each table's Time Travel window; tested with a test clone).
-- USE ROLE SYSADMIN;
-- CREATE DATABASE SECURITY_LAKE_EVIDENCE_20261017
--   CLONE SECURITY_LAKE AT(TIMESTAMP => '2026-10-17 09:00:00 +02:00'::TIMESTAMP_TZ)
--   COMMENT = 'Evidence for exfiltration incident 10.20.8.15 - read only';
-- GRANT OWNERSHIP ON DATABASE SECURITY_LAKE_EVIDENCE_20261017 TO ROLE SOC_ADMIN COPY CURRENT GRANTS;
-- GRANT USAGE ON DATABASE SECURITY_LAKE_EVIDENCE_20261017 TO ROLE THREAT_HUNTER;
-- Who created it and when is recorded in ACCOUNT_USAGE.QUERY_HISTORY / ACCESS_HISTORY (10.4).

-- ---------------------------------------------------------------------
-- When done: drop the clone (also included in 99_teardown.sql)
-- ---------------------------------------------------------------------
-- USE ROLE SOC_ADMIN;
-- DROP DATABASE IF EXISTS SECURITY_LAKE_DEV;
ALTER SESSION UNSET QUERY_TAG;
