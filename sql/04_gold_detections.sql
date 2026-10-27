-- =====================================================================
-- 04 · GOLD: detections, threat intelligence (CTI), ML, scheduling and alerts
-- Incidents seeded by the generator (see the instructor guide):
--   brute force svc_backup 14-Oct · DNS tunnel 10.20.5.77 15/16-Oct · exfil 10.20.8.15 17-Oct
--   O365 mass download maria.lopez 16-Oct · old IOC 10-Feb · fw-bcn-02 stops sending 20-Oct
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- 1) Brute force: >= 20 failures for one user from one IP within 10 minutes (7.6)
CREATE OR REPLACE VIEW DET_BRUTE_FORCE AS
SELECT user_name, src_ip, device, TIME_SLICE(event_time, 10, 'MINUTE') AS window_start,
       COUNT(*) AS failures, unit, country
FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
WHERE activity = 'logon_failure'
GROUP BY ALL
HAVING COUNT(*) >= 20;

-- 2) Sequence: failures -> success -> special privileges (MATCH_RECOGNIZE)
CREATE OR REPLACE VIEW DET_BRUTE_FORCE_SUCCESS AS
SELECT * FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
  MATCH_RECOGNIZE (
    PARTITION BY user_name, src_ip ORDER BY event_time
    MEASURES FIRST(event_time) AS first_failure, LAST(event_time) AS privilege_time,
             COUNT(fail.*) AS failures, MATCH_NUMBER() AS match_id
    ONE ROW PER MATCH
    PATTERN (fail{10,} ok priv)
    DEFINE fail AS activity = 'logon_failure',
           ok   AS activity = 'logon_success',
           priv AS activity = 'special_privileges'
  );

-- 3) DNS tunnel / DGA: many long, unique subdomains toward the same domain (7.3)
CREATE OR REPLACE VIEW DET_DNS_TUNNEL AS
SELECT src_ip, query_domain, event_time::DATE AS day, COUNT(*) AS queries,
       COUNT(DISTINCT query_label) AS distinct_labels, AVG(LENGTH(query_label)) AS avg_label_len, unit
FROM SECURITY_LAKE.SILVER.DNS_ACTIVITY
GROUP BY ALL
HAVING COUNT(DISTINCT query_label) > 200 AND AVG(LENGTH(query_label)) > 30;

-- 4) Exfiltration: a host's daily outbound bytes vs. its 30-day average (7.4)
CREATE OR REPLACE VIEW DET_EXFIL AS
WITH daily AS (
  SELECT src_ip, event_time::DATE AS day, SUM(bytes_out) AS bytes_out, ANY_VALUE(unit) AS unit
  FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
  WHERE source = 'netflow'
  GROUP BY ALL),
scored AS (
  SELECT *, AVG(bytes_out) OVER (PARTITION BY src_ip ORDER BY day ROWS BETWEEN 30 PRECEDING AND 1 PRECEDING) AS baseline
  FROM daily)
SELECT src_ip, day, bytes_out, baseline, ROUND(bytes_out / NULLIF(baseline, 0), 1) AS ratio, unit
FROM scored
WHERE bytes_out > 1e9 AND bytes_out > 20 * baseline;

-- 5) Mass download in Office 365 (7.2)
CREATE OR REPLACE VIEW DET_O365_MASS_DOWNLOAD AS
SELECT user_name, src_ip, DATE_TRUNC('hour', event_time) AS hour, COUNT(*) AS downloads, unit
FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
WHERE source = 'o365' AND activity = 'FileDownloaded'
GROUP BY ALL
HAVING COUNT(*) > 100;

-- 6) IOC matches across the full history (5.1): DNS by domain, network and auth by IP
CREATE OR REPLACE VIEW DET_IOC_HITS AS
SELECT d.event_time, 'dns' AS class, d.src_ip, d.query AS observable, i.indicator, i.confidence, d.unit
FROM SECURITY_LAKE.SILVER.DNS_ACTIVITY d JOIN SECURITY_LAKE.BRONZE.IOC i
  ON i.type = 'domain' AND d.query_domain = i.indicator
UNION ALL
SELECT n.event_time, 'network', n.src_ip, n.dst_ip, i.indicator, i.confidence, n.unit
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY n JOIN SECURITY_LAKE.BRONZE.IOC i
  ON i.type = 'ip' AND n.dst_ip = i.indicator
UNION ALL
SELECT a.event_time, 'auth', a.src_ip, a.user_name, i.indicator, i.confidence, a.unit
FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY a JOIN SECURITY_LAKE.BRONZE.IOC i
  ON i.type = 'ip' AND a.src_ip = i.indicator;

-- 7) Source health (1.11): devices with no events in the last 12 h of data
CREATE OR REPLACE VIEW DET_SOURCE_SILENT AS
WITH last_seen AS (
  SELECT source, COALESCE(device, technology) AS emitter, MAX(event_time) AS last_event
  FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY ALL),
ref AS (SELECT MAX(event_time) AS now_ts FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY)
SELECT l.*, DATEDIFF('hour', l.last_event, r.now_ts) AS hours_silent
FROM last_seen l, ref r
WHERE DATEDIFF('hour', l.last_event, r.now_ts) >= 12;

-- ---------------------------------------------------------------------
-- ML: anomaly detection on daily outbound traffic per /24 subnet
-- Built live with Cortex Code: prompts/ml_egress_anomalies.md
-- Backup (run during preparation): sql/backup/ml_backup_models.sql
--   creates NET_DAILY_SUBNET, EGRESS_DAILY_SUBNET, NET_ANOMALY_MODEL,
--   EGRESS_ANOMALIES and NET_ANOMALIES (used by demo_snippets/ml.sql and the guides).
-- ---------------------------------------------------------------------
-- Sort by deviation: the exfiltration (10.20.8, 17-Oct) shows up ~1000x above forecast
SELECT series, ts, y, ROUND(forecast) AS forecast, ROUND(y / forecast, 1) AS x_over_forecast
FROM EGRESS_ANOMALIES WHERE is_anomaly ORDER BY x_over_forecast DESC;

-- ---------------------------------------------------------------------
-- Alert queue + hourly task + source health alert
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ALERTS (
  alert_id STRING DEFAULT UUID_STRING(), detected_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
  detection STRING, entity STRING, event_time TIMESTAMP_NTZ, details VARIANT, unit STRING,
  status STRING DEFAULT 'NEW', triage VARIANT);

CREATE OR REPLACE PROCEDURE RUN_DETECTIONS()
RETURNS STRING LANGUAGE SQL AS
$$
BEGIN
  INSERT INTO ALERTS (detection, entity, event_time, details, unit)
  SELECT d.* FROM (
    SELECT 'brute_force_success', user_name || '@' || src_ip, first_failure,
           OBJECT_CONSTRUCT('failures', failures, 'privilege_time', privilege_time), 'UES'
    FROM DET_BRUTE_FORCE_SUCCESS
    UNION ALL
    SELECT 'dns_tunnel', src_ip || ' -> ' || query_domain, day::TIMESTAMP_NTZ,
           OBJECT_CONSTRUCT('queries', queries, 'distinct_labels', distinct_labels, 'avg_label_len', avg_label_len), unit
    FROM DET_DNS_TUNNEL
    UNION ALL
    SELECT 'exfiltration', src_ip, day::TIMESTAMP_NTZ,
           OBJECT_CONSTRUCT('bytes_out', bytes_out, 'baseline', baseline, 'ratio', ratio), unit
    FROM DET_EXFIL
    UNION ALL
    SELECT 'o365_mass_download', user_name || '@' || src_ip, hour,
           OBJECT_CONSTRUCT('downloads', downloads), unit
    FROM DET_O365_MASS_DOWNLOAD
    UNION ALL
    SELECT 'ioc_hit', src_ip || ' -> ' || indicator, MIN(event_time),
           OBJECT_CONSTRUCT('class', ANY_VALUE(class), 'hits', COUNT(*), 'confidence', MAX(confidence)), ANY_VALUE(unit)
    FROM DET_IOC_HITS GROUP BY src_ip, indicator
  ) d (detection, entity, event_time, details, unit)
  WHERE NOT EXISTS (SELECT 1 FROM ALERTS a
                    WHERE a.detection = d.detection AND a.entity = d.entity AND a.event_time = d.event_time);
  RETURN 'ok';
END;
$$;

CALL RUN_DETECTIONS();
SELECT detection, COUNT(*) FROM ALERTS GROUP BY 1 ORDER BY 1;

CREATE OR REPLACE TASK DETECTIONS_HOURLY
  WAREHOUSE = SOC_WH
  SCHEDULE = 'USING CRON 15 * * * * Europe/Madrid'
AS CALL RUN_DETECTIONS();
-- ALTER TASK DETECTIONS_HOURLY RESUME;

-- Source health alert (1.11). For email, create the integration first (see environment setup).
CREATE OR REPLACE ALERT SOURCE_SILENT_ALERT
  WAREHOUSE = SOC_WH
  SCHEDULE = '60 MINUTE'
  IF (EXISTS (SELECT 1 FROM DET_SOURCE_SILENT))
  THEN
    INSERT INTO ALERTS (detection, entity, event_time, details)
    SELECT 'source_silent', emitter, last_event, OBJECT_CONSTRUCT('hours_silent', hours_silent)
    FROM DET_SOURCE_SILENT;
-- Email variant:
--   THEN CALL SYSTEM$SEND_EMAIL('SOC_EMAIL_INT', 'soc@example.com', 'Silent source', 'Review DET_SOURCE_SILENT');
-- ALTER ALERT SOURCE_SILENT_ALERT RESUME;
