-- =====================================================================
-- 02 · BRONZE: load of the original event + traceability metadata
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.BRONZE;

-- CSV with header for COPY with positional transformation
CREATE OR REPLACE FILE FORMAT FF_CSV TYPE = CSV SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '"'
  EMPTY_FIELD_AS_NULL = TRUE COMPRESSION = AUTO;

-- One raw table per source: the event as-is + where it came from
CREATE TABLE IF NOT EXISTS DNS_RAW      (raw VARIANT, source STRING, technology STRING, src_file STRING, file_ts TIMESTAMP_LTZ, load_ts TIMESTAMP_LTZ);
CREATE TABLE IF NOT EXISTS NETFLOW_RAW  LIKE DNS_RAW;
CREATE TABLE IF NOT EXISTS SURICATA_RAW LIKE DNS_RAW;
CREATE TABLE IF NOT EXISTS AD_RAW       LIKE DNS_RAW;
CREATE TABLE IF NOT EXISTS O365_RAW     LIKE DNS_RAW;
CREATE TABLE IF NOT EXISTS FW_RAW       (raw_line STRING, source STRING, technology STRING, src_file STRING, file_ts TIMESTAMP_LTZ, load_ts TIMESTAMP_LTZ);

-- Live demo: DNS load with metadata (1.12, 1.13)
COPY INTO DNS_RAW
  FROM (SELECT $1, 'dns', 'bind', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
        FROM @S3_LOGS/dns/ (FILE_FORMAT => 'FF_JSON'))
  ON_ERROR = CONTINUE;

COPY INTO NETFLOW_RAW
  FROM (SELECT $1, 'netflow', 'netflow-v9', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
        FROM @S3_LOGS/netflow/ (FILE_FORMAT => 'FF_JSON'))
  ON_ERROR = CONTINUE;

COPY INTO SURICATA_RAW
  FROM (SELECT $1, 'suricata', 'suricata-eve', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
        FROM @S3_LOGS/suricata/ (FILE_FORMAT => 'FF_JSON'))
  ON_ERROR = CONTINUE;

COPY INTO AD_RAW
  FROM (SELECT $1, 'ad', 'windows-security', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
        FROM @S3_LOGS/ad/ (FILE_FORMAT => 'FF_JSON'))
  ON_ERROR = CONTINUE;

COPY INTO O365_RAW
  FROM (SELECT $1, 'o365', 'o365-management-api', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
        FROM @S3_LOGS/o365/ (FILE_FORMAT => 'FF_JSON'))
  ON_ERROR = CONTINUE;

-- Syslog: one line per event, unparsed (parsed in SILVER)
COPY INTO FW_RAW
  FROM (SELECT $1, 'fw', 'syslog', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
        FROM @S3_LOGS/fw/ (FILE_FORMAT => 'FF_LINES'))
  ON_ERROR = CONTINUE;

-- SIM requests (typed CSV) and threat intelligence (CTI) IOCs (5.1)
CREATE TABLE IF NOT EXISTS SIM_REQUESTS (
  request_ts TIMESTAMP_NTZ, msisdn STRING, request_type STRING, channel STRING, store_id STRING, agent_id STRING,
  new_device NUMBER, new_location NUMBER, requests_24h NUMBER, account_age_days NUMBER, is_fraud NUMBER,
  unit STRING, country STRING, src_file STRING);
COPY INTO SIM_REQUESTS
  FROM (SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, METADATA$FILENAME
        FROM @S3_LOGS/sim/ (FILE_FORMAT => 'FF_CSV'));

CREATE TABLE IF NOT EXISTS IOC (indicator STRING, type STRING, source STRING, confidence NUMBER, first_seen DATE, src_file STRING);
COPY INTO IOC
  FROM (SELECT $1, $2, $3, $4, $5, METADATA$FILENAME FROM @S3_LOGS/ioc/ (FILE_FORMAT => 'FF_CSV'));

-- Ingestion monitoring (1.10, 9.9, 9.10): files, rows and errors per source
SELECT table_name, COUNT(*) AS files, SUM(row_count) AS rows_loaded, SUM(error_count) AS errors,
       MAX(last_load_time) AS last_load
FROM SECURITY_LAKE.INFORMATION_SCHEMA.LOAD_HISTORY
WHERE schema_name = 'BRONZE'
GROUP BY table_name ORDER BY table_name;

-- Traceability of a specific event (1.12)
SELECT raw, source, technology, src_file, file_ts, load_ts FROM DNS_RAW LIMIT 5;

-- ---------------------------------------------------------------------
-- Query without copying (4.7, 5.2): external table over the bucket.
-- Requires an external stage (S3). Skip when rehearsing with the internal stage.
-- ---------------------------------------------------------------------
-- CREATE EXTERNAL TABLE DNS_EXT
--   WITH LOCATION = @S3_LOGS/dns/
--   FILE_FORMAT = (FORMAT_NAME = 'FF_JSON')
--   AUTO_REFRESH = FALSE;
-- ALTER EXTERNAL TABLE DNS_EXT REFRESH;
-- SELECT value:query::STRING AS query, COUNT(*) FROM DNS_EXT GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- Scheduled incremental load (not real time): a daily task repeats the COPYs;
-- COPY does not reload files already loaded (load metadata, 64 days).
CREATE OR REPLACE TASK LOAD_DNS_DAILY
  WAREHOUSE = SOC_WH
  SCHEDULE = 'USING CRON 0 2 * * * Europe/Madrid'
AS
  COPY INTO DNS_RAW
    FROM (SELECT $1, 'dns', 'bind', METADATA$FILENAME, METADATA$FILE_LAST_MODIFIED, CURRENT_TIMESTAMP()
          FROM @S3_LOGS/dns/ (FILE_FORMAT => 'FF_JSON'))
    ON_ERROR = CONTINUE;
-- ALTER TASK LOAD_DNS_DAILY RESUME;
