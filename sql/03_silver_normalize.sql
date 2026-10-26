-- =====================================================================
-- 03 · SILVER: normalized common model (OCSF style), quality, lineage, lifecycle
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.SILVER;

-- DNS activity (OCSF: DNS Activity)
CREATE OR REPLACE DYNAMIC TABLE DNS_ACTIVITY TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:ts::TIMESTAMP_NTZ              AS event_time,
       raw:client_ip::STRING              AS src_ip,
       LOWER(raw:query::STRING)           AS query,
       REGEXP_SUBSTR(LOWER(raw:query::STRING), '[^.]+[.][^.]+$') AS query_domain,
       SPLIT_PART(LOWER(raw:query::STRING), '.', 1)              AS query_label,
       raw:qtype::STRING                  AS query_type,
       raw:rcode::STRING                  AS rcode,
       raw:unit::STRING                   AS unit,
       raw:country::STRING                AS country,
       source, technology, src_file
FROM SECURITY_LAKE.BRONZE.DNS_RAW;

-- Network activity: NetFlow + parsed firewall/VPN syslog (OCSF: Network Activity)
CREATE OR REPLACE DYNAMIC TABLE NETWORK_ACTIVITY TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:ts::TIMESTAMP_NTZ AS event_time, raw:src_ip::STRING AS src_ip, raw:dst_ip::STRING AS dst_ip,
       raw:dst_port::INT AS dst_port, raw:proto::STRING AS proto, raw:bytes::NUMBER AS bytes_out,
       NULL::STRING AS action, NULL::STRING AS user_name, NULL::STRING AS device,
       raw:unit::STRING AS unit, raw:country::STRING AS country, source, technology, src_file
FROM SECURITY_LAKE.BRONZE.NETFLOW_RAW
UNION ALL
SELECT TRY_TO_TIMESTAMP_NTZ(REGEXP_SUBSTR(raw_line, '^<[0-9]+>(\\S+)', 1, 1, 'e', 1)),
       REGEXP_SUBSTR(raw_line, 'src=(\\S+)', 1, 1, 'e', 1),
       REGEXP_SUBSTR(raw_line, 'dst=(\\S+)', 1, 1, 'e', 1),
       TRY_TO_NUMBER(REGEXP_SUBSTR(raw_line, 'dport=(\\S+)', 1, 1, 'e', 1)),
       UPPER(REGEXP_SUBSTR(raw_line, 'proto=(\\S+)', 1, 1, 'e', 1)),
       NULL,
       REGEXP_SUBSTR(raw_line, 'action=(\\S+)', 1, 1, 'e', 1),
       REGEXP_SUBSTR(raw_line, 'user=(\\S+)', 1, 1, 'e', 1),
       REGEXP_SUBSTR(raw_line, '^<[0-9]+>\\S+ (\\S+)', 1, 1, 'e', 1),
       'UES', 'ES', source, REGEXP_SUBSTR(raw_line, 'vendor=(\\S+)', 1, 1, 'e', 1), src_file
FROM SECURITY_LAKE.BRONZE.FW_RAW;

-- Authentication: Windows/AD + Office 365 (OCSF: Authentication / API Activity)
CREATE OR REPLACE DYNAMIC TABLE AUTH_ACTIVITY TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:TimeCreated::TIMESTAMP_NTZ AS event_time, raw:TargetUserName::STRING AS user_name,
       raw:IpAddress::STRING AS src_ip, raw:Computer::STRING AS device, raw:EventID::INT AS event_id,
       CASE raw:EventID::INT WHEN 4624 THEN 'logon_success' WHEN 4625 THEN 'logon_failure'
            WHEN 4672 THEN 'special_privileges' ELSE 'other' END AS activity,
       raw:unit::STRING AS unit, raw:country::STRING AS country, source, technology, src_file
FROM SECURITY_LAKE.BRONZE.AD_RAW
UNION ALL
SELECT raw:CreationTime::TIMESTAMP_NTZ, SPLIT_PART(raw:UserId::STRING, '@', 1), raw:ClientIP::STRING,
       raw:Workload::STRING, NULL, raw:Operation::STRING, raw:unit::STRING, raw:country::STRING,
       source, technology, src_file
FROM SECURITY_LAKE.BRONZE.O365_RAW;

-- IDS findings: Suricata EVE (OCSF: Detection Finding)
CREATE OR REPLACE DYNAMIC TABLE IDS_FINDINGS TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:timestamp::TIMESTAMP_NTZ AS event_time, raw:src_ip::STRING AS src_ip, raw:dest_ip::STRING AS dst_ip,
       raw:dest_port::INT AS dst_port, raw:alert.signature::STRING AS signature,
       raw:alert.signature_id::INT AS signature_id, raw:alert.severity::INT AS severity,
       raw:alert.category::STRING AS category, raw:unit::STRING AS unit, raw:country::STRING AS country,
       source, technology, src_file
FROM SECURITY_LAKE.BRONZE.SURICATA_RAW;

-- Unified view for cross-source searches (4.4)
CREATE OR REPLACE VIEW ALL_EVENTS AS
SELECT event_time, 'dns' AS class, src_ip, NULL AS dst_ip, NULL AS user_name, query AS detail, unit, country, source FROM DNS_ACTIVITY
UNION ALL SELECT event_time, 'network', src_ip, dst_ip, user_name, action, unit, country, source FROM NETWORK_ACTIVITY
UNION ALL SELECT event_time, 'auth', src_ip, NULL, user_name, activity, unit, country, source FROM AUTH_ACTIVITY
UNION ALL SELECT event_time, 'ids', src_ip, dst_ip, NULL, signature, unit, country, source FROM IDS_FINDINGS;

-- ---------------------------------------------------------------------
-- Data quality (3.4): native DMFs on the normalized layer
-- ---------------------------------------------------------------------
ALTER DYNAMIC TABLE NETWORK_ACTIVITY SET DATA_METRIC_SCHEDULE = 'TRIGGER_ON_CHANGES';
ALTER DYNAMIC TABLE NETWORK_ACTIVITY ADD DATA METRIC FUNCTION SNOWFLAKE.CORE.NULL_COUNT ON (src_ip);
ALTER DYNAMIC TABLE NETWORK_ACTIVITY ADD DATA METRIC FUNCTION SNOWFLAKE.CORE.NULL_COUNT ON (event_time);
-- Live ad hoc check:
SELECT SNOWFLAKE.CORE.NULL_COUNT(SELECT event_time FROM NETWORK_ACTIVITY) AS null_event_time;

-- ---------------------------------------------------------------------
-- Historical reprocessing (3.5): change the parser and recompute the full history
-- Demo: add a field to DNS_ACTIVITY (CREATE OR REPLACE) or force a refresh:
-- ---------------------------------------------------------------------
ALTER DYNAMIC TABLE DNS_ACTIVITY REFRESH;

-- Lineage (3.6): Snowsight > Catalog > SILVER.NETWORK_ACTIVITY > Lineage

-- ---------------------------------------------------------------------
-- Storage tiers and retention (2.1, 2.5, 2.8)
-- Archives rows older than 365 days to COOL and expires them after 5 years in archive.
-- WARNING: a table's archive tier is permanent. Applied to BRONZE.
-- ---------------------------------------------------------------------
USE SCHEMA SECURITY_LAKE.BRONZE;
CREATE STORAGE LIFECYCLE POLICY IF NOT EXISTS SLP_RAW_1Y_COOL
  AS (ts TIMESTAMP_LTZ) RETURNS BOOLEAN -> ts < DATEADD('day', -365, CURRENT_TIMESTAMP())
  ARCHIVE_TIER = COOL
  ARCHIVE_FOR_DAYS = 1825
  COMMENT = 'Raw: 1 year queryable, 5 years in COOL archive';
ALTER TABLE DNS_RAW ADD STORAGE LIFECYCLE POLICY SLP_RAW_1Y_COOL ON (file_ts);
SHOW STORAGE LIFECYCLE POLICIES IN SCHEMA SECURITY_LAKE.BRONZE;
