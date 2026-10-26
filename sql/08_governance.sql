-- =====================================================================
-- 08 · Governance: tags, masking, segregation by unit, auditing, consumption
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
CREATE SCHEMA IF NOT EXISTS SECURITY_LAKE.GOVERNANCE;
USE SCHEMA SECURITY_LAKE.GOVERNANCE;

-- 1) Classification with tags
CREATE TAG IF NOT EXISTS DATA_SENSITIVITY ALLOWED_VALUES 'PII', 'CONFIDENTIAL', 'INTERNAL';
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.AUTH_ACTIVITY MODIFY COLUMN user_name SET TAG DATA_SENSITIVITY = 'PII';
ALTER TABLE SECURITY_LAKE.BRONZE.SIM_REQUESTS MODIFY COLUMN msisdn SET TAG DATA_SENSITIVITY = 'PII';
-- SIM_SCORED is a copy (CREATE TABLE AS in 06): it does not inherit the SIM_REQUESTS policy.
-- If 06 is re-run, this block must be re-run too.
ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET TAG DATA_SENSITIVITY = 'PII';

-- 2) Masking with a deterministic hash: the analyst does not see the data but can correlate
CREATE OR REPLACE MASKING POLICY MASK_PII_HASH AS (val STRING) RETURNS STRING ->
  CASE WHEN IS_ROLE_IN_SESSION('THREAT_HUNTER') THEN val
       ELSE 'h_' || LEFT(SHA2(val), 16) END;
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.AUTH_ACTIVITY MODIFY COLUMN user_name SET MASKING POLICY MASK_PII_HASH;
ALTER TABLE SECURITY_LAKE.BRONZE.SIM_REQUESTS MODIFY COLUMN msisdn SET MASKING POLICY MASK_PII_HASH;
ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET MASKING POLICY MASK_PII_HASH;

-- 3) Segregation by business unit in a single tenant (10.5)
CREATE TABLE IF NOT EXISTS UNIT_ACCESS (role_name STRING, unit STRING);
INSERT INTO UNIT_ACCESS
  SELECT * FROM VALUES ('SOC_ANALYST', 'UES') v
  WHERE NOT EXISTS (SELECT 1 FROM UNIT_ACCESS);
CREATE OR REPLACE ROW ACCESS POLICY RAP_BY_UNIT AS (row_unit STRING) RETURNS BOOLEAN ->
  IS_ROLE_IN_SESSION('THREAT_HUNTER')
  OR EXISTS (SELECT 1 FROM SECURITY_LAKE.GOVERNANCE.UNIT_ACCESS m
             WHERE IS_ROLE_IN_SESSION(m.role_name) AND m.unit = row_unit);
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.NETWORK_ACTIVITY ADD ROW ACCESS POLICY RAP_BY_UNIT ON (unit);

-- Demo: same SELECT, different result depending on the role.
-- IMPORTANT: disable secondary roles; otherwise the user inherits THREAT_HUNTER and sees everything.
USE ROLE SOC_ANALYST;
USE SECONDARY ROLES NONE;
SELECT unit, COUNT(*) FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY unit;        -- UES only
SELECT user_name, COUNT(*) FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
WHERE activity = 'logon_failure' GROUP BY 1 ORDER BY 2 DESC LIMIT 3;                    -- hash
USE ROLE THREAT_HUNTER;
SELECT unit, COUNT(*) FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY unit;        -- all
SELECT user_name, COUNT(*) FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
WHERE activity = 'logon_failure' GROUP BY 1 ORDER BY 2 DESC LIMIT 3;                    -- in clear text
-- The SOC agent (07) honors these same policies: ask it as SOC_ANALYST (8.7)

-- 4) Auditing (10.4, 9.11): who accessed PII data and what changed (latency ~1-3 h)
USE ROLE SOC_ADMIN;
SELECT ah.query_start_time, ah.user_name, obj.value:objectName::STRING AS object_name,
       col.value:columnName::STRING AS column_name
FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY ah,
     LATERAL FLATTEN(ah.base_objects_accessed) obj,
     LATERAL FLATTEN(obj.value:columns, OUTER => TRUE) col
WHERE ah.query_start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND obj.value:objectName::STRING ILIKE 'SECURITY_LAKE.%'
  AND col.value:columnName::STRING IN ('USER_NAME', 'MSISDN')
ORDER BY ah.query_start_time DESC LIMIT 50;

SELECT start_time, user_name, role_name, query_type, LEFT(query_text, 100) AS query_text
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND query_type IN ('ALTER_TABLE_MODIFY_COLUMN', 'CREATE_MASKING_POLICY', 'CREATE_ROW_ACCESS_POLICY', 'GRANT', 'REVOKE')
ORDER BY start_time DESC LIMIT 50;

-- Platform logins (Trust Center complements this with security scanners)
SELECT event_timestamp, user_name, client_ip, first_authentication_factor, is_success, error_message
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY event_timestamp DESC LIMIT 20;

-- 5) Consumption control (9.8): credit monitor with notification and suspension
USE ROLE ACCOUNTADMIN;
CREATE RESOURCE MONITOR IF NOT EXISTS SOC_MONITOR WITH CREDIT_QUOTA = 50
  FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY
  TRIGGERS ON 80 PERCENT DO NOTIFY ON 100 PERCENT DO SUSPEND;
ALTER WAREHOUSE SOC_WH SET RESOURCE_MONITOR = SOC_MONITOR;
