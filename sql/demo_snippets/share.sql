-- =====================================================================
-- IOC share with another Snowflake account (group CSIRT, another subsidiary, MSSP)
-- No copies, no files: the consumer queries a secure view live.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- Secure view: only aggregates per indicator, no internal hosts or users.
-- SECURE hides the definition from the consumer and is required to share views.
CREATE OR REPLACE SECURE VIEW V_IOC_HITS_SHARE
  COMMENT = 'IOC matches aggregated per indicator for sharing'
AS
SELECT indicator, class, unit, MAX(confidence) AS confidence, COUNT(*) AS hits,
       COUNT(DISTINCT src_ip) AS affected_hosts, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS
GROUP BY indicator, class, unit;

SELECT * FROM V_IOC_HITS_SHARE ORDER BY last_seen;

-- Create the share and grant minimum access (requires ACCOUNTADMIN or CREATE SHARE)
USE ROLE ACCOUNTADMIN;
CREATE SHARE IF NOT EXISTS SOC_IOC_SHARE COMMENT = 'IOCs detected by the SOC';
GRANT USAGE ON DATABASE SECURITY_LAKE TO SHARE SOC_IOC_SHARE;
GRANT USAGE ON SCHEMA SECURITY_LAKE.GOLD TO SHARE SOC_IOC_SHARE;
GRANT SELECT ON VIEW SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE TO SHARE SOC_IOC_SHARE;

SHOW SHARES LIKE 'SOC_IOC_SHARE';
SHOW GRANTS TO SHARE SOC_IOC_SHARE;

-- Add the consumer account (same region; across regions/clouds use a listing):
-- ALTER SHARE SOC_IOC_SHARE ADD ACCOUNTS = <ORG>.<CSIRT_ACCOUNT>;
-- In the consumer account:
--   CREATE DATABASE SOC_IOC FROM SHARE <ORG>.<PROVIDER_ACCOUNT>.SOC_IOC_SHARE;
--   SELECT * FROM SOC_IOC.GOLD.V_IOC_HITS_SHARE;
-- Policies: the RAP_BY_UNIT row access policy on SILVER.NETWORK_ACTIVITY is also evaluated
-- for the consumer; its roles do not exist there, so network rows
-- will not be visible unless the policy accounts for the share (e.g. with
-- IS_DATABASE_ROLE_IN_SESSION or CURRENT_ACCOUNT()). Validate with the real account.

-- When done (also in 99_teardown.sql):
-- DROP SHARE IF EXISTS SOC_IOC_SHARE;
-- DROP VIEW IF EXISTS SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE;
