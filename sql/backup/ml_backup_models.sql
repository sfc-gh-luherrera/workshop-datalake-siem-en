-- =====================================================================
-- backup · Backup ML models (run during environment PREPARATION)
-- In the workshop the models are built with Cortex Code following
-- prompts/ml_egress_anomalies.md and prompts/ml_sim_fraud.md. This script leaves
-- the same objects created so the following blocks (07 triage,
-- 08 governance, demo_snippets, Streamlit) have data even if the demo fails.
-- Objects: GOLD.NET_DAILY_SUBNET, EGRESS_DAILY_SUBNET, NET_ANOMALY_MODEL, EGRESS_ANOMALIES,
--          NET_ANOMALIES (compatibility), SIM_TRAIN, SIM_FRAUD_MODEL, SIM_SCORED
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- ---------------------------------------------------------------------
-- 1) Anomalies in daily outbound traffic per /24 subnet
--    Training: up to 16-Oct (the day before the seeded exfiltration).
--    Detection: 17–21 Oct. Expected: 10.20.8 on 17-Oct ~1000x above forecast.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW NET_DAILY_SUBNET AS
SELECT REGEXP_SUBSTR(src_ip, '^[0-9]+[.][0-9]+[.][0-9]+') AS subnet,
       event_time::DATE::TIMESTAMP_NTZ AS day, SUM(bytes_out)::FLOAT AS bytes_out
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
WHERE source = 'netflow'
GROUP BY ALL;

-- IMPORTANT: materialize the series into a table. NETWORK_ACTIVITY has the row access
-- policy RAP_BY_UNIT (08) and, inside ML training, IS_ROLE_IN_SESSION does not see the
-- session's roles: training on the view fails with "input_data is empty".
CREATE OR REPLACE TABLE EGRESS_DAILY_SUBNET COPY GRANTS AS SELECT * FROM NET_DAILY_SUBNET;

CREATE OR REPLACE SNOWFLAKE.ML.ANOMALY_DETECTION NET_ANOMALY_MODEL(
  INPUT_DATA => TABLE(SELECT * FROM EGRESS_DAILY_SUBNET WHERE day < '2026-10-17'),
  SERIES_COLNAME => 'SUBNET', TIMESTAMP_COLNAME => 'DAY', TARGET_COLNAME => 'BYTES_OUT',
  LABEL_COLNAME => '');

CREATE OR REPLACE TABLE EGRESS_ANOMALIES COPY GRANTS AS
SELECT * FROM TABLE(NET_ANOMALY_MODEL!DETECT_ANOMALIES(
  INPUT_DATA => TABLE(SELECT * FROM EGRESS_DAILY_SUBNET WHERE day >= '2026-10-17'),
  SERIES_COLNAME => 'SUBNET', TIMESTAMP_COLNAME => 'DAY', TARGET_COLNAME => 'BYTES_OUT',
  CONFIG_OBJECT => {'prediction_interval': 0.999}));

-- Compatibility: demo_snippets/ml.sql and the guides query NET_ANOMALIES
CREATE OR REPLACE TABLE NET_ANOMALIES COPY GRANTS AS SELECT * FROM EGRESS_ANOMALIES;

-- Check: 10.20.8 / 2026-10-17 must come first
SELECT series, ts, ROUND(y/1e6, 1) AS mb_out, ROUND(forecast/1e6, 1) AS mb_expected,
       ROUND(upper_bound/1e6, 1) AS mb_upper, ROUND(y / forecast, 1) AS x_over_forecast
FROM EGRESS_ANOMALIES WHERE is_anomaly ORDER BY x_over_forecast DESC;

-- ---------------------------------------------------------------------
-- 2) SIM swap / port-out fraud (classification). See 06_sim_swap_ml.sql
--    Expected: ring S-0457 / A-1123 with 75 high-risk requests.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW SIM_TRAIN AS
SELECT request_type, channel, new_device, new_location, requests_24h, account_age_days,
       HOUR(request_ts) AS hour_of_day, is_fraud::BOOLEAN AS is_fraud
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS
WHERE is_fraud IS NOT NULL;

CREATE OR REPLACE SNOWFLAKE.ML.CLASSIFICATION SIM_FRAUD_MODEL(
  INPUT_DATA => SYSTEM$REFERENCE('VIEW', 'SIM_TRAIN'),
  TARGET_COLNAME => 'IS_FRAUD');

CREATE OR REPLACE TABLE SIM_SCORED COPY GRANTS AS
SELECT s.request_ts, s.msisdn, s.request_type, s.channel, s.store_id, s.agent_id, s.unit,
       SIM_FRAUD_MODEL!PREDICT(INPUT_DATA => OBJECT_CONSTRUCT(
         'REQUEST_TYPE', s.request_type, 'CHANNEL', s.channel, 'NEW_DEVICE', s.new_device,
         'NEW_LOCATION', s.new_location, 'REQUESTS_24H', s.requests_24h,
         'ACCOUNT_AGE_DAYS', s.account_age_days, 'HOUR_OF_DAY', HOUR(s.request_ts))):probability:"True"::FLOAT AS fraud_score
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS s
WHERE s.is_fraud IS NULL;

-- SIM_SCORED is new: reapply the tag and masking from 08.
-- On the first build 08 does not exist yet: the block skips it and 08 applies them later.
EXECUTE IMMEDIATE $$
BEGIN
  ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET TAG SECURITY_LAKE.GOVERNANCE.DATA_SENSITIVITY = 'PII';
  ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET MASKING POLICY SECURITY_LAKE.GOVERNANCE.MASK_PII_HASH FORCE;
  RETURN 'PII reapplied on SIM_SCORED';
EXCEPTION WHEN OTHER THEN
  RETURN 'Skipped (run 08 afterwards): ' || SQLERRM;
END;
$$;

SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
