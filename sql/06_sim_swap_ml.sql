-- =====================================================================
-- 06 · SIM swap / port-out fraud: classification and investigation queue
-- (telco use case)
-- Labeled history (is_fraud) up to 17-Oct; 18–21 Oct are scored.
-- Seeded: fraud ring at store S-0457 / agent A-1123 from 18 to 20-Oct.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

CREATE OR REPLACE VIEW SIM_TRAIN AS
SELECT request_type, channel, new_device, new_location, requests_24h, account_age_days,
       HOUR(request_ts) AS hour_of_day, is_fraud::BOOLEAN AS is_fraud
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS
WHERE is_fraud IS NOT NULL;

CREATE OR REPLACE SNOWFLAKE.ML.CLASSIFICATION SIM_FRAUD_MODEL(
  INPUT_DATA => SYSTEM$REFERENCE('VIEW', 'SIM_TRAIN'),
  TARGET_COLNAME => 'IS_FRAUD');

-- Model quality and feature importance
CALL SIM_FRAUD_MODEL!SHOW_EVALUATION_METRICS();
CALL SIM_FRAUD_MODEL!SHOW_FEATURE_IMPORTANCE();

-- Daily scoring of new requests
CREATE OR REPLACE TABLE SIM_SCORED AS
SELECT s.request_ts, s.msisdn, s.request_type, s.channel, s.store_id, s.agent_id, s.unit,
       SIM_FRAUD_MODEL!PREDICT(INPUT_DATA => OBJECT_CONSTRUCT(
         'REQUEST_TYPE', s.request_type, 'CHANNEL', s.channel, 'NEW_DEVICE', s.new_device,
         'NEW_LOCATION', s.new_location, 'REQUESTS_24H', s.requests_24h,
         'ACCOUNT_AGE_DAYS', s.account_age_days, 'HOUR_OF_DAY', HOUR(s.request_ts))):probability:"True"::FLOAT AS fraud_score
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS s
WHERE s.is_fraud IS NULL;

-- Morning investigation queue: highest-risk requests
SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score, 3) AS score
FROM SIM_SCORED WHERE fraud_score > 0.5 ORDER BY fraud_score DESC LIMIT 25;

-- Insider fraud: agents/stores with an anomalous concentration of high-risk requests
SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
