-- =====================================================================
-- 06 · SIM swap / port-out fraud: classification and investigation queue
-- (telco use case)
-- Labeled history (is_fraud) up to 17-Oct; 18–21 Oct are scored.
-- Seeded: fraud ring at store S-0457 / agent A-1123 from 18 to 20-Oct.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- The model is built live with Cortex Code: prompts/ml_sim_fraud.md
-- Backup (run during preparation): sql/backup/ml_backup_models.sql
--   creates SIM_TRAIN, SIM_FRAUD_MODEL and SIM_SCORED (used by 08, Streamlit and the guides)
--   and reapplies the PII tag and MASK_PII_HASH on SIM_SCORED.msisdn.

-- Model quality and feature importance
CALL SIM_FRAUD_MODEL!SHOW_EVALUATION_METRICS();
CALL SIM_FRAUD_MODEL!SHOW_FEATURE_IMPORTANCE();

-- Morning investigation queue: highest-risk requests
SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score, 3) AS score
FROM SIM_SCORED WHERE fraud_score > 0.5 ORDER BY fraud_score DESC LIMIT 25;

-- Insider fraud: agents/stores with an anomalous concentration of high-risk requests
SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
