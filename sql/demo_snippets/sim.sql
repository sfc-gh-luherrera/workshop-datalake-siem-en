SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score,3) AS score
FROM SECURITY_LAKE.GOLD.SIM_SCORED WHERE fraud_score > 0.5 ORDER BY fraud_score DESC LIMIT 25;
