SELECT series, ts, ROUND(y/1e6,1) AS mb_out, ROUND(forecast/1e6,1) AS mb_expected, ROUND(upper_bound/1e6,1) AS mb_upper, ROUND(distance,2) AS distance
FROM SECURITY_LAKE.GOLD.NET_ANOMALIES WHERE is_anomaly ORDER BY distance DESC LIMIT 15;
