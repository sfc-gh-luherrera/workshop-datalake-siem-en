USE ROLE SOC_ADMIN; USE WAREHOUSE SOC_WH;
SELECT src_ip, query_domain, day, queries, distinct_labels, ROUND(avg_label_len,1) AS avg_len, unit
FROM SECURITY_LAKE.GOLD.DET_DNS_TUNNEL ORDER BY day;
