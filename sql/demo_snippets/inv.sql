USE ROLE SOC_ADMIN;
USE SCHEMA SECURITY_LAKE.BRONZE;
-- Bucket inventory via directory table
SELECT SPLIT_PART(relative_path,'/',1) AS source,
       COUNT(*) AS files,
       ROUND(SUM(size)/1024/1024,1) AS mb
FROM DIRECTORY(@S3_LOGS)
GROUP BY 1 ORDER BY mb DESC;
