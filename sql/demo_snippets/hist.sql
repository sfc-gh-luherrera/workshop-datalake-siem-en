USE ROLE SOC_ADMIN;
USE SCHEMA SECURITY_LAKE.BRONZE;
-- What was loaded, when and with what errors (idempotent: re-running the COPY does not duplicate)
SELECT file_name, row_count, error_count, status, last_load_time
FROM TABLE(INFORMATION_SCHEMA.COPY_HISTORY(TABLE_NAME=>'DNS_RAW_DEMO', START_TIME=>DATEADD(hour,-1,CURRENT_TIMESTAMP())))
ORDER BY file_name;
