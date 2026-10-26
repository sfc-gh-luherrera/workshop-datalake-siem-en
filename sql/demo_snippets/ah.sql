USE ROLE ACCOUNTADMIN;
SELECT query_start_time, user_name, f.value:"objectName"::STRING AS object, f.value:"columns" AS columns
FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY, LATERAL FLATTEN(base_objects_accessed) f
WHERE f.value:"objectName"::STRING ILIKE 'SECURITY_LAKE.SILVER.AUTH%' ORDER BY 1 DESC LIMIT 15;
