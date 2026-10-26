USE ROLE SOC_ADMIN;
USE SCHEMA SECURITY_LAKE.BRONZE;
-- Query the file directly in S3, without loading it: suspiciously long domains
SELECT METADATA$FILENAME AS file,
       $1:ts::timestamp AS ts, $1:client_ip::string AS client_ip,
       $1:query::string AS query, LENGTH($1:query::string) AS len
FROM @S3_LOGS/dns/2026/10/15/ (FILE_FORMAT => 'FF_JSON')
WHERE LENGTH($1:query::string) > 40
LIMIT 20;
