-- =====================================================================
-- Ingestion patterns: CSV, NDJSON, JSON array, wrapped JSON, embedded JSON
-- Sample files: samples/ingest_formats/
-- Uses its own internal stage (INGEST_DEMO) so it does not touch S3_LOGS.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.BRONZE;

CREATE STAGE IF NOT EXISTS INGEST_DEMO COMMENT = 'Ingestion format samples';
-- Upload from the repo root (SnowSQL / Snowflake CLI):
--   PUT file://samples/ingest_formats/* @INGEST_DEMO AUTO_COMPRESS = TRUE OVERWRITE = TRUE;
LIST @INGEST_DEMO;

CREATE FILE FORMAT IF NOT EXISTS FF_CSV TYPE = CSV SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '"'
  EMPTY_FIELD_AS_NULL = TRUE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_JSON TYPE = JSON STRIP_OUTER_ARRAY = FALSE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_JSON_ARRAY TYPE = JSON STRIP_OUTER_ARRAY = TRUE COMPRESSION = AUTO;

-- ---------------------------------------------------------------------
-- 1. CSV -> typed table (positional $1..$n). Quoted field "feed, partner A" stays one column.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DEMO_IOC (indicator STRING, type STRING, source STRING,
  confidence NUMBER, first_seen DATE, src_file STRING);
COPY INTO DEMO_IOC
  FROM (SELECT $1, $2, $3, $4, $5, METADATA$FILENAME
        FROM @INGEST_DEMO (FILE_FORMAT => 'FF_CSV', PATTERN => '.*ioc_sample[.]csv.*'));
SELECT * FROM DEMO_IOC;

-- ---------------------------------------------------------------------
-- 2. NDJSON (one object per line) -> VARIANT. The extra "new_field" does not break the load.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DEMO_DNS (raw VARIANT, src_file STRING);
COPY INTO DEMO_DNS
  FROM (SELECT $1, METADATA$FILENAME
        FROM @INGEST_DEMO (FILE_FORMAT => 'FF_JSON', PATTERN => '.*dns_ndjson[.]json.*'));
SELECT raw:ts::TIMESTAMP_TZ AS ts, raw:query::STRING AS query,
       raw:client.ip::STRING AS client_ip, raw:new_field::STRING AS new_field
FROM DEMO_DNS;

-- ---------------------------------------------------------------------
-- 3. Top-level array [ {...}, {...} ] -> STRIP_OUTER_ARRAY = TRUE, one row per element.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DEMO_O365 (raw VARIANT, src_file STRING);
COPY INTO DEMO_O365
  FROM (SELECT $1, METADATA$FILENAME
        FROM @INGEST_DEMO (FILE_FORMAT => 'FF_JSON_ARRAY', PATTERN => '.*o365_array[.]json.*'));
SELECT raw:CreationTime::TIMESTAMP_TZ AS ts, raw:Operation::STRING AS operation,
       raw:UserId::STRING AS user_id
FROM DEMO_O365;   -- 2 rows (with FF_JSON it would be 1 row holding the whole array)

-- ---------------------------------------------------------------------
-- 4. Wrapped JSON {"meta":..., "records":[...]} -> load 1 row per file, then FLATTEN.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DEMO_CLOUDTRAIL_RAW (raw VARIANT, src_file STRING);
COPY INTO DEMO_CLOUDTRAIL_RAW
  FROM (SELECT $1, METADATA$FILENAME
        FROM @INGEST_DEMO (FILE_FORMAT => 'FF_JSON', PATTERN => '.*cloudtrail_wrapped[.]json.*'));
SELECT d.raw:meta.exported_by::STRING        AS exported_by,
       r.value:eventTime::TIMESTAMP_TZ       AS ts,
       r.value:eventName::STRING             AS event_name,
       r.value:sourceIPAddress::STRING       AS src_ip,
       r.value:userIdentity.userName::STRING AS user_name
FROM DEMO_CLOUDTRAIL_RAW d,
     LATERAL FLATTEN(input => d.raw:records) r;

-- ---------------------------------------------------------------------
-- 5a. JSON embedded as a string inside JSON -> TRY_PARSE_JSON at query time.
--     The second line is not JSON: TRY_PARSE_JSON returns NULL instead of failing.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DEMO_APP (raw VARIANT, src_file STRING);
COPY INTO DEMO_APP
  FROM (SELECT $1, METADATA$FILENAME
        FROM @INGEST_DEMO (FILE_FORMAT => 'FF_JSON', PATTERN => '.*app_embedded[.]json.*'));
SELECT raw:timestamp::TIMESTAMP_TZ AS ts,
       raw:host::STRING            AS host,
       TRY_PARSE_JSON(raw:message::STRING)            AS msg,
       TRY_PARSE_JSON(raw:message::STRING):user::STRING   AS user_name,
       TRY_PARSE_JSON(raw:message::STRING):action::STRING AS action,
       raw:message::STRING         AS message_text
FROM DEMO_APP;

-- ---------------------------------------------------------------------
-- 5b. JSON inside a CSV column -> parse during the load into VARIANT.
-- ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DEMO_APP_CSV (ts TIMESTAMP_TZ, payload VARIANT, src_file STRING);
COPY INTO DEMO_APP_CSV
  FROM (SELECT $1, TRY_PARSE_JSON($2), METADATA$FILENAME
        FROM @INGEST_DEMO (FILE_FORMAT => 'FF_CSV', PATTERN => '.*app_embedded[.]csv.*'));
SELECT ts, payload:user::STRING AS user_name, payload:action::STRING AS action FROM DEMO_APP_CSV;

-- Cleanup
-- DROP TABLE IF EXISTS DEMO_IOC; DROP TABLE IF EXISTS DEMO_DNS; DROP TABLE IF EXISTS DEMO_O365;
-- DROP TABLE IF EXISTS DEMO_CLOUDTRAIL_RAW; DROP TABLE IF EXISTS DEMO_APP; DROP TABLE IF EXISTS DEMO_APP_CSV;
-- DROP STAGE IF EXISTS INGEST_DEMO; DROP FILE FORMAT IF EXISTS FF_JSON_ARRAY;
