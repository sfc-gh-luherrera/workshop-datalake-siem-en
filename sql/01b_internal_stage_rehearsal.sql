-- =====================================================================
-- 01b · NO-AWS ALTERNATIVE: internal stage with the same name (S3_LOGS)
-- Use it to rehearse the workshop without a bucket. Scripts 02-08 do not change.
-- Upload files: python generator/upload_internal.py --dir ./out
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.BRONZE;

CREATE STAGE IF NOT EXISTS S3_LOGS DIRECTORY = (ENABLE = TRUE)
  COMMENT = 'Rehearsal: internal stage that simulates s3://workshop-datalake-siem';

CREATE FILE FORMAT IF NOT EXISTS FF_JSON TYPE = JSON STRIP_OUTER_ARRAY = FALSE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_LINES TYPE = CSV FIELD_DELIMITER = NONE RECORD_DELIMITER = '\n'
  ESCAPE_UNENCLOSED_FIELD = NONE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_CSV TYPE = CSV SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '"'
  EMPTY_FIELD_AS_NULL = TRUE COMPRESSION = AUTO;
