# Evaluator Guide · Security Data Lake on Snowflake

In this lab you will build, in your own Snowflake account, a security data lake on top of logs
that live in an S3 bucket (or, if you don't have AWS at hand, in a Snowflake internal stage).
You will start from compressed DNS, NetFlow, IDS, Active Directory, firewall, Office 365 and SIM
change request files, and you will finish with SQL detections, hunting over a year of data, an
anomaly model, a fraud model, AI alert triage, a conversational agent, a dashboard and governance
policies that decide who sees what.

All the data is synthetic. It is produced by a script included in the repository, which
deliberately seeds several security incidents so you have something concrete to find. The full
lab takes two to three hours, plus the time to prepare the environment.

The guide is designed for technical security profiles who have never worked with Snowflake.
Every time a new concept appears, we explain it briefly in a box.

> **Snowsight** is the Snowflake web interface. From it you write SQL, explore objects, manage
> permissions and run applications and agents. Except for generating the data, the whole lab is
> done from the browser.

## Contents

1. Prerequisites
2. Step 0 · Get the code and generate the data
3. Step 1 · Prepare the account
4. Module 1 · The platform: navigation, compute and roles
5. Module 2 · The logs in the bucket: explore, query in place and load
6. Module 3 · Normalization and layered model
7. Module 4 · Detection and hunting over a year
8. Module 5 · SIM swap fraud with ML
9. Module 6 · AI for the SOC: triage, runbooks, agent, MCP and dashboard
10. Module 7 · Governance and auditing
11. Optional reading · Coexistence with Splunk
12. Common issues
13. Cleanup
14. Answer key: seeded incidents

---

## Prerequisites

| Item | Detail |
|---|---|
| Snowflake account | Enterprise edition or higher. An AWS region in the EU is recommended (for example `eu-west-3`, Paris, or `eu-central-1`, Frankfurt). If you don't have an account, you can open a trial one. |
| Role | `ACCOUNTADMIN` for scripts `00` and `01`, which create roles, the S3 integration and account permissions. The rest runs with the `SOC_ADMIN` role that the lab itself creates. |
| Cortex (AI) | The language models must be available in your region or cross-region inference must be enabled. We check this in step 1. |
| Cortex Code | Snowsight's AI assistant, used to build the ML models and the masking with the prompts in `prompts/`. If you don't have it available, each step has an alternative script. |
| AWS (optional) | Permissions to create an S3 bucket, a policy and an IAM role. If you don't have AWS, you will use an internal stage and the result is the same. |
| Local machine | Python 3.10 or higher and `git`. For the no-AWS option, a configured Snowflake connection (for example with Snowflake CLI, in `~/.snowflake/connections.toml`). |

Consumption is small: the dataset takes about 50 MB compressed and all queries run on an XSMALL
warehouse in a few seconds. Even so, the lab creates a resource monitor that caps spending at 50
credits.

---

## Step 0 · Get the code and generate the data

Clone or download the lab repository. Its structure is as follows:

| Path | What it is |
|---|---|
| `generator/` | Synthetic log generator and upload script to an internal stage |
| `sql/` | Setup scripts and per-module scripts, numbered in execution order |
| `sql/demo_snippets/` | The queries of each step, standalone, to paste into Snowsight |
| `sql/backup/` | Backup script that creates the ML models if you don't use Cortex Code |
| `prompts/` | Prompts for Cortex Code: anomaly ML, fraud ML and masking |
| `streamlit/` | SOC dashboard code |
| `runbooks/` | Synthetic runbooks that the AI will query |

### The dataset

The `generator/generate_logs.py` script simulates thirteen months of activity (395 days, from
September 22, 2025 to October 21, 2026) in an organization with three business units:
UES (Spain), UDE (Germany) and UBR (Brazil). It uses a fixed random seed (`SEED = 42`), so it
always produces exactly the same files and your results will match the ones in this
guide.

It generates seven sources, each in the format it would have in real life:

| Source | Format | Approximate daily volume | What it simulates |
|---|---|---|---|
| `dns` | JSON lines | 2,000 queries | Queries from internal hosts to the DNS resolver |
| `netflow` | JSON lines | 2,000 flows | Network connections from internal hosts to the Internet |
| `suricata` | JSON (EVE) | 60 alerts | Alerts from a network IDS |
| `ad` | JSON | 600 events | Windows and Active Directory logons (4624, 4625, 4672) |
| `fw` | Text syslog | 1,200 lines | Firewalls and VPN from four different vendors |
| `o365` | JSON | 300 events | Office 365 auditing (file access and downloads) |
| `sim` | CSV | 150 requests | SIM change, porting and in-store activation requests |

It also generates an indicators of compromise file (`ioc/ioc_feed.csv.gz`) with 55 entries and
copies the runbooks from `runbooks/` so the AI can query them. Each source is written to one
gzip file per day with the path `<source>/YYYY/MM/DD/<source>_YYYYMMDD.<extension>.gz`, which is
the usual layout of a log bucket and the one that lets you query or load just one month or one
day. In total there are about 2.5 million events.

On top of that background traffic, the generator inserts several incidents. We don't tell you
about them here so that you find them yourself; if you get stuck, they are at the end, in the answer key.

> **Stage.** In Snowflake, a *stage* is a named pointer to a file location. It can be
> *external* (it points to an S3, Azure or GCS bucket that is still yours) or *internal*
> (Snowflake stores the files for you). On a stage you can list files, query them
> directly with SQL or load them into tables. In both cases, the lab calls it
> `SECURITY_LAKE.BRONZE.S3_LOGS`, so the later scripts don't change.

### Option A: with your own S3 bucket

1. Create a bucket in the same region as your Snowflake account and block public access. In
   this guide we call it `<your-bucket>`.
2. Create an IAM policy with read access on the bucket, with write access only to the `exports/`
   folder (we will use it to export results):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": "arn:aws:s3:::<your-bucket>/*" },
       { "Effect": "Allow",
         "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": "arn:aws:s3:::<your-bucket>" },
       { "Effect": "Allow",
         "Action": ["s3:PutObject", "s3:DeleteObject"],
         "Resource": "arn:aws:s3:::<your-bucket>/exports/*" }
     ]
   }
   ```

3. Create an IAM role with that policy. You will complete the trust policy in step 1, when
   Snowflake gives you its identifiers.
4. Generate the data and upload it (you need AWS credentials with write permission, for example
   via `aws configure`):

   ```bash
   cd generator
   pip install -r requirements.txt
   python generate_logs.py --upload --bucket <your-bucket>
   ```

### Option B: without AWS, with an internal stage

If you don't have AWS, generate the files on disk and upload them to Snowflake. The upload script
uses the Snowflake Python connector, which is installed with the rest of the dependencies:

```bash
cd generator
pip install -r requirements.txt
python generate_logs.py --local ./out
```

The upload (`upload_internal.py`) is done after creating the stage, in step 1.

In both options, the `--scale` parameter lets you multiply the volume (for example,
`--scale 0.5` generates half). The figures in this guide correspond to the default scale.

---

## Step 1 · Prepare the account

Open Snowsight, go to Projects > Workspaces and create a SQL file. In it you will paste and run
the scripts from the `sql/` directory. To run a whole script, paste its content and use
"Run all"; to run a single query, place the cursor on it and press Ctrl+Enter
(Cmd+Enter on Mac).

### 1.1 Check Cortex

As `ACCOUNTADMIN`, check the region and that the language model used by the lab
responds:

```sql
SELECT CURRENT_REGION(), CURRENT_VERSION();
SHOW PARAMETERS LIKE 'CORTEX_ENABLED_CROSS_REGION' IN ACCOUNT;
-- Optional: restrict Cortex inference to EU regions
ALTER ACCOUNT SET CORTEX_ENABLED_CROSS_REGION = 'AWS_EU';
SELECT AI_COMPLETE('claude-sonnet-4-5', 'say hello');
```

If the last query fails because the model is not available, change the model in
`sql/07_ai_triage.sql` to one available in your region.

### 1.2 Roles, warehouse and database (`sql/00_admin_roles_wh.sql`)

Run script `00` with `ACCOUNTADMIN`. It creates the `SECURITY_LAKE` database with its schemas,
the `SOC_WH` warehouse, the `SOC_ADMIN`, `SOC_ANALYST` and `THREAT_HUNTER` roles, the resource
monitor `SOC_MONITOR` and the required permissions, including `EXECUTE DATA METRIC FUNCTION`.

> **Database and schema.** A Snowflake *account* contains *databases*, each database
> contains *schemas* and each schema contains tables, views and other objects. Here we use
> `SECURITY_LAKE` with four schemas: `BRONZE` (the logs as they arrive), `SILVER`
> (normalized), `GOLD` (detections and alerts) and `GOVERNANCE` (policies).

### 1.3 Connect to the files

**Option A (S3).** Edit `sql/01_s3_integration_stage.sql` before running it: replace
`<AWS_ACCOUNT_ID>` and the IAM role name in `STORAGE_AWS_ROLE_ARN`, and change
`workshop-datalake-siem` to `<your-bucket>` in `STORAGE_ALLOWED_LOCATIONS` and in the stage
`URL`. Run it with `ACCOUNTADMIN`. Then get the identifiers that Snowflake will use to
assume your role:

```sql
DESC INTEGRATION S3_SIEM_INT;
```

Copy `STORAGE_AWS_IAM_USER_ARN` and `STORAGE_AWS_EXTERNAL_ID` into the trust policy of the IAM
role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "<STORAGE_AWS_IAM_USER_ARN>" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<STORAGE_AWS_EXTERNAL_ID>" } }
  }]
}
```

> **Storage integration.** It is the object that holds the trust relationship between Snowflake
> and your AWS account. Instead of storing access keys, Snowflake assumes an IAM role that you
> control, presenting a unique external identifier. You can revoke access at any
> time from AWS by removing the trust policy.

**Option B (internal stage).** Run `sql/01b_internal_stage_rehearsal.sql`. It creates the
internal stage `S3_LOGS` with the same structure and the file formats. Then, from your machine,
upload the generated files:

```bash
python upload_internal.py --dir ./out --connection <your-connection>
```

**Check.** In both cases, this query should list files:

```sql
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/dns/2026/10/;
```

### 1.4 Build the rest of the lab (`sql/02` to `sql/08`)

Run scripts `02` to `05` in order with the `SOC_ADMIN` role. They load the bronze layer,
build the silver and gold layers, create the detections and prepare the hunting. On an
XSMALL warehouse each takes a few minutes.

Next, run `sql/backup/ml_backup_models.sql` (about a minute). It creates the two
ML models and their results (`GOLD.EGRESS_ANOMALIES`, `GOLD.NET_ANOMALIES` and `GOLD.SIM_SCORED`).
In modules 4 and 5 you will build them again yourself with Cortex Code, with the same names;
this backup guarantees that the following scripts have data even if something fails. It must run
before `06` to `08`: `06` queries the fraud model, `07` and the dashboard read its results and
`08` masks `SIM_SCORED.msisdn`.

Finally, run `06` to `08`, which prepare the AI and apply governance. The modules that follow
walk through what they create, explaining each piece and repeating their key queries. Script `09` (clone
and Time Travel) and `sql/demo_snippets/share.sql` are not part of the preparation: you will run them
in modules 4 and 3.

> **Cortex Code.** It is Snowflake's AI assistant for data engineering: it takes a
> natural-language request, explores the objects in the account, writes the SQL, runs it with your
> active role and explains the result. Each file in `prompts/` has, per step, the prompt to
> paste, the expected result and a checkpoint query.

If you use option A, in `sql/02_bronze_load.sql` you can uncomment the block for the external
table `DNS_EXT`; it only works with an external stage.

---

## Module 1 · The platform: navigation, compute and roles

**Goal:** get your bearings in Snowsight and understand how storage, compute and
permissions are separated.

### 1.1 Navigation

On the Snowsight home page, go through the left menu: Projects, Ingestion,
Transformation, AI & ML, Monitoring, Apps, Catalog, Governance & security, Compute and Admin.
Everything is a managed service: there are no servers, patches or indexes to operate. Data is
encrypted at rest with AES-256 and in transit with TLS.

It should look like this:

### 1.2 Elastic compute

In Compute > Warehouses open `SOC_WH`. It is XSMALL in size, auto-suspends after 60
seconds of inactivity and can grow from one to three clusters if there are many concurrent queries.

> **Warehouse.** In Snowflake, a *virtual warehouse* is not a data store, but a compute
> cluster that runs queries. The data is stored separately, so you can have
> several warehouses of different sizes reading the same data without copying it. You pay per
> second while the warehouse is running, and it shuts down by itself when nobody uses it.

In a SOC this lets you isolate workloads. Think of the morning shift: the hunting
team launches a search over twelve months of NetFlow right when the hourly detection task
runs. With one warehouse for each (for example, a small `DETECT_WH` for the tasks and a
larger `HUNT_WH` that is only on when someone is hunting), neither slows the other down. The lab
uses a single `SOC_WH` for simplicity.

There are two ways to grow. *Scaling up* (from XSMALL to LARGE) speeds up a heavy query; you
will do it in module 4. *Scaling out* (multi-cluster, from one to three clusters on `SOC_WH`)
does not speed up any single query, but absorbs concurrency when many analysts query at
the same time. Multi-cluster requires Enterprise edition or higher.

> **Auto-suspend and per-second billing.** A warehouse suspends by itself after the configured
> idle time (here, 60 seconds) and resumes by itself with the next query. It is
> billed per second, with a minimum of 60 seconds each time it starts.

The cost guardrail is the `SOC_MONITOR` resource monitor, which you will see in module 7: if someone
leaves a large warehouse running, it notifies at 80% of the budget and suspends it at 100%.

**Challenge.** Without running it, write the `CREATE WAREHOUSE` for a LARGE `HUNT_WH` that
suspends after 60 seconds and starts suspended. A 5-second search on that stopped
warehouse: how many seconds of compute does it bill?

### 1.3 Roles

The lab has three roles: `SOC_ANALYST`, which sees the SILVER and GOLD layers; `THREAT_HUNTER`,
which also sees the original logs in BRONZE; and `SOC_ADMIN`, which administers the environment.
Switch roles in the selector in the bottom-left corner and watch how the visible objects change in
Catalog.

> **Roles.** In Snowflake, permissions are never granted directly to a person, but to a *role*,
> and the user works with the role that is active. A user can also have *secondary
> roles*, whose permissions add to those of the primary role. This will be important in the
> governance module.

**Challenge.** With the `SOC_ANALYST` role, try to query `SECURITY_LAKE.BRONZE.DNS_RAW`. What error
do you get and why?

---

## Module 2 · The logs in the bucket: explore, query in place and load

**Goal:** see that Snowflake works on the files you already have, without moving them, and
learn the two ways of using them: query them in place or load them.

### 2.1 Explore the stage from the interface

In Catalog > Database Explorer > `SECURITY_LAKE` > `BRONZE` > Stages, open `S3_LOGS`. You will see
one folder per source: `ad`, `dns`, `fw`, `ioc`, `netflow`, `o365`, `runbooks`, `sim` and `suricata`.

Go into `dns/2026/10/` and look at the size of each day's files. Does any of them
stand out? Note the dates: you will come back to them.

### 2.2 How it connects

If you use S3, review the integration again and locate the `STORAGE_AWS_ROLE_ARN` and
`STORAGE_AWS_EXTERNAL_ID` fields:

```sql
USE ROLE SOC_ADMIN;
DESC INTEGRATION S3_SIEM_INT;
```

### 2.3 List files with SQL

```sql
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/dns/2026/10/;
```

`LIST` returns the files in that folder with their size and modification date, just as the
AWS console would, but from SQL.

### 2.4 Inventory with SQL

```sql
USE SCHEMA SECURITY_LAKE.BRONZE;
SELECT SPLIT_PART(relative_path,'/',1) AS source,
       COUNT(*) AS files,
       ROUND(SUM(size)/1024/1024,1) AS mb
FROM DIRECTORY(@S3_LOGS)
GROUP BY 1 ORDER BY mb DESC;
```

> **Directory table.** A stage can have an associated directory table, which is a catalog
> of its files (path, size, date) that can be queried with normal SQL via `DIRECTORY(@stage)`.

**Expected result:** 395 daily files per source, one per day for thirteen months; netflow
is the heaviest source, at about 22 MB.

### 2.5 Query in place, without loading

Directly query the DNS files of one of the days that caught your attention in step
2.1 (here, October 15), filtering queries with very long names:

```sql
SELECT $1:ts::TIMESTAMP_NTZ AS ts, $1:client_ip::STRING AS host,
       $1:query::STRING AS query, METADATA$FILENAME AS file
FROM @S3_LOGS/dns/2026/10/15/ (FILE_FORMAT => 'FF_JSON')
WHERE LENGTH($1:query::STRING) > 40
LIMIT 20;
```

> **Querying a stage.** Snowflake can read files directly from a stage, without
> loading them into a table. `$1` represents the content of each line, the `$1:field` notation
> extracts a field from the JSON and `::TYPE` casts the value to a data type. The *file format*
> `FF_JSON` tells Snowflake how to interpret the files (in this case, gzip-compressed
> JSON).

**Food for thought:** what do the queried names have in common, and what attack technique do they suggest?

### 2.6 Load with COPY

```sql
CREATE OR REPLACE TABLE DNS_RAW_DEMO (raw VARIANT, src_file STRING,
                                      loaded_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP());
COPY INTO DNS_RAW_DEMO (raw, src_file)
  FROM (SELECT $1, METADATA$FILENAME FROM @S3_LOGS/dns/2026/10/)
  FILE_FORMAT = (FORMAT_NAME = 'FF_JSON');
```

> **VARIANT and COPY INTO.** `VARIANT` is a column type that stores JSON (or other
> semi-structured data) as is, without defining its schema beforehand, and that is later queried
> with the same `raw:field` notation. `COPY INTO` is the bulk load command from a stage into a
> table.

**Expected result:** 21 files with status `LOADED` and no errors. Run the `COPY` again:
it loads nothing, because `COPY` remembers which files it has already loaded and is therefore
idempotent. The `src_file` column stores the source file of each row, which gives traceability
back to the bucket object.

Query the load history:

```sql
SELECT file_name, row_count, error_count, status, last_load_time
FROM TABLE(INFORMATION_SCHEMA.COPY_HISTORY(TABLE_NAME=>'DNS_RAW_DEMO',
     START_TIME=>DATEADD(hour,-1,CURRENT_TIMESTAMP())));
```

In production there are three common ways to use the files in a bucket: a `COPY` scheduled
with a task; Snowpipe with auto-ingest, which loads each new file as soon as S3 notifies it; or
external and Iceberg tables, which query the files without copying them.

The choice depends on how much latency each source tolerates:

| SOC source | How it arrives | Mechanism | Typical latency |
|---|---|---|---|
| Firewall logs exported every night to S3 | Daily files | `COPY INTO` scheduled with a task (`LOAD_DNS_DAILY` in script `02`) | hours |
| Proxy or VPN logs landing in S3 every few minutes | Small, continuous files | Snowpipe with auto-ingest | minutes |
| EDR telemetry published to Kafka | Messages, not files | Snowpipe Streaming with the Snowflake Connector for Kafka | seconds |

> **Snowpipe and Snowpipe Streaming.** *Snowpipe* is a continuous loading service without a warehouse: S3
> notifies each new file and Snowflake loads it with the same `COPY`. *Snowpipe Streaming* does not
> work with files, but with rows: a client (for example, the Kafka connector) writes the
> events directly into the table and they become queryable within seconds.

Open `sql/02_bronze_load.sql` and look at how the load is written to be robust: one
`COPY` per source with an explicit `PATTERN`, never `FORCE = TRUE` (load metadata prevents
duplicates for 64 days), a 15-minute cap per statement with
`STATEMENT_TIMEOUT_IN_SECONDS = 900` and a final block with `LOAD_HISTORY` that shows which source
has pending files or errors. If something fails, only that source's `COPY` is relaunched.
Each row stores `METADATA$FILENAME` in `src_file`, so you can always go back to the exact object
in the bucket.

### 2.7 The complete bronze layer

Script `02` already loaded all the sources. Check the volumes:

```sql
SELECT 'dns' t, COUNT(*) FROM DNS_RAW UNION ALL SELECT 'netflow', COUNT(*) FROM NETFLOW_RAW
UNION ALL SELECT 'fw', COUNT(*) FROM FW_RAW UNION ALL SELECT 'ad', COUNT(*) FROM AD_RAW
UNION ALL SELECT 'o365', COUNT(*) FROM O365_RAW UNION ALL SELECT 'sim', COUNT(*) FROM SIM_REQUESTS
UNION ALL SELECT 'suricata', COUNT(*) FROM SURICATA_RAW UNION ALL SELECT 'ioc', COUNT(*) FROM IOC;
```

**Expected result:** about 2.5 million events: 793,040 DNS, 790,050 NetFlow, 473,566
firewall, 237,062 Active Directory, 119,000 Office 365, 59,325 SIM requests, 23,701
Suricata alerts and 55 indicators of compromise.

**Challenge.** You have a two-year CloudTrail archive in S3 that you query twice a month. Would
you load it or query it in place? Both answers are valid: querying it in place avoids
duplicating storage and loading it makes queries faster. It is decided source by source.

**Challenge.** Adapt the query from step 2.5 to count, per day of October, how many DNS queries
are longer than 40 characters, reading the files in place.

**Challenge.** Run the verification block at the end of `sql/02_bronze_load.sql`. Which source
has pending files or errors? Run the script's `DNS_RAW` `COPY` again: how many
rows does it load and why?

**Challenge.** Classify these sources by ingestion mechanism (scheduled `COPY`, Snowpipe or Snowpipe
Streaming): daily Office 365 audit exported to S3, EDR alerts on a Kafka topic and
proxy logs written to S3 every five minutes.

---

## Module 3 · Normalization and layered model

**Goal:** understand how heterogeneous logs are turned into a common model that maintains
itself (script `sql/03_silver_normalize.sql`).

JSON logs are stored in `VARIANT` columns and queried with paths such as
`raw:alert.signature`, while the firewall syslog is free text that is parsed
with regular expressions (`REGEXP_SUBSTR`) inside the `NETWORK_ACTIVITY` table.

The layers have a clear role. BRONZE keeps the logs intact, which enables forensic
analysis. SILVER normalizes them following the OCSF model (Open Cybersecurity Schema Framework).
GOLD contains the detections and alerts. Snowflake does not ship its own security data model:
you adopt a standard such as OCSF, implemented as views or dynamic tables.

### 3.1 Dynamic tables and lineage

In Catalog > `SILVER` > Dynamic tables, open `NETWORK_ACTIVITY` and review the Graph tab.

> **Dynamic table.** It is a table defined by a SQL query that Snowflake keeps
> up to date automatically. Instead of writing an ETL process with an orchestrator, you declare
> how much lag is tolerated with `TARGET_LAG` (here, one hour) and Snowflake decides when to refresh and
> processes only the new data.

The Lineage tab shows the lineage from BRONZE to SILVER and to GOLD, at table and column level.

### 3.2 Data quality

The Data quality tab shows the quality checks associated with the table: they count the
nulls in `EVENT_TIME` and `SRC_IP` every time the table changes.

> **Data Metric Functions (DMF).** They are data quality functions (number of nulls, of
> duplicates, freshness, etc.) that are associated with a table and that Snowflake runs on a
> schedule or every time the table changes, keeping the history of results.

If the checks show no results ("No checks"), the table has not been refreshed yet since
they were associated. Force a refresh:

```sql
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.NETWORK_ACTIVITY REFRESH;
```

### 3.3 Reprocessing and lifecycle

If a parser changes, you just redefine the dynamic table so that it recomputes the whole history
from the original BRONZE data. For the lifecycle, the script applies the
`SLP_RAW_1Y_COOL` policy, which keeps the data queryable for one year and then archives it in
COOL storage for five years. The policy takes about 24 hours to run for the first
time.

> **Storage lifecycle policy.** It is a policy that Snowflake automatically applies to the rows
> of a table based on their age, either to delete them or to move them to cheaper archive
> storage.

At the end of the retention section, script `03` leaves a COLD variant commented out,
`SLP_RAW_90D_COLD`, intended for logs that after some time are only requested for a legal requirement
or a forensic analysis. COLD costs roughly a quarter of COOL, but requires a minimum of
180 days in archive, is only available on AWS and GCP and retrieval can take up to 48
hours. Archived data is not queried directly: it is restored to a new table with
`CREATE TABLE ... FROM ARCHIVE OF ...` and a mandatory `WHERE`. Do not run it on `DNS_RAW`: the
archive tier of a table cannot be changed once assigned.

### 3.4 Share IOCs with another team

Imagine that the group CSIRT, or another country's SOC, wants to see today the IOC matches
your SOC has found. Instead of exporting a CSV, you publish a secure view with only the
aggregates per indicator and share it live. Run `sql/demo_snippets/share.sql` (about 7
seconds; the share part requires `ACCOUNTADMIN`):

```sql
USE ROLE SOC_ADMIN;
CREATE OR REPLACE SECURE VIEW SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE AS
SELECT indicator, class, unit, MAX(confidence) AS confidence, COUNT(*) AS hits,
       COUNT(DISTINCT src_ip) AS affected_hosts, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS GROUP BY indicator, class, unit;

USE ROLE ACCOUNTADMIN;
CREATE SHARE IF NOT EXISTS SOC_IOC_SHARE COMMENT = 'IOCs detected by the SOC';
GRANT USAGE ON DATABASE SECURITY_LAKE TO SHARE SOC_IOC_SHARE;
GRANT USAGE ON SCHEMA SECURITY_LAKE.GOLD TO SHARE SOC_IOC_SHARE;
GRANT SELECT ON VIEW SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE TO SHARE SOC_IOC_SHARE;
SHOW GRANTS TO SHARE SOC_IOC_SHARE;
```

> **Secure Data Sharing.** A *share* gives another Snowflake account read-only access to specific
> objects, without copying data or moving files: the consumer queries the current version and the
> provider can revoke it at any time. A *secure view* hides its definition from the
> consumer and is required to share views. Across different regions or clouds a
> *listing* is used.

**Expected result:** `SHOW GRANTS TO SHARE` shows usage on the database and the schema and
`SELECT` on the view, and nothing else. To add a consumer account you would use
`ALTER SHARE SOC_IOC_SHARE ADD ACCOUNTS = <ORG>.<ACCOUNT>`; don't do it if you don't have a second
account. Open the view in Catalog and review its owner, its comment and its tags: that is what
the other team would see when they find it.

**Challenge.** Why does the shared view aggregate per indicator and not include `src_ip`? What would you have to
change so the CSIRT only sees the matches of the UES unit?

**Challenge.** Open `sql/03_silver_normalize.sql`, find how the firewall syslog fields are
extracted with `REGEXP_SUBSTR` and write a query on `BRONZE.FW_RAW` that extracts the destination
port (`dport=`) of each line.

---

## Module 4 · Detection and hunting over a year

**Objective:** write detections as SQL code, cross threat intelligence (CTI) with a year of
events, build with Cortex Code an ML model that detects anomalies, test rule changes
on a clone, undo mistakes with Time Travel and run everything on a schedule (scripts
`sql/04_gold_detections.sql`, `sql/05_hunting_1y.sql` and `sql/09_timetravel_clone.sql`, and
`prompts/ml_egress_anomalies.md`).

### 4.1 Detections in SQL

Each detection is a view in the GOLD schema. Query `DET_BRUTE_FORCE`,
`DET_BRUTE_FORCE_SUCCESS`, `DET_DNS_TUNNEL`, `DET_EXFIL`, and `DET_O365_MASS_DOWNLOAD` one by one,
and open their definitions in Catalog to see how they are written. `DET_BRUTE_FORCE_SUCCESS` does
not count failures: it looks for a complete sequence.

> **MATCH_RECOGNIZE.** A standard SQL clause for finding patterns in sequences of ordered rows,
> similar to a regular expression but applied to events. Here it looks for "several failures,
> followed by a success, followed by a privilege escalation" for the same user.

The DNS tunnel detection closes the lead you found in the bucket:

```sql
SELECT src_ip, query_domain, day, queries, distinct_labels,
       ROUND(avg_label_len,1) AS avg_len, unit
FROM SECURITY_LAKE.GOLD.DET_DNS_TUNNEL ORDER BY day;
```

**Think about it:** do the days match the large files you saw in module 2?

### 4.2 Threat intelligence over twelve months

```sql
SELECT class, COUNT(*) AS hits, MIN(event_time) AS first_seen,
       MAX(event_time) AS last_seen, COUNT(DISTINCT src_ip) AS hosts
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS GROUP BY class ORDER BY hits DESC;
```

This view crosses the feed's indicators with the whole year of events.

**Expected result:** 3,040 matches in DNS, 562 in authentication, and 50 in network traffic.
Look at the `first_seen` column for DNS: how many months back was the first contact? With a
retention of 30 to 90 days, that case could not be seen.

Also query `GOLD.DET_SOURCE_SILENT`, which warns when a source has not sent logs for more than
twelve hours. Missing data is also an incident.

### 4.3 Anomaly ML with Cortex Code

The `DET_EXFIL` rule has fired. Is it the only case, or are there more subnets sending out more data than normal?
You are going to build an anomaly detection model without writing SQL by hand. Open Cortex Code with
the `SOC_ADMIN` role and the `SOC_WH` warehouse, and paste one by one the five prompts in
`prompts/ml_egress_anomalies.md`. After each one, run the file's checkpoint
query.

| Prompt | What it asks | Expected result |
|---|---|---|
| 1 | Discover the network table | `SILVER.NETWORK_ACTIVITY`; only `netflow` carries `bytes_out` (about 790,000 rows) |
| 2 | Daily series per /24 subnet in the view `GOLD.NET_DAILY_SUBNET`, materialized into `GOLD.EGRESS_DAILY_SUBNET` | 9 subnets, 395 days, 3,555 points; 3,510 before October 17 |
| 3 | Train `GOLD.NET_ANOMALY_MODEL` with the days before October 17 | `Instance NET_ANOMALY_MODEL successfully created` |
| 4 | Detect from October 17 and save into `GOLD.EGRESS_ANOMALIES` | 45 rows and 2 anomalies |
| 5 | Explain the columns and plot observed vs. expected band | 10.20.8 goes off the scale on October 17 |

> **ML Functions.** Snowflake includes machine learning functions that are trained and used with
> SQL, without writing data science code. Here we use the anomaly detection one: it learns the
> normal behavior of a time series and flags values that fall outside the expected interval.

When you finish, review the result:

```sql
SELECT series, ts, ROUND(y/1e6,1) AS mb_out, ROUND(forecast/1e6,1) AS mb_expected,
       ROUND(upper_bound/1e6,1) AS mb_upper, ROUND(y/forecast) AS x_over_forecast
FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES WHERE is_anomaly ORDER BY x_over_forecast DESC;
```

**Expected result:** two anomalies. The first one, very prominent: subnet 10.20.8 on October
17, with about 5,374 MB outbound versus about 5.3 MB forecast (about 1,000 times more). The
second, smaller one (10.20.9 on October 19, 8.9 MB versus an upper bound of 8.2 MB) is a false
positive. The model prioritizes; the analyst still makes the decision.

So the rest of the lab reads your results, refresh the compatibility table:

```sql
CREATE OR REPLACE TABLE SECURITY_LAKE.GOLD.NET_ANOMALIES COPY GRANTS AS
SELECT * FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES;
```

**If you don't have Cortex Code or something fails:** the same objects already exist, because
`sql/backup/ml_backup_models.sql` created them in step 1.4. Run the previous query directly. If
Cortex Code trains on the view and returns `input_data is empty`, it is the row access policy
`RAP_BY_UNIT`, which filters everything out inside training: ask it to train on the table
`EGRESS_DAILY_SUBNET`.

**Challenge.** Ask Cortex Code to repeat the detection with `prediction_interval` 0.99 instead of
0.999. How many anomalies show up now and what does that tell you about the threshold?

### 4.4 Operations: alerts and scheduled tasks

```sql
SELECT detection, COUNT(*) AS alerts, MIN(event_time) AS first_ev,
       MAX(event_time) AS last_ev, COUNT_IF(triage IS NOT NULL) AS triaged
FROM SECURITY_LAKE.GOLD.ALERTS GROUP BY detection ORDER BY alerts DESC;

SHOW TASKS IN SCHEMA SECURITY_LAKE.GOLD;
```

> **Task.** A *task* is a Snowflake scheduled job that runs SQL or a procedure on a schedule
> (with cron syntax) or when new data arrives. It replaces cron or an external orchestrator.

**Expected result:** ten alerts spread across five detections, all already prioritized with AI.
The `DETECTIONS_HOURLY` task calls the `RUN_DETECTIONS()` procedure every hour, which runs the
detections and writes the new alerts. It is suspended so it does not consume credits; it would be
activated with `ALTER TASK SECURITY_LAKE.GOLD.DETECTIONS_HOURLY RESUME`. The script also includes
the `SOURCE_SILENT_ALERT` alert, which sends an email when a source stops sending.

### 4.5 Test a rule change on a clone

The night shift complains about noise and proposes raising the DNS tunnel threshold from 200 to 2,000
distinct labels per day. Before touching production, clone the whole lake and test the change on
the clone. Run block A1 of `sql/09_timetravel_clone.sql`:

```sql
USE ROLE SYSADMIN;
CREATE DATABASE SECURITY_LAKE_DEV CLONE SECURITY_LAKE;
GRANT OWNERSHIP ON DATABASE SECURITY_LAKE_DEV TO ROLE SOC_ADMIN COPY CURRENT GRANTS;
USE ROLE SOC_ADMIN;
SHOW DYNAMIC TABLES IN DATABASE SECURITY_LAKE_DEV;
SHOW TASKS IN DATABASE SECURITY_LAKE_DEV;
```

> **Zero-Copy Clone.** A clone is an instant copy of a database, a schema or a
> table that does not duplicate the data: it shares storage with the original and you only pay for what
> changes afterward.

**Expected result:** the clone takes about 28 seconds. The dynamic tables show up in
`SUSPENDED` state and the tasks as `suspended`: the clone does not run anything on its own. Careful: the dynamic
tables and views use fully qualified names (`SECURITY_LAKE....`), so if you resume them they would read from
production.

Continue with the script: redefine `SECURITY_LAKE_DEV.GOLD.DET_DNS_TUNNEL` with the 2,000 threshold, delete
the clone's tunnel alerts, run `CALL RUN_DETECTIONS();` and compare with production:

```sql
SELECT detection, COUNT_IF(env = 'PROD') AS prod, COUNT_IF(env = 'DEV') AS dev
FROM (SELECT 'PROD' AS env, detection FROM SECURITY_LAKE.GOLD.ALERTS
      UNION ALL SELECT 'DEV', detection FROM SECURITY_LAKE_DEV.GOLD.ALERTS)
GROUP BY 1 ORDER BY 1;
```

**Think about it:** which detection changes and which incident disappears? Would you promote the change?

### 4.6 Undo a mistake with Time Travel

Mid-shift someone runs a `DELETE` without the right filter and empties the queue of open
alerts. Run block A2 of script `09`, always on the clone:

```sql
USE SCHEMA SECURITY_LAKE_DEV.GOLD;
SELECT SYSTEM$WAIT(60);            -- only if you just created the clone
SET t_before = CURRENT_TIMESTAMP();
DELETE FROM ALERTS WHERE status = 'NEW';
SET q_delete = LAST_QUERY_ID();

SELECT (SELECT COUNT(*) FROM ALERTS) AS now_count,
       (SELECT COUNT(*) FROM ALERTS AT(OFFSET => -60)) AS sixty_seconds_ago,
       (SELECT COUNT(*) FROM ALERTS BEFORE(STATEMENT => $q_delete)) AS just_before_delete,
       (SELECT COUNT(*) FROM ALERTS AT(TIMESTAMP => $t_before)) AS at_t_before;
```

> **Time Travel.** Snowflake keeps previous versions of the data for a retention
> period (one day by default, up to 90 on Enterprise), so you can query a table
> as it was at an instant (`AT`), just before a specific statement (`BEFORE`), or
> recover a dropped table with `UNDROP`. After that period, permanent tables have seven
> days of Fail-safe, recoverable only by Snowflake Support.

Continue with the script: recover the rows with `INSERT INTO ALERTS SELECT * FROM ALERTS
BEFORE(STATEMENT => $q_delete) WHERE status = 'NEW'`, create a copy of the table as it was
with `CLONE ... BEFORE(STATEMENT => ...)`, drop it with `DROP TABLE` and recover it with `UNDROP TABLE`,
and review each table's retention in `INFORMATION_SCHEMA.TABLES`.

The script ends with a commented-out block that creates a forensic clone,
`SECURITY_LAKE_EVIDENCE_20261017`, with `CLONE SECURITY_LAKE AT(TIMESTAMP => ...)`: it freezes the lake
as it was before an incident, to keep it as read-only evidence. Its creation
is recorded in `QUERY_HISTORY` and `ACCESS_HISTORY`.

**Challenge.** Write the query that answers the incident report question: "which alerts
were in the queue at instant `$t_before`?".

**Challenge.** Why can `AT(OFFSET => -3600)` fail on the clone while `BEFORE(STATEMENT => ...)` does not?

### 4.7 Hunting

Run script `05` step by step. First, tag the session so you can measure your queries
afterward:

```sql
ALTER SESSION SET QUERY_TAG = 'workshop_hunting';
```

Search for a domain in a year of original, non-normalized logs:

```sql
SELECT raw:ts::TIMESTAMP_NTZ AS ts, raw:client_ip::STRING AS host, raw:query::STRING AS query, src_file
FROM SECURITY_LAKE.BRONZE.DNS_RAW
WHERE SEARCH(raw, 'update-check-srv.com')
ORDER BY ts;
```

Search for everything a host touched in twelve months, using the common `ALL_EVENTS` view, which
unions all sources:

```sql
SELECT class, COUNT(*) AS events, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.SILVER.ALL_EVENTS
WHERE (src_ip = '10.20.8.15' OR dst_ip = '10.20.8.15')
  AND event_time >= DATEADD('month', -12, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY class;
```

Compute the top destinations by volume for the year, note the time, change the warehouse to
LARGE, repeat the query, and go back to XSMALL:

```sql
SELECT dst_ip, COUNT(DISTINCT src_ip) AS hosts, SUM(bytes_out) AS bytes_out
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
WHERE source = 'netflow' AND event_time >= DATEADD('year', -1, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY dst_ip ORDER BY bytes_out DESC LIMIT 20;

USE ROLE SOC_ADMIN;
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'LARGE';
-- (repeat the previous query)
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'XSMALL';
```

Enable Search Optimization on the original DNS logs, repeat the domain search, and compare the
partitions scanned in the Query Profile:

```sql
ALTER TABLE SECURITY_LAKE.BRONZE.DNS_RAW ADD SEARCH OPTIMIZATION ON FULL_TEXT(raw), EQUALITY(raw:client_ip);
SHOW TABLES LIKE 'DNS_RAW' IN SCHEMA SECURITY_LAKE.BRONZE;
```

> **Search Optimization and Query Profile.** *Search Optimization* is a service that builds
> search structures on a table so that point lookups (an IP, a domain, a text string) do not have
> to scan it entirely. The `search_optimization_progress` column reaches 100 when they finish
> building. The *Query Profile* is the visual execution plan of a query, showing how much it read
> and where it spent its time. You open it from the query history.

Finally, export a result to the stage to share it with another team, and review what your
queries cost:

```sql
COPY INTO @SECURITY_LAKE.BRONZE.S3_LOGS/exports/ioc_hits_
  FROM (SELECT * FROM SECURITY_LAKE.GOLD.DET_IOC_HITS)
  FILE_FORMAT = (TYPE = CSV COMPRESSION = GZIP) HEADER = TRUE OVERWRITE = TRUE;
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/exports/;
```

The script ends by querying `QUERY_HISTORY` filtered by the `workshop_hunting` tag, with the
seconds and bytes of each query. Keep in mind that the dataset is small: queries take between
0.2 and 2 seconds and are not a measure of performance at scale.

**Challenge.** Write a new detection as a view in GOLD, for example, denied connections to port
22 by source IP and hour from `BRONZE.FW_RAW` (script `05` has a starting point with
`ILIKE '%action=deny%'`).

**Challenge.** Search `ALL_EVENTS` for everything related to another of the indicators in the
`BRONZE.IOC` table. Does it appear in more than one source?

---

## Module 5 · SIM swap fraud with ML

**Objective:** build with Cortex Code a classification model to prioritize suspicious SIM change
requests (`prompts/ml_sim_fraud.md`, with `sql/06_sim_swap_ml.sql` as
reference queries).

SIM swap consists of getting the carrier to move the victim's number to a SIM controlled by the
attacker, which lets them receive the bank's one-time codes. Requests before October 18 carry an
`is_fraud` label, used to train the model; later ones arrive unlabeled, and those are the ones the
model has to score.

> **Classification with ML Functions.** Like anomaly detection, the classification function is
> trained with a SQL query that tells it which column to predict (here, `is_fraud`) and then
> scores new rows with a probability. `SHOW_FEATURE_IMPORTANCE` shows which variables weigh most
> in the decision.

In Cortex Code, with `SOC_ADMIN` and `SOC_WH`, paste one by one the prompts in
`prompts/ml_sim_fraud.md` and then run each step's checkpoint query:

| Prompt | What it asks | Expected result |
|---|---|---|
| 1 | Describe `BRONZE.SIM_REQUESTS` | 58,650 labeled rows (1,187 frauds, 2%) and 675 unlabeled, from October 18 to 21 |
| 2 | View `GOLD.SIM_TRAIN`, without `msisdn`, store or agent as features | 58,650 rows, 2.02% fraud |
| 3 | Train `GOLD.SIM_FRAUD_MODEL`, with metrics and feature importance | about 15 s; `ACCOUNT_AGE_DAYS` and `REQUESTS_24H` on top |
| 4 | Score the new requests into `GOLD.SIM_SCORED` | 675 rows, 86 with `fraud_score > 0.5` |
| 5 | Investigation queue and concentration by store and agent | one group stands out |

`SIM_SCORED` is a new table and loses the PII tag and the mask on `msisdn`. After prompt
4, ask Cortex Code to run the final block of `sql/backup/ml_backup_models.sql` to
reapply them; you will check it in module 7.

**If you don't have Cortex Code or something fails:** the model and `SIM_SCORED` already exist from the backup in
step 1.4; run the queries in `sql/06_sim_swap_ml.sql` directly.

```sql
SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score,3) AS score
FROM SECURITY_LAKE.GOLD.SIM_SCORED WHERE fraud_score > 0.5
ORDER BY fraud_score DESC LIMIT 25;
```

**Think about it:** do the store or the agent repeat in the queue? What would that suggest? The
script includes a concentration query that quantifies it.

The model metrics will come out perfect because the data is synthetic and the pattern is very
easy to separate. With real data, the threshold is tuned by comparing the cost of blocking a
legitimate customer with the cost of letting a fraud through.

**Challenge.** Change the threshold from `0.5` to `0.2` and compare how many requests enter the
queue.

**Challenge.** Prompt 2 deliberately excludes the store and the agent. Why, if the
ring is precisely at a specific store and agent?

---

## Module 6 · AI for the SOC: triage, runbooks, agent, MCP, and dashboard

**Objective:** prioritize alerts with a language model, query runbooks in natural language, and
talk to an agent that respects permissions (script `sql/07_ai_triage.sql`).

> **Cortex.** The name of Snowflake's set of AI services. It includes SQL functions that call
> language models, a semantic search engine over documents, and agents. The models run inside
> Snowflake's perimeter, so data does not leave for an external provider.

### 6.1 Triage

```sql
SELECT detection, entity, unit, LEFT(triage::STRING, 300) AS ai_triage
FROM SECURITY_LAKE.GOLD.ALERTS WHERE triage IS NOT NULL LIMIT 10;
```

Each alert carries a JSON with a summary, a severity, the MITRE ATT&CK tactic, and the
recommended next steps. The `AI_COMPLETE` function, when given a JSON schema, returns structured
data that can be queried with SQL, for example with
`WHERE triage:severity = 'critical'`.

### 6.2 Runbooks

The script creates the `RUNBOOK_SEARCH` service over the runbooks in `runbooks/`. Ask it, for
example, "How did we handle the last DNS tunnel case?". It returns the matching runbook excerpt
even if the question does not use the same words.

> **Cortex Search.** A search service that combines semantic (meaning-based) and keyword search
> over text, in this case the SOC runbooks. It is the retrieval piece the agent uses to ground its
> answers in your own documentation.

### 6.3 Agent

In AI & ML > Snowflake Intelligence, open the `SOC_AGENT` agent and ask it: "Which critical
severity alerts are there and which entity do they affect?". The agent answers and shows the SQL
it generated. Then ask which runbook to apply to that alert: to answer, it combines the data query
with the runbook search. Each question takes between 20 and 40 seconds.

> **Snowflake Intelligence and agents.** A *Cortex Agent* is an assistant that receives
> natural-language questions and decides which tool to use: it can generate SQL over tables from
> a semantic model that describes the data, search documents with Cortex Search, or combine both.
> *Snowflake Intelligence* is the chat interface where users talk to those agents.

### 6.4 MCP

The script creates the `SOC_MCP` server, which exposes the agent to external clients (assistants
such as Claude or Cursor, or other agents) with OAuth authentication and respecting roles.

> **MCP (Model Context Protocol).** An open protocol that lets AI applications use external tools
> and data. Snowflake can publish a managed MCP server, so that an external assistant queries the
> data with the same permissions the user would have.

### 6.5 Dashboard

Deploy the dashboard in `streamlit/soc_dashboard.py`. From Snowsight you can upload the file to
the stage through the UI (Catalog > stage > "+ Files") or, with Snowflake CLI or SnowSQL, with
`PUT`:

```sql
USE ROLE SOC_ADMIN;
CREATE STAGE IF NOT EXISTS SECURITY_LAKE.GOLD.APP_STAGE;
PUT file://streamlit/soc_dashboard.py @SECURITY_LAKE.GOLD.APP_STAGE/soc/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
CREATE OR REPLACE STREAMLIT SECURITY_LAKE.GOLD.SOC_DASHBOARD
  FROM '@SECURITY_LAKE.GOLD.APP_STAGE/soc/' MAIN_FILE = 'soc_dashboard.py'
  QUERY_WAREHOUSE = SOC_WH RUNTIME_NAME = 'SYSTEM$WAREHOUSE_RUNTIME'
  TITLE = 'SOC · Security Data Lake';
GRANT USAGE ON STREAMLIT SECURITY_LAKE.GOLD.SOC_DASHBOARD TO ROLE SOC_ANALYST;
```

Open it in Projects > Streamlit > `SOC · Security Data Lake`. It shows alerts by detection,
events by source, and the SIM swap queue. The first startup takes between 30 and 60 seconds.

> **Streamlit in Snowflake.** Streamlit is a Python framework for building data web
> applications. Snowflake can host and run these applications inside the account, so the
> dashboard needs no server of its own and reads data with the user's permissions.

**Challenge.** Call `AI_COMPLETE` yourself with one of the rows of `GOLD.DET_O365_MASS_DOWNLOAD`
and ask for a two-sentence summary for a non-technical manager.

**Challenge.** Ask the agent a question that forces it to cross two sources, for example, what
the user with the most downloads did in Office 365 during the week of the incident.

---

## Module 7 · Governance and auditing

**Objective:** verify that the same data looks different depending on the role, in any query,
dashboard, or agent, and that every access is logged (script `sql/08_governance.sql`).

### 7.1 Test user

To see the policies as an analyst would, create a user with no secondary roles:

```sql
USE ROLE USERADMIN;
CREATE USER IF NOT EXISTS SOC_DEMO_ANALYST PASSWORD = '<generar>' MUST_CHANGE_PASSWORD = FALSE
  DEFAULT_ROLE = SOC_ANALYST DEFAULT_WAREHOUSE = SOC_WH DEFAULT_SECONDARY_ROLES = ();
GRANT ROLE SOC_ANALYST TO USER SOC_DEMO_ANALYST;
```

Sign in with it in an incognito window. Alternatively, in your own session you can use
`USE ROLE SOC_ANALYST; USE SECONDARY ROLES NONE;`. Without this, your secondary roles would give
you `THREAT_HUNTER` permissions and you would see everything.

### 7.2 Masking with a deterministic hash

```sql
USE ROLE SOC_ANALYST;
USE SECONDARY ROLES NONE;
SELECT event_time, user_name, src_ip, activity, unit
FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY LIMIT 10;
```

**Expected result:** `user_name` appears as `h_…`. Since the same user always produces the same
hash, the analyst can correlate events without seeing the data.

> **Masking policy and tags.** A *masking policy* is a function that Snowflake applies to a
> column at query time and that decides, based on the role of whoever is asking, whether to
> return the real value or a masked version. A *tag* is a label placed on a column or object (for
> example, `DATA_SENSITIVITY = 'PII'`) to which policies can be attached to apply them at scale.

### 7.3 Protect a new data field with Cortex Code

The fraud team wants to publish the high-risk SIM queue to the analysts, but the
sales agent identifier is an employee's personal data. Go back to `SOC_ADMIN`
(`USE ROLE SOC_ADMIN; USE SECONDARY ROLES ALL;`) and paste into Cortex Code the four prompts in
`prompts/masking.md`, running each step's checkpoint query:

| Prompt | What it asks | Expected result |
|---|---|---|
| 1 | Inventory of policies and tags | `MASK_PII_HASH` on `AUTH_ACTIVITY.user_name`, `SIM_REQUESTS.msisdn` and `SIM_SCORED.msisdn`; `agent_id` unprotected |
| 2 | View `GOLD.V_SIM_AGENT_RISK` with `SELECT` for `SOC_ANALYST` | 86 rows |
| 3 | Policy `GOVERNANCE.MASK_AGENT_ID` on `agent_id`, tagged as PII | applied to the view |
| 4 | Verify with `SOC_ANALYST` (no secondary roles) and with `THREAT_HUNTER` | see the following table |

| Role | store_id | agent_id | msisdn |
|---|---|---|---|
| SOC_ANALYST | S-0457 | `A-****` | `h_515a806e…` (hash) |
| THREAT_HUNTER | S-0457 | `A-1123` | in clear |

**Think about it:** you haven't applied any policy to `msisdn` in the view and yet it comes out
masked. Why?

The reference policies for this module are in `sql/08_governance.sql`; if you don't have Cortex
Code, you can write the view and the policy by hand using it as a model.

### 7.4 Segregation by business unit

```sql
USE ROLE SOC_ANALYST;
USE SECONDARY ROLES NONE;
SELECT unit, COUNT(*) AS events FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY unit;
```

**Expected result:** as `SOC_ANALYST` only the UES unit appears, with 737,464 events. Repeat the
query with `THREAT_HUNTER`: UES, UDE, and UBR appear.

> **Row access policy.** A policy that filters the rows each role can see. It is written once on
> the table and applies to any query, report, or agent that reads it.

Ask the agent a question from the `SOC_DEMO_ANALYST` session: the answer also comes out masked
and filtered, because the agent queries with the user's role.

### 7.5 Auditing

```sql
USE ROLE ACCOUNTADMIN;
SELECT query_start_time, user_name, f.value:"objectName"::STRING AS object,
       f.value:"columns" AS columns
FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY, LATERAL FLATTEN(base_objects_accessed) f
WHERE f.value:"objectName"::STRING ILIKE 'SECURITY_LAKE.SILVER.AUTH%'
ORDER BY 1 DESC LIMIT 15;
```

> **ACCOUNT_USAGE and ACCESS_HISTORY.** `SNOWFLAKE.ACCOUNT_USAGE` is a read-only schema that
> Snowflake maintains in every account with the history of queries, accesses, logins, and
> consumption. `ACCESS_HISTORY` records which user read or wrote which tables and columns in each
> query.

This view has a latency of up to three hours: your reads from the previous steps will show up
later.

### 7.6 Cost control

```sql
USE ROLE ACCOUNTADMIN;
SHOW RESOURCE MONITORS;
```

`SOC_MONITOR` is assigned to `SOC_WH`, notifies at 80% of the 50 credits, and suspends the
warehouse at 100%.

> **Resource monitor.** A credit consumption limit assigned to one or more warehouses that can
> notify or suspend them when a threshold is reached.

When you finish the module, return to your usual role with
`USE ROLE SOC_ADMIN; USE SECONDARY ROLES ALL;`.

**Challenge.** Review the `MASK_PII_HASH` policy in `sql/08_governance.sql` and which columns it
applies to. Notice that it is applied twice to `msisdn`: in `BRONZE.SIM_REQUESTS` and in
`GOLD.SIM_SCORED`. `SIM_SCORED` was created with `CREATE TABLE AS` in module 5 (or in the backup), and a copy like
that does not inherit the masking of the source table. Verify with `SOC_ANALYST` that `msisdn`
appears as a hash in `SIM_SCORED` and that you can still group by it. How would you avoid having
to remember every copy? Hint: by attaching the policy to the `DATA_SENSITIVITY` tag, so it
applies to any column tagged as PII.

---

## Optional reading · Coexistence with Splunk

If your SOC uses Splunk, this data lake does not replace it: it sits alongside it. These are the
integration options, although they are not part of the lab.

**Splunk queries Snowflake without ingesting.** Splunk Cloud Platform offers Federated Search for
Snowflake, which lets you query Snowflake tables and views with SPL2 without ingesting that data
and correlate it with what is already in Splunk. It is a Splunk feature and requires Splunk Cloud
Platform hosted on AWS.

**From Splunk to Snowflake there is no native federation:** the data is copied to Snowflake. There
are four paths. The first is Openflow with the
[`GetSplunk`](https://docs.snowflake.com/en/user-guide/data-integration/openflow/processors/getsplunk)
processor, which runs searches against the Splunk API and, with the managed time range strategy,
remembers the last run to bring only what is new. The second is streaming with Kafka (Confluent's
Splunk Source connector and the Snowflake connector). The third is batches: searches with the
Splunk REST API exported to S3 and loaded with Snowpipe or queried with external tables, just as
in this lab. The fourth, an external function that calls the Splunk API, is a custom integration
and not real federation.

> **External functions.** An *external function* is a Snowflake SQL function that, when executed,
> calls an external HTTP service (through an API gateway) and returns its response as the query
> result.

**From Snowflake to Splunk.** With Openflow, `PutSplunkHTTP` sends events to the HTTP Event
Collector and `QuerySplunkIndexingStatus` confirms they have been indexed. This way the alerts in
`GOLD.ALERTS` can be forwarded to Splunk.

> **Openflow.** Snowflake's data integration service, based on Apache NiFi. It lets you build
> visual flows that move data between systems (SIEM, Kafka, databases, APIs) and Snowflake, and it
> can be deployed managed by Snowflake or in your own cloud (BYOC).

**Recommended architecture.** Recent, high-priority data for fast detection stays in Splunk. The
full history goes to Snowflake for retention, hunting, analytics, and ML. When history is needed,
Splunk federates the query to Snowflake, and high-value alerts from Snowflake go back to Splunk
with Openflow.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `LIST @S3_LOGS` fails or returns nothing (option A) | The IAM role trust policy does not have the values from `DESC INTEGRATION S3_SIEM_INT`, or the bucket in `STORAGE_ALLOWED_LOCATIONS` and the stage `URL` do not match yours. Review step 1.3. If you cannot resolve it, use option B; scripts `02` to `08` do not change. |
| Quality checks show as `SUSPENDED_INSUFFICIENT_PRIVILEGE` | `SOC_ADMIN` is missing `EXECUTE DATA METRIC FUNCTION` (granted by script `00`). If the checks were created before the grant, remove them from the table and add them again. |
| Data quality shows "No checks" | The dynamic table has not refreshed since they were attached: `ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.NETWORK_ACTIVITY REFRESH;`. |
| `AI_COMPLETE` fails because the model is unavailable | The model is not in your region. Enable cross-region inference or change the model in `sql/07_ai_triage.sql`. |
| The dashboard fails with "pyproject.toml file does not exist" | It was created on the container runtime. Create it on the warehouse runtime with the `CREATE OR REPLACE STREAMLIT ... RUNTIME_NAME = 'SYSTEM$WAREHOUSE_RUNTIME'` from module 6. |
| The dashboard does not reflect code changes | The app runs a versioned copy of its files. After uploading the file, run `CREATE OR REPLACE STREAMLIT ... FROM '@SECURITY_LAKE.GOLD.APP_STAGE/soc/'` again. |
| Error with the `hide_index` parameter of `st.dataframe` | The warehouse runtime does not support it; remove it from the code. |
| The dashboard is slow to open | The first startup takes between 30 and 60 seconds. |
| Masking or row filtering is not applied | You have secondary roles active. Use `USE SECONDARY ROLES NONE` or the `SOC_DEMO_ANALYST` user. |
| `ACCESS_HISTORY` or Cortex consumption appear empty | `ACCOUNT_USAGE` views have between one and three hours of latency. |
| The lifecycle policy has not done anything | It takes about 24 hours to run for the first time. |
| Cortex Code returns `input_data is empty` when training the anomaly model | It is training on a view that reads `NETWORK_ACTIVITY`, filtered by the row access policy. Ask it to train on the table `GOLD.EGRESS_DAILY_SUBNET`. |
| `msisdn` shows in clear in `SIM_SCORED` after module 5 | Recreating the table loses the mask. Run the final block of `sql/backup/ml_backup_models.sql`. |
| `AT(OFFSET => ...)` returns error 000707 on the clone | The offset falls before the clone was created. Wait with `SYSTEM$WAIT(60)` or use `BEFORE(STATEMENT => ...)`. |
| `CREATE DATABASE ... CLONE` fails with `SOC_ADMIN` | `SOC_ADMIN` does not have `CREATE DATABASE`. Clone with `SYSADMIN` and transfer ownership, as script `09` does. |
| `CREATE SHARE` fails due to permissions | It requires `ACCOUNTADMIN` or the `CREATE SHARE` privilege. |

---

## Cleanup

When you finish, suspend what consumes credits and drop the test user, the clone, the share and the
objects created with Cortex Code in module 7:

```sql
USE ROLE ACCOUNTADMIN;
DROP USER IF EXISTS SOC_DEMO_ANALYST;
DROP SHARE IF EXISTS SOC_IOC_SHARE;
DROP DATABASE IF EXISTS SECURITY_LAKE_DEV;
-- and any SECURITY_LAKE_EVIDENCE_* you created
DROP VIEW IF EXISTS SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK;
DROP MASKING POLICY IF EXISTS SECURITY_LAKE.GOVERNANCE.MASK_AGENT_ID;
ALTER TASK SECURITY_LAKE.GOLD.DETECTIONS_HOURLY SUSPEND;
ALTER WAREHOUSE SOC_WH SUSPEND;
```

To tear everything down, run `sql/99_teardown.sql`. It drops the `SECURITY_LAKE` database, the
`SECURITY_LAKE_DEV` clone, the `SOC_IOC_SHARE` share and the
roles, warehouse, and resource monitor created in script `00`. If you used option A, also drop
the integration (`DROP INTEGRATION S3_SIEM_INT;`), and in AWS delete the bucket, the IAM role, and
its policy, and rotate the credentials you used to upload the data.

To see what the lab cost, query
`SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY`.

---

## Answer key: seeded incidents

Stop reading if you still want to find them on your own. The generator inserts seven
incidents; the October ones generate the ten alerts in `GOLD.ALERTS`.

| Incident | Date | Entities | Where it appears |
|---|---|---|---|
| Historical IOC | Feb 10, 2026 | 10.20.3.40 → update-check-srv.com | Module 4 (IOC and raw search) |
| Brute force and privileges | Oct 14 | svc_backup / 185.220.101.45 | Module 4 (`MATCH_RECOGNIZE`) |
| DNS tunnel | Oct 15 and 16 | 10.20.5.77 → x1f9-cdn.net | Module 2 (file size and query in place), module 4 and clone (4.5) |
| O365 mass download | Oct 16 | maria.lopez / 91.240.118.172 | Module 4 |
| 5 GB exfiltration | Oct 17 | 10.20.8.15 → 45.137.21.9 | Module 4 (rule and ML) and module 6 (agent) |
| SIM swap ring | Oct 18 to 20 | store S-0457 / agent A-1123 | Module 5 |
| Silent source | from Oct 20 at 12:00 | fw-bcn-02 | Module 4 (source health) |

The **historical IOC** is an internal host that, in February, made forty late-night queries to a
domain that is now on the threat list. With a year of queryable data, a new indicator can be
searched backward in seconds.

The **brute force** is sixty failed logins by the `svc_backup` service account in about five
minutes, followed by a successful login and a 4672 event, which indicates the session received
special privileges.

The **DNS tunnel** is 1,500 queries per day, over two days, with long random subdomains (about 52
characters) to `x1f9-cdn.net`. That is why the DNS files for those days weigh about 85 KB versus
the usual 23 KB.

The **Office 365 mass download** is five hundred SharePoint downloads by the user `maria.lopez`
in a single hour and from an unusual IP.

The **5 GB exfiltration** is fifty flows of about 100 MB between 3:00 and 3:50 a.m., from
10.20.8.15 to an external IP, with a Suricata alert. `DET_EXFIL` sees it as about 43,000 times the
host's average, and the anomaly model as 5,374 MB outbound from subnet 10.20.8 versus about 5.3 MB
forecast.

The **SIM swap ring** is twenty-five SIM change requests per day, over three days, at the same
store and by the same agent, with a new device and location: 75 high-risk requests pointing to
possible insider fraud.

The **silent source** is the `fw-bcn-02` firewall, which stops sending logs on October 20 at
noon.

### Answers to the compute, ingestion, sharing, ML, clone and Time Travel challenges

**Module 1 · `HUNT_WH`.** `CREATE WAREHOUSE HUNT_WH WAREHOUSE_SIZE = 'LARGE' AUTO_SUSPEND = 60
INITIALLY_SUSPENDED = TRUE;`. A 5-second search on the stopped warehouse bills 60
seconds, because each start has a one-minute minimum; subsequent queries while it stays
running are billed per second.

**Module 2 · Load verification.** With the lab data, the verification block should not
show pending or failed files for any source. The second `COPY` of `DNS_RAW`
loads 0 rows: load metadata (64 days) remembers the files already loaded, which is why
`FORCE = TRUE` is never used.

**Module 2 · Mechanism per source.** Daily Office 365 audit in S3: `COPY` scheduled with a
task. Proxy logs every five minutes in S3: Snowpipe with auto-ingest. EDR alerts in Kafka:
Snowpipe Streaming with the Kafka connector.

**Module 3 · Shared view.** It aggregates per indicator so as not to expose internal hosts or users to
another organization: the CSIRT needs to know which indicator was seen, how many times and when, not which
specific machine. To limit it to UES, add `WHERE unit = 'UES'` to the view (or a row access
policy that takes the consumer account into account, for example with `CURRENT_ACCOUNT()`).

**Module 4 · `prediction_interval`.** With 0.99 the expected band is narrower and more
mild anomalies show up; the 10.20.8 one on October 17 is still, by far, the first. The threshold
is a trade-off between false positives and missed cases, and the SOC decides it.

**Module 4 · Clone.** `dns_tunnel` changes: with the 2,000 threshold the two real alerts
for the 10.20.5.77 tunnel on October 15 and 16 disappear, which have about 1,500 distinct labels
per day. The change is not promoted: raising the threshold would have hidden the real incident. Production has not
been touched.

**Module 4 · Queue at `$t_before`.**

```sql
SELECT detection, entity, event_time, status
FROM SECURITY_LAKE_DEV.GOLD.ALERTS AT(TIMESTAMP => $t_before)
ORDER BY event_time;
```

**Module 4 · `OFFSET` vs. `STATEMENT`.** `AT(OFFSET => -3600)` asks for the table as it was
an hour ago, and the clone did not exist then: Time Travel cannot go further back than the
object's creation (error 000707). `BEFORE(STATEMENT => ...)` points at the exact instant before the `DELETE`,
which is after the clone was created. Also, `OFFSET` is approximate and may include other
changes; `STATEMENT` is exact.

**Module 5 · Model features.** If the store and the agent were features, the model would learn
which stores or agents had fraud in the past, and would not recognize a ring at a new store.
With behavioral features (account age, requests in 24 hours, type, hour), the
model scores each request on its own, and the concentration at S-0457 / A-1123 appears afterward when
grouping: it is evidence independent of the model.

**Module 7 · `msisdn` in the view.** The `MASK_PII_HASH` policy is applied to the column of the
base table `GOLD.SIM_SCORED`, and a table's policies also apply to any view that
reads it. That is why `POLICY_REFERENCES` on the view only shows `MASK_AGENT_ID`.
