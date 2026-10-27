# ML with Cortex Code: outbound traffic anomalies

Goal: detect the seeded exfiltration (subnet **10.20.8**, **17-Oct-2026**) with
`SNOWFLAKE.ML.ANOMALY_DETECTION`, without writing SQL by hand. Each step is a prompt to
copy and paste into Cortex Code, the expected result and a checkpoint SQL.

- Role: `SOC_ADMIN` · Warehouse: `SOC_WH` · Output schema: `SECURITY_LAKE.GOLD`
- Backup if something fails: `sql/backup/ml_backup_models.sql` (creates the same objects with the same names).

---

## 1. Discover the network table

**Prompt**

```
Find the table in SECURITY_LAKE.SILVER with network activity (NetFlow and firewall).
Tell me its columns, which sources it contains (source column), the date range
and which source carries the outbound byte volume. Don't create anything yet.
```

**Expected result**: it identifies `SILVER.NETWORK_ACTIVITY` (dynamic table). Two sources:
`netflow` (~790,000 rows, all with `bytes_out`) and `fw` (~474,000 rows, `bytes_out` empty).
Data from 22-Sep-2025 to 21-Oct-2026. Only `netflow` can be used to measure volume.

**Checkpoint**

```sql
SELECT source, COUNT(*) AS row_count, COUNT(bytes_out) AS with_bytes,
       MIN(event_time) AS from_ts, MAX(event_time) AS to_ts
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY source ORDER BY source;
```

---

## 2. Daily time series of outbound bytes per subnet

**Prompt**

```
Create in SECURITY_LAKE.GOLD the view NET_DAILY_SUBNET with the daily total of bytes_out
per /24 subnet (the first three octets of src_ip, column SUBNET), only source = 'netflow'.
Columns: SUBNET (string), DAY (TIMESTAMP_NTZ, truncated to the day), BYTES_OUT (FLOAT).
Then materialize the view into the table GOLD.EGRESS_DAILY_SUBNET (CREATE OR REPLACE TABLE AS),
because NETWORK_ACTIVITY has a row access policy and ML training must not read it
directly. Show me how many subnets and days there are, and the value of subnet 10.20.8
on 17-Oct-2026 against its median.
```

**Expected result**: 9 subnets (10.20.1 to 10.20.9), 395 days each, 3,555 points.
The daily median is around 5 MB; 10.20.8 on 17-Oct has ~5,374 MB (about 1,000 times more).
Training will use the days **before 17-Oct** (3,510 points).

**Checkpoint**

```sql
SELECT COUNT(DISTINCT subnet) AS subnets, COUNT(*) AS points, MIN(day) AS from_day, MAX(day) AS to_day,
       COUNT_IF(day < '2026-10-17') AS training_points,
       MAX(IFF(subnet = '10.20.8' AND day = '2026-10-17', ROUND(bytes_out/1e6), NULL)) AS mb_10_20_8_17oct
FROM SECURITY_LAKE.GOLD.EGRESS_DAILY_SUBNET;
-- 9 | 3555 | 2025-09-22 | 2026-10-21 | 3510 | 5374
```

> If the agent trains directly on the view, the error is
> `input_data is empty`: the `RAP_BY_UNIT` row access policy filters everything out inside
> training. That is why the table is materialized.

---

## 3. Train the anomaly model

**Prompt**

```
Train a SNOWFLAKE.ML.ANOMALY_DETECTION model called SECURITY_LAKE.GOLD.NET_ANOMALY_MODEL
on GOLD.EGRESS_DAILY_SUBNET, one series per SUBNET, timestamp DAY, target BYTES_OUT,
without labels (LABEL_COLNAME => ''), using only the days before 2026-10-17.
Explain in two sentences what the model learns.
```

**Expected result**: `Instance NET_ANOMALY_MODEL successfully created`.
The model learns the normal behavior of each subnet separately (it is a per-series
forecasting model) and does not need examples of attacks.

**Checkpoint**

```sql
SHOW SNOWFLAKE.ML.ANOMALY_DETECTION IN SCHEMA SECURITY_LAKE.GOLD;
-- 1 row: NET_ANOMALY_MODEL, owner SOC_ADMIN
```

---

## 4. Detect and save results

**Prompt**

```
Use NET_ANOMALY_MODEL!DETECT_ANOMALIES on GOLD.EGRESS_DAILY_SUBNET for the days
from 2026-10-17 (same columns as in training) with
CONFIG_OBJECT => {'prediction_interval': 0.999} and save the result in the table
SECURITY_LAKE.GOLD.EGRESS_ANOMALIES. List the anomalies ordered by how many times
the observed value exceeds the forecast.
```

**Expected result**: 45 rows (9 subnets x 5 days), 2 anomalies. The first one is
**10.20.8 on 17-Oct: 5,374 MB against 5.3 MB forecast (~1,005x)**. The second one
(10.20.9 on 19-Oct, 8.9 MB against an upper bound of 8.2 MB) is a minor false positive:
a good moment to talk about thresholds.

**Checkpoint**

```sql
SELECT COUNT(*) AS row_count, COUNT_IF(is_anomaly) AS anomalies,
       MAX_BY(series || ' ' || ts::DATE, distance) AS top_anomaly,
       ROUND(MAX(y / forecast)) AS max_x_over_forecast
FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES;
-- 45 | 2 | 10.20.8 2026-10-17 | 1005
```

---

## 5. Explain and visualize observed vs. expected range

**Prompt**

```
Explain for a SOC analyst what the Y, FORECAST, LOWER_BOUND, UPPER_BOUND, IS_ANOMALY
and DISTANCE columns of GOLD.EGRESS_ANOMALIES mean. Then draw a line chart
in MB per day for subnets 10.20.8 and 10.20.1 with the observed value,
the forecast and the min–max band. Finish with the recommended next action
(which 10.20.8 host to investigate and with which detection or runbook).
```

**Expected result**: in 10.20.1 the observed value always stays within the band
(~1–9 MB). In 10.20.8 on 17-Oct it goes off the scale (5,374 MB against a maximum of 9 MB) and
returns to normal the next day. Next step: host `10.20.8.15` (alert
`exfiltration` in `GOLD.ALERTS`, IOC `45.137.21.9`) and the runbook `rb_exfiltration.md`.

**Checkpoint**

```sql
SELECT series, ts::DATE AS day, ROUND(y/1e6, 1) AS mb_observed, ROUND(forecast/1e6, 1) AS mb_forecast,
       ROUND(lower_bound/1e6, 1) AS mb_min, ROUND(upper_bound/1e6, 1) AS mb_max, is_anomaly
FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES
WHERE series IN ('10.20.8', '10.20.1') ORDER BY series, day;
-- 10 rows; only 10.20.8 / 2026-10-17 with is_anomaly = TRUE
```

---

Compatibility: `demo_snippets/ml.sql` and the guides read `GOLD.NET_ANOMALIES`. If this flow
was followed instead of the backup, refresh it:
`CREATE OR REPLACE TABLE SECURITY_LAKE.GOLD.NET_ANOMALIES COPY GRANTS AS SELECT * FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES;`
