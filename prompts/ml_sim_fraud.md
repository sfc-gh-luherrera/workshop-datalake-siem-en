# ML with Cortex Code: fraud in SIM requests (SIM swap / port-out)

Goal: train a classifier with `SNOWFLAKE.ML.CLASSIFICATION` on the labeled
history and surface the ring seeded at store **S-0457** / agent **A-1123**
(18–20 Oct). Based on `sql/06_sim_swap_ml.sql`.

- Role: `SOC_ADMIN` · Warehouse: `SOC_WH` · Schema: `SECURITY_LAKE.GOLD`
- Backup: `sql/backup/ml_backup_models.sql` (same object names).

---

## 1. Discover the data

**Prompt**

```
Describe the table SECURITY_LAKE.BRONZE.SIM_REQUESTS: columns, number of rows,
how many have an is_fraud label and how many don't, and the fraud percentage among the labeled ones.
What date range do the unlabeled rows cover?
```

**Expected result**: 58,650 labeled rows (1,187 frauds, ~2%) and 675 unlabeled,
which are the new requests from 18 to 21-Oct that need to be scored.

**Checkpoint**

```sql
SELECT COUNT_IF(is_fraud IS NOT NULL) AS labeled, COUNT_IF(is_fraud = 1) AS frauds,
       COUNT_IF(is_fraud IS NULL) AS unlabeled,
       MIN(IFF(is_fraud IS NULL, request_ts, NULL)) AS new_from,
       MAX(IFF(is_fraud IS NULL, request_ts, NULL)) AS new_to
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS;
```

---

## 2. Training view

**Prompt**

```
Create the view SECURITY_LAKE.GOLD.SIM_TRAIN with the labeled rows of SIM_REQUESTS and these
features: request_type, channel, new_device, new_location, requests_24h, account_age_days,
the request hour as hour_of_day and is_fraud converted to BOOLEAN.
Do not include msisdn, store or agent: they must not be model features.
```

**Expected result**: view created; 58,650 rows, 1,187 with `is_fraud = TRUE` (2.02%).

**Checkpoint**

```sql
SELECT COUNT(*) AS row_count, COUNT_IF(is_fraud) AS frauds, ROUND(AVG(is_fraud::INT) * 100, 2) AS pct_fraud
FROM SECURITY_LAKE.GOLD.SIM_TRAIN;
-- 58650 | 1187 | 2.02
```

---

## 3. Train and evaluate the classifier

**Prompt**

```
Train a SNOWFLAKE.ML.CLASSIFICATION model called SECURITY_LAKE.GOLD.SIM_FRAUD_MODEL on the view
SIM_TRAIN (use SYSTEM$REFERENCE('VIEW', ...)) with target IS_FRAUD. Show me the evaluation
metrics and the feature importance, and explain which ones weigh the most and why that makes
sense for SIM swap fraud.
```

**Expected result**: model created (~15 s on XS). On this synthetic dataset the evaluation
metrics come out perfect (precision/recall 1 in both classes): point out that with real data
it will not be the case. Most important features: `ACCOUNT_AGE_DAYS`, `REQUESTS_24H`, `REQUEST_TYPE`,
`HOUR_OF_DAY`.

**Checkpoint**

```sql
CALL SECURITY_LAKE.GOLD.SIM_FRAUD_MODEL!SHOW_EVALUATION_METRICS();
CALL SECURITY_LAKE.GOLD.SIM_FRAUD_MODEL!SHOW_FEATURE_IMPORTANCE();
-- rank 1: ACCOUNT_AGE_DAYS, rank 2: REQUESTS_24H
```

---

## 4. Score the new requests

**Prompt**

```
Score the unlabeled requests in SIM_REQUESTS with SIM_FRAUD_MODEL!PREDICT and save into
SECURITY_LAKE.GOLD.SIM_SCORED: request_ts, msisdn, request_type, channel, store_id, agent_id,
unit and fraud_score (the probability of class "True" as FLOAT). Keep the table's existing
permissions (COPY GRANTS).
```

**Expected result**: 675 scored rows.

> `SIM_SCORED` is a new table: it loses the PII tag and the mask on `msisdn`.
> Reapply them by asking Cortex Code to run the corresponding block of
> `sql/08_governance.sql` (or the final block of the backup script).

**Checkpoint**

```sql
SELECT COUNT(*) AS scored, COUNT_IF(fraud_score > 0.5) AS high_risk FROM SECURITY_LAKE.GOLD.SIM_SCORED;
SELECT policy_name FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_NAME => 'SECURITY_LAKE.GOLD.SIM_SCORED', REF_ENTITY_DOMAIN => 'TABLE'));
-- 675 | 86 ; MASK_PII_HASH
```

---

## 5. Investigation queue and insider fraud

**Prompt**

```
Using SIM_SCORED, give me this morning's investigation queue (the 25 requests with the highest
fraud_score > 0.5) and then group by store and agent to see whether there is an anomalous
concentration of high-risk requests (5 or more). What does the result indicate and what would you do next?
```

**Expected result**: a single group stands out, **S-0457 / A-1123 with 75 high-risk
requests** and an average score of 1.0: an insider fraud pattern (an agent processing SIM changes for
a ring). Next step: block the agent, review the affected lines, notify the fraud team.

**Checkpoint**

```sql
SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SECURITY_LAKE.GOLD.SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
-- S-0457 | A-1123 | 75 | 1
```
