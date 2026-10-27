# Governance with Cortex Code: view + masking of a personal data field

Goal: publish a view for the analyst on high-risk SIM requests and
hide the sales agent identifier (employee personal data) with a masking
policy, checking the result per role. Based on `sql/08_governance.sql`
(`MASK_PII_HASH`, `RAP_BY_UNIT`, SOC_ANALYST / THREAT_HUNTER separation).

- Role: `SOC_ADMIN` · Warehouse: `SOC_WH`
- Requirements: `08_governance.sql` executed and `GOLD.SIM_SCORED` in place (06 or backup).

---

## 1. See what is already protected

**Prompt**

```
Which masking policies and tags exist in SECURITY_LAKE.GOVERNANCE and which columns are they
applied to? Tell me specifically which columns of GOLD.SIM_SCORED are protected and which are not.
```

**Expected result**: `MASK_PII_HASH` (deterministic hash except for `THREAT_HUNTER`)
applied to `SILVER.AUTH_ACTIVITY.user_name`, `BRONZE.SIM_REQUESTS.msisdn` and
`GOLD.SIM_SCORED.msisdn`; tag `DATA_SENSITIVITY = 'PII'` on those columns.
`agent_id` in `SIM_SCORED` is **not** protected.

**Checkpoint**

```sql
SELECT ref_column_name, policy_name, policy_kind FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_NAME => 'SECURITY_LAKE.GOLD.SIM_SCORED', REF_ENTITY_DOMAIN => 'TABLE'));
-- MSISDN | MASK_PII_HASH | MASKING_POLICY
```

---

## 2. Create the view for the analyst

**Prompt**

```
Create the view SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK with request_ts, store_id, agent_id,
msisdn, request_type and fraud_score rounded to 3 decimals, only for fraud_score > 0.5,
and grant SELECT on it to the SOC_ANALYST role (GOLD's future grants do not cover views).
```

**Expected result**: view created with 86 rows; grant applied.

**Checkpoint**

```sql
SELECT COUNT(*) FROM SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK;   -- 86
SHOW GRANTS ON VIEW SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK;     -- SELECT to SOC_ANALYST
```

---

## 3. Masking policy on the agent identifier

**Prompt**

```
Create in SECURITY_LAKE.GOVERNANCE the masking policy MASK_AGENT_ID for STRING that leaves the value
in clear if the THREAT_HUNTER role is in the session (IS_ROLE_IN_SESSION) and, otherwise, replaces
the digits with asterisks (A-1123 -> A-****), so the analyst can group by store
but cannot identify the employee. Apply it to the agent_id column of the view
GOLD.V_SIM_AGENT_RISK and tag the column with DATA_SENSITIVITY = 'PII'.
```

**Expected result**: policy created and applied to the view. The view's `msisdn` is already
masked without doing anything: the base table policy (`SIM_SCORED`) also applies
through the view.

**Checkpoint**

```sql
SELECT ref_column_name, policy_name FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_NAME => 'SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK', REF_ENTITY_DOMAIN => 'VIEW'));
-- AGENT_ID | MASK_AGENT_ID   (the msisdn one is on the base table, not on the view)
```

---

## 4. Verify per role

**Prompt**

```
Check the view with two roles. First USE ROLE SOC_ANALYST; USE SECONDARY ROLES NONE;
USE WAREHOUSE SOC_WH; and query store_id, agent_id and msisdn (2 rows). Then
USE ROLE THREAT_HUNTER and repeat. Compare and explain the difference. When done go back to
USE ROLE SOC_ADMIN; USE SECONDARY ROLES ALL;
```

**Expected result**

| Role | store_id | agent_id | msisdn |
|---|---|---|---|
| SOC_ANALYST | S-0457 | `A-****` | `h_515a806e…` (hash) |
| THREAT_HUNTER | S-0457 | `A-1123` | `+34 6…` (in clear) |

Important: without `USE SECONDARY ROLES NONE` the analyst inherits the user's secondary
roles (e.g. SOC_ADMIN → THREAT_HUNTER) and sees everything in clear.

**Checkpoint** (run with each role)

```sql
SELECT CURRENT_ROLE() AS role_name, store_id, agent_id, msisdn
FROM SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK LIMIT 2;
```

---

## Cleanup (optional, when done)

```sql
USE ROLE SOC_ADMIN;
DROP VIEW IF EXISTS SECURITY_LAKE.GOLD.V_SIM_AGENT_RISK;
DROP MASKING POLICY IF EXISTS SECURITY_LAKE.GOVERNANCE.MASK_AGENT_ID;
```
