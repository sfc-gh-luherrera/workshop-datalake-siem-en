# Workshop: Security Data Lake on Snowflake

Hands-on lab for security and SOC teams. It starts from logs stored in S3 (or in a Snowflake
internal stage) and goes all the way to SQL detections, hunting over a year of data, anomaly and
fraud models, AI triage, a conversational agent, a dashboard and data governance, all inside
Snowflake.

The step-by-step guide is in [`docs/evaluator_guide.md`](docs/evaluator_guide.md).

## Contents

| Path | What it is |
|---|---|
| `docs/evaluator_guide.md` | Guide to replicate the lab, with expected results and challenges |
| `generator/` | Synthetic log generator (13 months) with seeded incidents |
| `sql/` | Scripts in execution order (`00` to `08`, and `99` to clean up) |
| `streamlit/` | SOC dashboard for Streamlit in Snowflake |
| `runbooks/` | Synthetic runbooks indexed by Cortex Search |

All data is synthetic.
