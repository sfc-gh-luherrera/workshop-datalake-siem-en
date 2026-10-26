"""Uploads the generator's local output to an internal stage (no-AWS rehearsal).

Usage: python upload_internal.py --dir ./out --connection <name in connections.toml>
Keeps the <source>/YYYY/MM/DD/ layout inside @SECURITY_LAKE.BRONZE.S3_LOGS.
"""
import argparse
from pathlib import Path

import snowflake.connector

p = argparse.ArgumentParser()
p.add_argument("--dir", required=True)
p.add_argument("--connection", default=None)
a = p.parse_args()

con = snowflake.connector.connect(connection_name=a.connection) if a.connection else snowflake.connector.connect()
cur = con.cursor()
cur.execute("USE ROLE SOC_ADMIN")
cur.execute("USE SCHEMA SECURITY_LAKE.BRONZE")
root = Path(a.dir).resolve()
dirs = sorted({f.parent for f in root.rglob("*") if f.is_file()})
for d in dirs:
    rel = d.relative_to(root).as_posix()
    cur.execute(f"PUT 'file://{d}/*' @S3_LOGS/{rel}/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE PARALLEL=8")
print(f"Uploaded {len(dirs)} directories")
cur.execute("ALTER STAGE S3_LOGS REFRESH")
