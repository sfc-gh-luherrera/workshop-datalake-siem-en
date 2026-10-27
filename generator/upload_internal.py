"""Uploads the generator's local output to an internal stage (no-AWS rehearsal).

Usage: python upload_internal.py --dir ./out --connection <name in connections.toml>
     python upload_internal.py --dir ./out --resume --workers 4   # resumes an interrupted upload
Keeps the <source>/YYYY/MM/DD/ layout inside @SECURITY_LAKE.BRONZE.S3_LOGS.

Resilience:
  - login/network timeouts on the connection (never hangs),
  - one PUT per <source>/YYYY/MM (small, re-runnable monthly batches),
  - OVERWRITE=FALSE: re-running does not re-upload what is already there,
  - --resume: compares sizes with a LIST of the stage and skips files already uploaded,
  - per-batch retries with exponential backoff, failure summary and exit code != 0.
"""
import argparse
import random
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import snowflake.connector

MAX_RETRIES = 5
STAGE = "S3_LOGS"

p = argparse.ArgumentParser()
p.add_argument("--dir", required=True)
p.add_argument("--connection", default=None)
p.add_argument("--workers", type=int, default=8, help="parallel monthly batches (one connection per thread)")
p.add_argument("--resume", action="store_true", help="skip files already in the stage with the same size")
p.add_argument("--progress-every", type=int, default=10, help="progress line every N batches")
p.add_argument("--parallel", type=int, default=8, help="PUT PARALLEL")
a = p.parse_args()
if a.workers < 1 or a.progress_every < 1:
    p.error("--workers and --progress-every must be >= 1")

def connect():
    kw = dict(login_timeout=60, network_timeout=300, socket_timeout=300)
    con = snowflake.connector.connect(connection_name=a.connection, **kw) if a.connection \
        else snowflake.connector.connect(**kw)
    cur = con.cursor()
    cur.execute("USE ROLE SOC_ADMIN")
    cur.execute("USE SCHEMA SECURITY_LAKE.BRONZE")
    return con

root = Path(a.dir).resolve()
files = [f for f in root.rglob("*") if f.is_file() and not f.name.endswith(".part")]

# Files already in the stage: relative path -> size
remote = {}
if a.resume:
    con = connect()
    for row in con.cursor().execute(f"LIST @{STAGE}"):
        # name comes as "s3_logs/dns/2026/10/01/dns_20261001.json.gz"
        remote[row[0].split("/", 1)[1] if "/" in row[0] else row[0]] = int(row[1])
    con.close()
    print(f"--resume: {len(remote)} files already in @{STAGE}", flush=True)

# Batches per <source>/YYYY/MM (or the parent directory if it does not follow the layout, e.g. ioc/, runbooks/)
batches = defaultdict(list)
skipped = 0
for f in files:
    rel = f.relative_to(root).as_posix()
    if a.resume and remote.get(rel) == f.stat().st_size:
        skipped += 1
        continue
    m = re.match(r"^([^/]+/\d{4}/\d{2})/", rel)
    batches[m.group(1) if m else f.parent.relative_to(root).as_posix()].append(f)

local = threading.local()

def cursor():
    if not hasattr(local, "con"):
        local.con = connect()
    return local.con.cursor()

def upload_batch(key, batch):
    # Group by day: the PUT keeps the <source>/YYYY/MM/DD/ layout
    by_dir = defaultdict(list)
    for f in batch:
        by_dir[f.parent].append(f)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            for d, fs in sorted(by_dir.items()):
                rel = d.relative_to(root).as_posix()
                pattern = f"{d}/*" if not a.resume else None
                srcs = [pattern] if pattern else [str(f) for f in fs]
                for src in srcs:
                    cursor().execute(f"PUT 'file://{src}' @{STAGE}/{rel}/ "
                                     f"AUTO_COMPRESS=FALSE OVERWRITE=FALSE PARALLEL={a.parallel}")
            return len(batch)
        except Exception as e:  # noqa: BLE001
            if hasattr(local, "con"):  # connection possibly broken: recreate it
                try:
                    local.con.close()
                except Exception:  # noqa: BLE001
                    pass
                del local.con
            if attempt == MAX_RETRIES:
                raise
            wait = min(60, 2 ** attempt) + random.random()
            print(f"Retry {attempt}/{MAX_RETRIES} batch {key} in {wait:.1f}s: {e!r}", file=sys.stderr, flush=True)
            time.sleep(wait)

done = uploaded = 0
failed = []
with ThreadPoolExecutor(max_workers=a.workers) as pool:
    futs = {pool.submit(upload_batch, k, v): k for k, v in sorted(batches.items())}
    for fut in as_completed(futs):
        done += 1
        try:
            uploaded += fut.result()
        except Exception as e:  # noqa: BLE001
            failed.append((futs[fut], repr(e)))
            print(f"ERROR batch {futs[fut]}: {e!r}", file=sys.stderr, flush=True)
        if done % a.progress_every == 0:
            print(f"[progress] {done}/{len(batches)} batches, {uploaded} files, {len(failed)} failed batches", flush=True)

print(f"Uploaded {uploaded} files in {len(batches)} monthly batches; {skipped} skipped (--resume); "
      f"{len(failed)} failed batches")
try:
    connect().cursor().execute(f"ALTER STAGE {STAGE} REFRESH")
except Exception as e:  # noqa: BLE001 - the internal stage may not have a directory table
    print(f"Warning: ALTER STAGE REFRESH failed: {e!r}", file=sys.stderr)
if failed:
    print("Failed batches (re-run with --resume to retry only what is pending):", file=sys.stderr)
    for k, err in sorted(failed):
        print(f"  {k}: {err}", file=sys.stderr)
    sys.exit(1)
