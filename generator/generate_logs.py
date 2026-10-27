"""Synthetic log generator for the Security Data Lake workshop on Snowflake.

Generates 13 months of logs (DNS, NetFlow, Suricata EVE, Windows/AD, firewall/VPN syslog,
Office 365, SIM requests) and an IOC file, with seeded incidents that the demos
must find. All data is synthetic.

Usage:
  python generate_logs.py --local ./out            # writes to disk
  python generate_logs.py --upload                 # uploads to s3://workshop-datalake-siem
  python generate_logs.py --upload --bucket other --scale 0.5
  python generate_logs.py --upload --resume --workers 16   # resumes an interrupted upload

Layout: <source>/YYYY/MM/DD/<source>_YYYYMMDD.<ext>.gz
"""

import argparse
import csv
import gzip
import io
import json
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

BUCKET = "workshop-datalake-siem"
END_DATE = date(2026, 10, 21)
DAYS = 395  # ~13 months
SEED = 42
MAX_FILE_RETRIES = 5  # retries per file (on top of botocore's)

UNITS = [("UES", "ES"), ("UBR", "BR"), ("UDE", "DE")]
USERS = [f"{n}.{s}" for n in ["ana", "luis", "maria", "jorge", "lucia", "pablo", "elena", "david", "sara", "ivan"]
         for s in ["garcia", "lopez", "martin", "sanchez", "perez"]]
SERVICE_ACCOUNTS = ["svc_backup", "svc_monitor", "svc_deploy"]
INTERNAL_HOSTS = [f"10.20.{a}.{b}" for a in range(1, 10) for b in range(10, 60)]
EXTERNAL_IPS = [f"{random.Random(i).randint(20, 220)}.{random.Random(i+1).randint(0, 255)}."
                f"{random.Random(i+2).randint(0, 255)}.{random.Random(i+3).randint(1, 254)}" for i in range(300)]
DOMAINS = ["google.com", "microsoft.com", "office365.com", "acme-telco.es", "acme-mobile.es", "aws.amazon.com",
           "github.com", "slack.com", "zoom.us", "salesforce.com", "cdn.cloudflare.net", "akamaiedge.net"]
FIREWALLS = [("fw-mad-01", "cisco"), ("fw-bcn-02", "juniper"), ("vpn-mad-01", "cisco"), ("fw-sao-01", "paloalto")]

# --- Seeded incidents (reference for the instructor guide) ---
BRUTE = dict(day=date(2026, 10, 14), user="svc_backup", ip="185.220.101.45", host="DC-MAD-01")
TUNNEL = dict(start=date(2026, 10, 15), days=2, host="10.20.5.77", domain="x1f9-cdn.net")
EXFIL = dict(day=date(2026, 10, 17), host="10.20.8.15", dst="45.137.21.9", gb=5)
OLD_IOC = dict(day=date(2026, 2, 10), host="10.20.3.40", domain="update-check-srv.com")
O365 = dict(day=date(2026, 10, 16), user="maria.lopez", ip="91.240.118.172")
SIM_RING = dict(start=date(2026, 10, 18), days=3, store="S-0457", agent="A-1123")
FW_GAP = dict(fw="fw-bcn-02", after=datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc))
IOCS = [("185.220.101.45", "ip"), ("45.137.21.9", "ip"), ("91.240.118.172", "ip"),
        ("x1f9-cdn.net", "domain"), ("update-check-srv.com", "domain")]

def ts(d, rng, hour=None, minute=None, second=None):
    return datetime(d.year, d.month, d.day, rng.randint(0, 23) if hour is None else hour,
                    rng.randint(0, 59) if minute is None else minute,
                    rng.randint(0, 59) if second is None else second, tzinfo=timezone.utc)

def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def unit(rng):
    return rng.choice(UNITS)

def gen_dns(d, rng, n):
    rows = []
    for _ in range(n):
        u, c = unit(rng)
        rows.append(dict(ts=iso(ts(d, rng)), client_ip=rng.choice(INTERNAL_HOSTS),
                         query=f"{rng.choice(['www', 'api', 'login', 'cdn', 'mail'])}.{rng.choice(DOMAINS)}",
                         qtype=rng.choice(["A", "A", "A", "AAAA", "CNAME", "TXT"]),
                         rcode=rng.choice(["NOERROR"] * 9 + ["NXDOMAIN"]), resolver="10.0.0.53",
                         unit=u, country=c))
    if TUNNEL["start"] <= d < TUNNEL["start"] + timedelta(days=TUNNEL["days"]):
        for _ in range(1500):
            sub = "".join(rng.choices(string.ascii_lowercase + "234567", k=rng.randint(45, 60)))
            rows.append(dict(ts=iso(ts(d, rng)), client_ip=TUNNEL["host"], query=f"{sub}.{TUNNEL['domain']}",
                             qtype="TXT", rcode="NOERROR", resolver="10.0.0.53", unit="UES", country="ES"))
    if d == OLD_IOC["day"]:
        for _ in range(40):
            rows.append(dict(ts=iso(ts(d, rng, hour=rng.randint(2, 4))), client_ip=OLD_IOC["host"],
                             query=f"cdn.{OLD_IOC['domain']}", qtype="A", rcode="NOERROR",
                             resolver="10.0.0.53", unit="UES", country="ES"))
    return rows

def gen_netflow(d, rng, n):
    rows = []
    for _ in range(n):
        u, c = unit(rng)
        rows.append(dict(ts=iso(ts(d, rng)), src_ip=rng.choice(INTERNAL_HOSTS), dst_ip=rng.choice(EXTERNAL_IPS),
                         src_port=rng.randint(1024, 65535), dst_port=rng.choice([443, 443, 443, 80, 53, 22, 3389]),
                         proto=rng.choice(["TCP", "TCP", "UDP"]), bytes=int(rng.lognormvariate(9, 1.5)),
                         packets=rng.randint(1, 500), duration_ms=rng.randint(10, 60000), unit=u, country=c))
    if d == EXFIL["day"]:
        chunk = EXFIL["gb"] * 1024 ** 3 // 50
        for i in range(50):
            rows.append(dict(ts=iso(ts(d, rng, hour=3, minute=i)), src_ip=EXFIL["host"], dst_ip=EXFIL["dst"],
                             src_port=rng.randint(1024, 65535), dst_port=443, proto="TCP", bytes=chunk,
                             packets=chunk // 1400, duration_ms=55000, unit="UES", country="ES"))
    return rows

def gen_suricata(d, rng, n):
    sigs = [("ET SCAN Nmap Scripting Engine", 2009358, 2, "Attempted Information Leak"),
            ("ET POLICY SSH session in progress", 2001978, 3, "Misc activity"),
            ("ET WEB_SERVER SQL Injection Attempt", 2006445, 1, "Web Application Attack")]
    rows = []
    for _ in range(n):
        s = rng.choice(sigs)
        u, c = unit(rng)
        rows.append(dict(timestamp=iso(ts(d, rng)), event_type="alert", src_ip=rng.choice(EXTERNAL_IPS),
                         src_port=rng.randint(1024, 65535), dest_ip=rng.choice(INTERNAL_HOSTS), dest_port=443,
                         proto="TCP", alert=dict(signature=s[0], signature_id=s[1], severity=s[2], category=s[3]),
                         unit=u, country=c))
    if d == EXFIL["day"]:
        rows.append(dict(timestamp=iso(ts(d, rng, hour=3, minute=5)), event_type="alert", src_ip=EXFIL["host"],
                         src_port=51515, dest_ip=EXFIL["dst"], dest_port=443, proto="TCP",
                         alert=dict(signature="ET POLICY Large outbound TLS transfer to rare destination",
                                    signature_id=2900001, severity=1, category="Potential Corporate Privacy Violation"),
                         unit="UES", country="ES"))
    return rows

def gen_ad(d, rng, n):
    rows = []
    for _ in range(n):
        u, c = unit(rng)
        ok = rng.random() > 0.05
        rows.append(dict(TimeCreated=iso(ts(d, rng)), EventID=4624 if ok else 4625,
                         TargetUserName=rng.choice(USERS + SERVICE_ACCOUNTS), IpAddress=rng.choice(INTERNAL_HOSTS),
                         Computer=rng.choice(["DC-MAD-01", "DC-BCN-01", "DC-SAO-01"]),
                         LogonType=rng.choice([2, 3, 3, 10]), unit=u, country=c))
    if d == BRUTE["day"]:
        base = dict(TargetUserName=BRUTE["user"], IpAddress=BRUTE["ip"], Computer=BRUTE["host"],
                    LogonType=3, unit="UES", country="ES")
        for i in range(60):
            rows.append(dict(TimeCreated=iso(ts(d, rng, hour=2, minute=10 + i // 10, second=(i * 7) % 60)),
                             EventID=4625, **base))
        rows.append(dict(TimeCreated=iso(ts(d, rng, hour=2, minute=17, second=0)), EventID=4624, **base))
        rows.append(dict(TimeCreated=iso(ts(d, rng, hour=2, minute=17, second=30)), EventID=4672, **base))
    return rows

def gen_fw(d, rng, n):
    lines = []
    for _ in range(n):
        fw, vendor = rng.choice(FIREWALLS)
        t = ts(d, rng)
        if fw == FW_GAP["fw"] and t > FW_GAP["after"]:
            continue  # source that stops sending (source health)
        action = rng.choice(["allow"] * 8 + ["deny"] * 2)
        lines.append(f"<134>{iso(t)} {fw} vendor={vendor} action={action} src={rng.choice(INTERNAL_HOSTS)} "
                     f"dst={rng.choice(EXTERNAL_IPS)} dport={rng.choice([443, 80, 53, 22])} "
                     f"proto={rng.choice(['tcp', 'udp'])} user={rng.choice(USERS)}")
    return lines

def gen_o365(d, rng, n):
    ops = ["UserLoggedIn", "FileAccessed", "FileModified", "MailItemsAccessed", "FileDownloaded"]
    rows = []
    for _ in range(n):
        u, c = unit(rng)
        rows.append(dict(CreationTime=iso(ts(d, rng)), Operation=rng.choice(ops), UserId=f"{rng.choice(USERS)}@corp.example",
                         ClientIP=rng.choice(EXTERNAL_IPS[:30]), Workload=rng.choice(["SharePoint", "Exchange", "OneDrive"]),
                         ResultStatus="Succeeded", unit=u, country=c))
    if d == O365["day"]:
        for i in range(500):
            rows.append(dict(CreationTime=iso(ts(d, rng, hour=23, minute=i % 60)), Operation="FileDownloaded",
                             UserId=f"{O365['user']}@corp.example", ClientIP=O365["ip"], Workload="SharePoint",
                             ResultStatus="Succeeded", unit="UES", country="ES"))
    return rows

def gen_sim(d, rng, n):
    rows = []
    stores = [f"S-{i:04d}" for i in range(400, 480)]
    agents = [f"A-{i:04d}" for i in range(1100, 1180)]
    in_ring = SIM_RING["start"] <= d < SIM_RING["start"] + timedelta(days=SIM_RING["days"])
    for _ in range(n):
        u, c = unit(rng)
        fraud = rng.random() < 0.02
        rows.append(dict(request_ts=iso(ts(d, rng)), msisdn=f"+34 6{rng.randint(10000000, 99999999)}",
                         request_type=rng.choice(["SIM_SWAP", "PORT_OUT", "ACTIVATION"]),
                         channel=rng.choice(["store", "online", "call_center"]),
                         store_id=rng.choice(stores), agent_id=rng.choice(agents),
                         new_device=int(fraud or rng.random() < 0.2), new_location=int(fraud or rng.random() < 0.1),
                         requests_24h=rng.randint(3, 6) if fraud else rng.randint(1, 2),
                         account_age_days=rng.randint(1, 60) if fraud else rng.randint(30, 4000),
                         is_fraud=int(fraud) if d < SIM_RING["start"] else None, unit=u, country=c))
    if in_ring:
        for _ in range(25):
            rows.append(dict(request_ts=iso(ts(d, rng, hour=rng.randint(9, 20))),
                             msisdn=f"+34 6{rng.randint(10000000, 99999999)}", request_type="SIM_SWAP",
                             channel="store", store_id=SIM_RING["store"], agent_id=SIM_RING["agent"],
                             new_device=1, new_location=1, requests_24h=rng.randint(3, 5),
                             account_age_days=rng.randint(200, 3000), is_fraud=None, unit="UES", country="ES"))
    return rows

SOURCES = {  # name: (generator, rows/day, extension)
    "dns": (gen_dns, 2000, "json"),
    "netflow": (gen_netflow, 2000, "json"),
    "suricata": (gen_suricata, 60, "json"),
    "ad": (gen_ad, 600, "json"),
    "fw": (gen_fw, 1200, "log"),
    "o365": (gen_o365, 300, "json"),
    "sim": (gen_sim, 150, "csv"),
}

def serialize(rows, ext):
    if ext == "json":
        return "\n".join(json.dumps(r, separators=(",", ":")) for r in rows).encode()
    if ext == "log":
        return ("\n".join(rows) + "\n").encode()
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode()

def ioc_csv(rng):
    rows = [dict(indicator=i, type=t, source="cti-feed-demo", confidence=rng.randint(70, 100),
                 first_seen="2026-01-01") for i, t in IOCS]
    # Filler: documentation IPs (RFC 5737) that do not appear in the traffic
    rows += [dict(indicator=f"198.51.100.{i}", type="ip", source="cti-feed-demo",
                  confidence=rng.randint(40, 90), first_seen="2026-01-01") for i in range(1, 51)]
    return serialize(rows, "csv")

class Uploader:
    """Resilient write/upload: bounded pool, retries with backoff and --resume.

    Generation stays sequential (a single RNG with SEED) so the output
    is deterministic; only the I/O (S3 or disk) runs in parallel.
    """

    def __init__(self, a):
        self.a = a
        self.s3 = None
        self.transfer = None
        if a.upload:
            import boto3
            from boto3.s3.transfer import TransferConfig
            from botocore.config import Config
            # Adaptive retries and timeouts: never hangs waiting on S3
            cfg = Config(retries={"mode": "adaptive", "max_attempts": 10},
                         connect_timeout=10, read_timeout=60,
                         max_pool_connections=max(10, a.workers * 2))
            self.s3 = boto3.client("s3", config=cfg)
            self.transfer = TransferConfig(multipart_threshold=8 * 1024 ** 2,
                                           multipart_chunksize=8 * 1024 ** 2,
                                           max_concurrency=4, use_threads=True)
        self.pool = ThreadPoolExecutor(max_workers=a.workers)
        # Caps pending files in memory (backpressure on the generator)
        self.slots = threading.BoundedSemaphore(a.workers * 4)
        self.lock = threading.Lock()
        self.futures = []
        self.done = self.skipped = 0
        self.failed = []

    def _exists_same_size(self, key, size):
        if self.s3:
            from botocore.exceptions import ClientError
            try:
                return self.s3.head_object(Bucket=self.a.bucket, Key=key)["ContentLength"] == size
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                    return False
                raise
        path = Path(self.a.local) / key
        return path.is_file() and path.stat().st_size == size

    def _write(self, key, data):
        if self.s3:
            self.s3.upload_fileobj(io.BytesIO(data), self.a.bucket, key, Config=self.transfer)
        else:
            path = Path(self.a.local) / key
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".part")  # atomic write
            tmp.write_bytes(data)
            tmp.replace(path)

    def _task(self, key, data):
        try:
            for attempt in range(1, MAX_FILE_RETRIES + 1):
                try:
                    if self.a.resume and self._exists_same_size(key, len(data)):
                        self._progress(skipped=True)
                        return
                    self._write(key, data)
                    self._progress()
                    return
                except Exception as e:  # noqa: BLE001 - any I/O failure is retried
                    if attempt == MAX_FILE_RETRIES:
                        with self.lock:
                            self.failed.append((key, repr(e)))
                        print(f"ERROR {key}: {e!r} (after {attempt} attempts)", file=sys.stderr, flush=True)
                        return
                    wait = min(30, 2 ** attempt) + random.random()  # exponential backoff + jitter
                    print(f"Retry {attempt}/{MAX_FILE_RETRIES} {key} in {wait:.1f}s: {e!r}",
                          file=sys.stderr, flush=True)
                    time.sleep(wait)
        finally:
            self.slots.release()

    def _progress(self, skipped=False):
        with self.lock:
            self.done += 1
            self.skipped += skipped
            if self.done % self.a.progress_every == 0:
                print(f"[progress] {self.done} files ({self.skipped} skipped by --resume, "
                      f"{len(self.failed)} failed)", flush=True)

    def put(self, key, data, compress=True):
        if compress:
            data = gzip.compress(data, mtime=0)  # fixed mtime: deterministic bytes (--resume by size)
        self.slots.acquire()
        self.futures.append(self.pool.submit(self._task, key, data))

    def close(self):
        for f in self.futures:
            f.result()
        self.pool.shutdown(wait=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--local", help="local output directory")
    p.add_argument("--upload", action="store_true", help="upload to S3")
    p.add_argument("--bucket", default=BUCKET)
    p.add_argument("--scale", type=float, default=1.0, help="volume multiplier")
    p.add_argument("--workers", type=int, default=8, help="parallel uploads/writes")
    p.add_argument("--resume", action="store_true",
                   help="skip objects that already exist with the same size")
    p.add_argument("--progress-every", type=int, default=100, help="progress line every N files")
    a = p.parse_args()
    if not a.local and not a.upload:
        p.error("usa --local DIR o --upload")
    if a.workers < 1 or a.progress_every < 1:
        p.error("--workers and --progress-every must be >= 1")

    up = Uploader(a)
    rng = random.Random(SEED)
    counts = {s: 0 for s in SOURCES}
    try:
        for i in range(DAYS):
            d = END_DATE - timedelta(days=DAYS - 1 - i)
            for name, (fn, n, ext) in SOURCES.items():
                rows = fn(d, rng, int(n * a.scale))
                if not rows:
                    continue
                counts[name] += len(rows)
                up.put(f"{name}/{d:%Y/%m/%d}/{name}_{d:%Y%m%d}.{ext}.gz", serialize(rows, ext))
        up.put("ioc/ioc_feed.csv.gz", ioc_csv(rng))
        for f in sorted(Path(__file__).resolve().parent.parent.joinpath("runbooks").glob("*.md")):
            up.put(f"runbooks/{f.name}", f.read_bytes(), compress=False)
    finally:
        up.close()
    print("Rows generated:", json.dumps(counts, indent=1))
    print(f"Files: {up.done} processed, {up.skipped} skipped (--resume), {len(up.failed)} failed")
    if up.failed:
        print("Failed (re-run with --resume to retry only these):", file=sys.stderr)
        for key, err in up.failed:
            print(f"  {key}: {err}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
