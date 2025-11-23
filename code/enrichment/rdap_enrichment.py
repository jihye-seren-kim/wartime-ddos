#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RDAP Enrichment with sharding and multi-threading:

This script enriches monthly CSV partitions with RDAP metadata for source IPs, using sharding across processes and multi-threaded lookups per file.
It applies a token-bucket rate limiter and exponential backoff, writes results to a JSONL cache via a dedicated append-only thread, 
and can skip CDN/cloud infrastructure using ASN/domain/org heuristics. 
For each IP it merges normalized RDAP fields (country, org/name, CIDR, RIR, error) back into the original rows 
and adds two consensus columns that reconcile RU/UA labels between the dataset and RDAP (“strict / mm_only / rdap_only / conflict”).
Inputs under `PART_DIR` are mirrored to `OUT_DIR` with the same subfolder structure, 
with options to shard the workload (`SHARD_TOTAL/SHARD_IDX`) and skip files that already have outputs. 
Progress and errors are tracked in `_progress.jsonl` and `_errors.txt`, and retries can be enabled for failed or incomplete cache entries.

Input:
  PART_DIR/<YYYY>/<YYYY-MM>.csv or PART_DIR/*.csv
Output:
  OUT_DIR/<YYYY>/<YYYY-MM>.csv
  (extra columns) rdap_ok, rdap_net_cc, rdap_org, rdap_cidr, rir, rdap_error, country_consensus, consensus_rule

Environment examples:
  export RDAP_CACHE=out_amp_wartime/rdap_cache_v2.jsonl
  export OUT_DIR=out_amp_wartime/enriched_monthly_rdap/all_v2
  export SKIP_IF_EXISTS=0 RDAP_ONLY_RUUA=1
  export RDAP_RETRY_BAD_CACHE=1 RDAP_RETRY_EMPTY_CC=1
  export RDAP_WORKERS=64 RDAP_QPS=6 RDAP_BURST=24
  export STRICT_ONLY=0 SHARD_TOTAL=4

Sharded runs:
  SHARD_IDX=0 python3 rdap_enrichment.py
  SHARD_IDX=1 python3 rdap_enrichment.py
  SHARD_IDX=2 python3 rdap_enrichment.py
  SHARD_IDX=3 python3 rdap_enrichment.py

Quickstart (single-process, no sharding):
  PART_DIR="out_amp_wartime/enriched_monthly/all" \
  OUT_DIR="out_amp_wartime/enriched_monthly_rdap/all" \
  python3 rdap_enrichment.py

Required input columns:
  - `src` (if absent, the script will use `target` to populate `src`)
  - Optional but helpful: `countrycode`, `asnum`, `asorg`/`org`/`isp`, `domain`

Output columns (added by this script):
  - `rdap_ok`, `rdap_net_cc`, `rdap_org`, `rdap_cidr`, `rir`, `rdap_error`
  - `country_consensus` (resolved RU/UA label) and `consensus_rule` ∈ {strict, mm_only, rdap_only, conflict, no_ru_ua}
"""

import os, time, json, sys, threading, re, random
from queue import Queue
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from ipwhois import IPWhois
from tqdm import tqdm

# input and output configuration
PART_DIR        = Path(os.environ.get("PART_DIR", "out_amp_wartime/enriched_monthly/all"))
OUT_DIR         = Path(os.environ.get("OUT_DIR",  "out_amp_wartime/enriched_monthly_rdap/all")); OUT_DIR.mkdir(parents=True, exist_ok=True)
RDAP_CACHE      = Path(os.environ.get("RDAP_CACHE", "out_amp_wartime/rdap_cache.jsonl"))

# RDAP lookup behavior
RDAP_WORKERS    = int(os.environ.get("RDAP_WORKERS", "48"))
RDAP_QPS        = float(os.environ.get("RDAP_QPS", "12"))         
RDAP_BURST      = int(os.environ.get("RDAP_BURST", "36"))          
RDAP_BUDGET     = int(os.environ.get("RDAP_BUDGET", "0"))          

# RDAP cache and retry settings
RDAP_RETRY_BAD_CACHE = int(os.environ.get("RDAP_RETRY_BAD_CACHE", "1"))
RDAP_RETRY_EMPTY_CC  = int(os.environ.get("RDAP_RETRY_EMPTY_CC", "1"))  

# filtering and labeling options
RDAP_ONLY_RUUA  = int(os.environ.get("RDAP_ONLY_RUUA", "0"))
STRICT_ONLY     = int(os.environ.get("STRICT_ONLY", "0"))

# sharding and parallel execution
SHARD_TOTAL     = int(os.environ.get("SHARD_TOTAL", "1"))
SHARD_IDX       = int(os.environ.get("SHARD_IDX", "0"))
SKIP_IF_EXISTS  = int(os.environ.get("SKIP_IF_EXISTS", "1"))

# CDN / cloud exclusion
CDN_EXCLUDE     = int(os.environ.get("CDN_EXCLUDE", "1"))

# progress display and logging
TQDM_DISABLE = bool(int(os.environ.get("TQDM_DISABLE", "0")))
TQDM_MININTERVAL = float(os.environ.get("TQDM_MININTERVAL", "0.2"))

# default CDN/Cloud ASN list
_DEFAULT_CDN_ASNS = [
    13335, 20940, 32787, 54113, 199524, 12989,
    16509, 14618, 15169, 8075, 31898, 45102, 20473, 14061, 63949,
    16276, 24940, 9009, 60781, 32934, 174, 262254, 57724, 209242, 132203
]
_env_asns = [x.strip() for x in os.environ.get("CDN_ASNS","").split(",") if x.strip()]
try:
    CDN_ASNS = {int(x) for x in _env_asns} if _env_asns else set(_DEFAULT_CDN_ASNS)
except Exception:
    CDN_ASNS = set(_DEFAULT_CDN_ASNS)

# default CDN/Cloud domain keywords (can be expanded)
_DEFAULT_DOMAIN_KEYS = [
    "cloudflare","akamai","amazonaws","cloudfront","fastly","cdn",
    "googleusercontent","azure","aliyuncs","oraclecloud",
    "linodeusercontent","digitaloceanspaces","edgesuite","edgekey",
    "cdn77","gcore","stackpath"
]
CDN_DOMAIN_KEYS = [k.strip().lower() for k in os.environ.get("CDN_DOMAIN_KEYS", "").split(",") if k.strip()] or _DEFAULT_DOMAIN_KEYS

# default CDN/Cloud org keywords (can be expanded)
_DEFAULT_ORG_KEYS = [
    "cloudflare","akamai","fastly","amazon","aws","google","microsoft",
    "azure","oracle","alibaba","tencent","linode","digitalocean","ovh",
    "hetzner","meta","facebook","leaseweb","g-core","gcore","stackpath",
    "ddos-guard","ddos guard","qrator"
]
CDN_ORG_KEYS = [k.strip().lower() for k in os.environ.get("CDN_ORG_KEYS","").split(",") if k.strip()] or _DEFAULT_ORG_KEYS

RUUA = {"RU":"Russia", "UA":"Ukraine"}

PROGRESS_JOURNAL = OUT_DIR / "_progress.jsonl"
ERRORS_FILE      = OUT_DIR / "_errors.txt"

def _tqdm_disable_default():
    return TQDM_DISABLE or (not sys.stdout.isatty())

def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def write_atomic(path: Path, df: pd.DataFrame):
    # atomic write: write to .tmp then move
    tmp = Path(str(path) + ".tmp")
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)

def load_cache(path: Path) -> dict:
    # load JSONL cache into memory {ip: data}
    d = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    o = json.loads(line)
                    d[str(o["ip"])] = o["data"]
                except Exception:
                    pass
    return d

# fcntl file locks (no-op on platforms without fcntl)
try:
    import fcntl
    def _lock(f):  fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    def _unlock(f): fcntl.flock(f.fileno(), fcntl.LOCK_UN)
except Exception:
    def _lock(f):   return None
    def _unlock(f): return None

# dedicated async cache writer (append-only JSONL)
_cache_q = Queue(maxsize=10000)
def cache_writer_thread(path: Path, stop_evt: threading.Event):
    f = path.open("a", encoding="utf-8")
    try:
        while not stop_evt.is_set() or not _cache_q.empty():
            try:
                ip, data = _cache_q.get(timeout=0.2)
            except Exception:
                continue
            try:
                _lock(f)
                f.write(json.dumps({"ip": ip, "data": data}, ensure_ascii=False) + "\n")
                f.flush()
            finally:
                try: _unlock(f)
                except Exception: pass
    finally:
        f.flush(); f.close()

def append_progress(obj: dict):
    with PROGRESS_JOURNAL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def append_error(msg: str):
    with ERRORS_FILE.open("a", encoding="utf-8") as f:
        f.write(msg.rstrip() + "\n")

# RDAP lookup with signature compatibility
def _lookup_rdap_compat(ip: str, *, asn_methods=None, timeout=12,
                        retry_count=1, rate_limit_timeout=60):
    obj = IPWhois(ip)
    attempts = [
        {"asn_methods": asn_methods, "timeout": timeout,
         "retry_count": retry_count, "rate_limit_timeout": rate_limit_timeout},
        {"asn_methods": asn_methods, "retry_count": retry_count,
         "rate_limit_timeout": rate_limit_timeout},
        {"asn_methods": asn_methods, "retry_count": retry_count},
        {"asn_methods": asn_methods},
        {}
    ]
    last_err = None
    for kw in attempts:
        try:
            return obj.lookup_rdap(**kw)
        except TypeError as e:
            last_err = str(e)
            continue
    raise TypeError(last_err or "lookup_rdap signature not supported")

# token bucket state
_tb_lock = threading.Lock()
_tb_tokens = float(RDAP_BURST)
_tb_last = time.monotonic()

def _rate_limit_token_bucket():
    # consume one token or return required wait time if insufficient tokens
    global _tb_tokens, _tb_last
    now = time.monotonic()
    with _tb_lock:
        add = (now - _tb_last) * RDAP_QPS
        if add > 0:
            _tb_tokens = min(RDAP_BURST, _tb_tokens + add)
            _tb_last = now
        if _tb_tokens >= 1.0:
            _tb_tokens -= 1.0
            return 0.0
        need = 1.0 - _tb_tokens
        wait = need / RDAP_QPS
    return max(0.0, wait)

def _with_backoff(func, *a, **kw):
    # simple exponential backoff for rate-limit-like errors
    delay = 0.5
    for _ in range(6):
        try:
            return func(*a, **kw)
        except Exception as e:
            msg = str(e).lower()
            if "429" in msg or "rate" in msg or "too many" in msg:
                time.sleep(delay + random.random()*delay*0.2)
                delay = min(delay*2, 16)
                continue
            raise
    return func(*a, **kw)

def rdap_lookup(ip: str) -> dict:
    # RDAP lookup with rate-limit + backoff; return normalized dict
    try:
        wait = _rate_limit_token_bucket()
        if wait > 0:
            time.sleep(wait)
        r = _with_backoff(
            _lookup_rdap_compat,
            ip, asn_methods=['http','whois'],
            timeout=12, retry_count=1, rate_limit_timeout=60
        )
        net = r.get("network") or {}
        return {
            "ok": True,
            "rdap_net_cc": (net.get("country") or "").upper() or None,
            "rdap_org": (net.get("name") or r.get("asn_description")),
            "rdap_cidr": net.get("cidr"),
            "rir": r.get("nir") or r.get("asn_registry"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _norm_cc_series(s: pd.Series) -> pd.Series:
    s = s.astype("string").str.upper()
    return s.where(~s.isin(["", "NA", "N/A", "NONE", "NULL", "NAN"]), "")

_cdn_dom_re = re.compile("|".join(map(re.escape, CDN_DOMAIN_KEYS)), re.I)
_cdn_org_re = re.compile("|".join(map(re.escape, CDN_ORG_KEYS)), re.I)

def exclude_cdn(df: pd.DataFrame) -> pd.DataFrame:
    dom = df.get("domain")
    if dom is None:
        m_dom = pd.Series(False, index=df.index)
    else:
        m_dom = dom.astype("string", copy=False).str.contains(_cdn_dom_re, na=False)
    asn = df.get("asnum")
    if asn is None:
        m_asn = pd.Series(False, index=df.index)
    else:
        m_asn = pd.to_numeric(asn, errors="coerce").astype("Int64").isin(pd.Series(list(CDN_ASNS), dtype="Int64"))
    org_cols = [c for c in ("asorg","org","isp","rdap_org") if c in df.columns]
    if org_cols:
        joined = df[org_cols].astype("string").fillna("").agg(" ".join, axis=1)
        m_org = joined.str.contains(_cdn_org_re, na=False)
    else:
        m_org = pd.Series(False, index=df.index)
    mask = ~(m_dom | m_asn | m_org)
    return df.loc[mask].copy()

def consensus_cols(out: pd.DataFrame, strict: bool):
    # compute (country_consensus, consensus rule) for RU/UA
    mm = _norm_cc_series(out.get("countrycode")) if "countrycode" in out.columns else pd.Series("", index=out.index)
    rd = _norm_cc_series(out.get("rdap_net_cc"))

    cons = pd.Series(index=out.index, dtype="object")                 
    rule = pd.Series("no_ru_ua", index=out.index, dtype="string")

    # 1) 'strict': both in RU/UA and equal
    m_both   = mm.isin(RUUA) & rd.isin(RUUA)
    m_strict = m_both & (mm == rd)
    cons[m_strict] = mm[m_strict].map(RUUA)
    rule[m_strict] = "strict"

    if strict:
        return cons, rule

    # 2) conflict: both RU/UA but different
    m_conflict = m_both & (mm != rd)
    rule[m_conflict] = "conflict"

    # 3) mm_only: only CSV says RU/UA
    m_mm = mm.isin(RUUA) & ~m_strict & ~m_conflict
    cons[m_mm]  = mm[m_mm].map(RUUA)
    rule[m_mm]  = "mm_only"

    # 4) rdap_only: only RDAP says RU/UA 
    m_rd = rd.isin(RUUA) & ~m_strict & ~m_conflict & ~m_mm
    cons[m_rd]  = rd[m_rd].map(RUUA)
    rule[m_rd]  = "rdap_only"

    return cons, rule

def process_csv(path: Path, cache: dict) -> pd.DataFrame:
    # per-file pipeline:
    # 1) read_csv 2) CDN exclusion 3) decide RDAP IPs 4) parallel RDAP 5) merge + consensus
    df = pd.read_csv(path, engine="c", low_memory=False, encoding="utf-8", on_bad_lines="skip")

    if "src" not in df.columns and "target" in df.columns:
        df["src"] = df["target"]
    
    if "asnum" in df.columns:
        df["asnum"] = pd.to_numeric(df["asnum"], errors="coerce").astype("Int64")

    if CDN_EXCLUDE:
        before = len(df)
        df = exclude_cdn(df)
        log(f"[CDN] {path.name}: excluded {before - len(df):,} rows (remain {len(df):,})")

    # build unique candidate IP list
    ips = list({str(x) for x in df["src"].dropna().astype(str).unique()})

    # restrict to RU/UA candidates
    if RDAP_ONLY_RUUA and "countrycode" in df.columns:
        cand = set(df.loc[df["countrycode"].astype("string").str.upper().isin(["RU","UA"]), "src"].astype(str))
        ips = [ip for ip in ips if ip in cand]

    # decide which IPs need fresh queries
    to_query, used = [], 0
    for ip in ips:
        c = cache.get(ip)
        if not c:
            pass  
        else:
            ok = bool(c.get("ok"))
            cc = (c.get("rdap_net_cc") or "").strip().upper()
            if (not ok) and not RDAP_RETRY_BAD_CACHE:
                continue  
            if ok and cc == "" and RDAP_RETRY_EMPTY_CC:
                pass      
            elif ok:
                continue  
        if RDAP_BUDGET and used >= RDAP_BUDGET:
            break
        to_query.append(ip); used += 1

    # parallel RDAP lookups
    if to_query:
        desc = f"RDAP {path.name}"
        disable = _tqdm_disable_default()
        with tqdm(total=len(to_query), desc=desc, unit="ip", mininterval=TQDM_MININTERVAL, disable=disable) as rdap_pbar:
            with ThreadPoolExecutor(max_workers=RDAP_WORKERS) as ex:
                futs = {ex.submit(rdap_lookup, ip): ip for ip in to_query}
                for f in as_completed(futs):
                    ip = futs[f]
                    data = f.result()
                    cache[ip] = data
                    _cache_q.put((ip, data))
                    rdap_pbar.update(1)

    # build RDAP frame and merge 
    rows = []
    for ip in ips:
        r = cache.get(ip) or {}
        rows.append({
            "src": ip,
            "rdap_ok": bool(r.get("ok")) if r else None,
            "rdap_net_cc": (r.get("rdap_net_cc") or None) if r else None,
            "rdap_org": r.get("rdap_org") if r else None,
            "rdap_cidr": r.get("rdap_cidr") if r else None,
            "rir": r.get("rir") if r else None,
            "rdap_error": r.get("error") if r else None,
        })
    rd = pd.DataFrame(rows)

    out = df.merge(rd, on="src", how="left")
    # consensus columns
    cons, rule = consensus_cols(out, bool(STRICT_ONLY))
    out["country_consensus"] = cons
    out["consensus_rule"] = rule
    return out

def main():
    if not PART_DIR.exists():
        log(f"[FATAL] PART_DIR not found: {PART_DIR}")
        sys.exit(1)
        
    # load cache into memory
    cache = load_cache(RDAP_CACHE)
    
    # find input CSVs: prefer PART_DIR/YYYY/*.csv, else PART_DIR/*.csv
    all_csvs = []
    for year_dir in sorted(PART_DIR.glob("*")):
        if year_dir.is_dir():
            all_csvs.extend(sorted(year_dir.glob("*.csv")))
    if not all_csvs:
        all_csvs = sorted(PART_DIR.glob("*.csv"))
    if not all_csvs:
        log(f"[FATAL] no input CSVs under: {PART_DIR}")
        sys.exit(1)

    # shared assignment
    my_jobs = [p for i, p in enumerate(all_csvs) if (i % max(1, SHARD_TOTAL)) == SHARD_IDX]
    N = len(my_jobs)
    log(f"[RDAP] total_files={len(all_csvs)} | shard={SHARD_IDX}/{SHARD_TOTAL} → assigned={N}")

    # start background cache writer
    stop_evt = threading.Event()
    writer_t = threading.Thread(target=cache_writer_thread, args=(RDAP_CACHE, stop_evt), daemon=True)
    writer_t.start()
    
    # process files
    disable = _tqdm_disable_default()
    try:
        with tqdm(total=N, desc=f"Files shard {SHARD_IDX}/{SHARD_TOTAL}", unit="file",
                  mininterval=TQDM_MININTERVAL, disable=disable) as files_pbar:
            for csv in my_jobs:
                rel = csv.relative_to(PART_DIR)
                out_path = OUT_DIR / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)

                if SKIP_IF_EXISTS and out_path.exists():
                    files_pbar.update(1)
                    log(f"[skip] {rel} (exists)")
                    append_progress({"file": str(rel), "status":"skip_exists"})
                    continue

                try:
                    log(f"[proc] {rel} → {out_path}")
                    out = process_csv(csv, cache)
                    write_atomic(out_path, out)
                    append_progress({"file": str(rel), "status":"ok", "rows": int(len(out))})
                except Exception as e:
                    append_error(f"{rel}: {e}")
                    append_progress({"file": str(rel), "status":"error", "error": str(e)})
                    log(f"[error] {rel}: {e}")
                finally:
                    files_pbar.update(1)
    finally:
        stop_evt.set()
        writer_t.join()

    log("[DONE] all assigned files processed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("[INTERRUPTED] graceful stop")
        raise
