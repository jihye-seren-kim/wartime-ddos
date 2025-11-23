#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Make monthly CSV partitions from AmpPot raw inputs

Overview
- Loads and normalizes raw AmpPot CSVs from both CISPA and YNU sources into a unified schema.  
- Performs GeoIP enrichment using MaxMind databases (Country, City, ASN, Domain, ISP, Connection Type).  
- Saves the enriched data as monthly CSV partitions by year/month, ready for RDAP enrichment.  

Sources (auto-detected)
- CISPA: amppot_monthly/amppot-YYYY-MM-DD.csv  
  → source=cispa, honeypot_type=emulated  
- YNU: amppot_monthly/amppot-ynu_jihye_YYYYMM.csv  
  → source=ynu, honeypot_type=proxied/agnostic

Output
  OUTDIR/enriched_monthly_all/<scope>/<YYYY>/<YYYY-MM>.csv  
  where scope ∈ {all, cispa, ynu}

Output schema (hpdate removed)
  target(=src), dport, t_start, t_end, packets,  
  countrycode, city, latitude, longitude, loc_acc_km,  
  domain,  
  asnum, asorg,               # from ASN DB  
  isp, org, contype,          # from ISP / Connection-Type DBs  
  hostname,                   # passthrough from source if available  
  source, honeypot_type  

GeoIP Enrichment
- GEOIP_COUNTRY: GeoIP2-Country.mmdb → countrycode  
- GEOIP_CITY   : GeoIP2-City-Europe.mmdb → city, lat, lon, accuracy_km  
- GEOIP_ASN    : GeoLite2-ASN.mmdb → asnum, as_org  
- GEOIP_DOMAIN : GeoIP2-Domain.mmdb → domain  
- GEOIP_ISP    : GeoIP2-ISP.mmdb → isp, org 
- GEOIP_CONTYPE: GeoIP2-Connection-Type.mmdb → contype  

Environment variables (examples)
  export AMPPOT_INDIR=amppot_monthly  
  export OUTDIR=out_amp_wartime  
  export START=2022-01-01 END=2025-06-30  
  export GEOIP_COUNTRY=GeoIP2-Country.mmdb  
  export GEOIP_CITY=GeoIP2-City.mmdb  
  export GEOIP_ASN=GeoLite2-ASN.mmdb  
  export GEOIP_DOMAIN=GeoIP2-Domain.mmdb  
  export GEOIP_ISP=GeoIP2-ISP.mmdb  
  export GEOIP_CONTYPE=GeoIP2-Connection-Type.mmdb  

Quickstart
  python3 maxmind_enrichment.py  

  # with explicit MaxMind DBs
  GEOIP_COUNTRY=GeoIP2-Country.mmdb \
  GEOIP_ASN=GeoLite2-ASN.mmdb \
  GEOIP_DOMAIN=GeoIP2-Domain.mmdb \
  python3 maxmind_enrichment.py  

  # to filter by specific countries
  COUNTRY_FILTER="RU,UA" python3 maxmind_enrichment.py  

Pipeline linkage (next step)
- The output from this script (`OUTDIR/enriched_monthly_all/all/YYYY/YYYY-MM.csv`)
  is used as the input to the RDAP enrichment pipeline (rdap_enrichment.py),  
  which adds RDAP metadata and RU/UA consensus labels.

Notes
- Rows without valid `t_start` timestamps are dropped.  
- No shared-infrastructure exclusion is applied here (can be handled later via CDN filtering).
"""

import os, time, warnings
from pathlib import Path
import pandas as pd
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning)

# config (env)
AMPPOT_INDIR = Path(os.environ.get("AMPPOT_INDIR", "amppot_monthly"))
OUTDIR       = Path(os.environ.get("OUTDIR", "out_amp_wartime")); OUTDIR.mkdir(parents=True, exist_ok=True)
START        = pd.to_datetime(os.environ.get("START", "2022-01-01"))
END          = pd.to_datetime(os.environ.get("END",   "2025-06-30"))
COUNTRY_FILTER = [c.strip().upper() for c in os.environ.get("COUNTRY_FILTER","").split(",") if c.strip()]

GEOIP_COUNTRY = os.environ.get("GEOIP_COUNTRY")
GEOIP_CITY    = os.environ.get("GEOIP_CITY")
GEOIP_ASN     = os.environ.get("GEOIP_ASN")
GEOIP_DOMAIN  = os.environ.get("GEOIP_DOMAIN")
GEOIP_ISP     = os.environ.get("GEOIP_ISP")
GEOIP_CONTYPE = os.environ.get("GEOIP_CONTYPE")

VERBOSE = int(os.environ.get("VERBOSE", "1"))

def log(msg: str):
    if VERBOSE:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# Time helpers
def to_naive_utc(series: pd.Series) -> pd.Series:
    """Normalize to timezone-naive UTC (assumes values are UTC or parseable)."""
    dt = pd.to_datetime(series, errors="coerce", utc=True)
    return dt.dt.tz_convert(None)

def ynu_mode_to_type(mode: str, amppot: str) -> str:
    s = ((mode or "") + "|" + (amppot or "")).lower()
    return "agnostic" if "agnostic" in s else "proxied"

# GeoIP enrichment
def geoip_enrich(df: pd.DataFrame) -> pd.DataFrame:
    """
    Perform GeoIP enrichment using MaxMind databases (Country, City, ASN, Domain, ISP, Connection Type).
    If a database is missing or cannot be opened, the corresponding fields are filled with defaults.
    """

    try:
        import geoip2.database
    except Exception as e:
        log(f"[geoip] geoip2 not available: {e} (skip)")
        for c in ["geo_cc","geo_city","geo_domain","geo_asn","geo_as_org",
                  "geo_lat","geo_lon","geo_acc_km","geo_isp","geo_org","geo_contype"]:
            if c not in df: df[c] = np.nan if c in {"geo_lat","geo_lon","geo_acc_km"} else ""
        return df

    readers = {}
    def _open(key, path):
        if path and Path(path).exists():
            try:
                readers[key] = geoip2.database.Reader(path)
                log(f"[geoip] opened {key}: {path}")
            except Exception as e:
                log(f"[geoip] failed {key}: {e}")

    _open("country", GEOIP_COUNTRY)
    _open("city",    GEOIP_CITY)
    _open("asn",     GEOIP_ASN)
    _open("domain",  GEOIP_DOMAIN)
    _open("isp",     GEOIP_ISP)
    _open("contype", GEOIP_CONTYPE)

    if not readers:
        log("[geoip] no db opened; skip enrichment")
        for c in ["geo_cc","geo_city","geo_domain","geo_asn","geo_as_org",
                  "geo_lat","geo_lon","geo_acc_km","geo_isp","geo_org","geo_contype"]:
            if c not in df: df[c] = np.nan if c in {"geo_lat","geo_lon","geo_acc_km"} else ""
        return df

    ips = df["src"].dropna().unique().tolist()
    rows = []
    for ip in ips:
        row = {"src": ip}
        
        # Country
        try:
            if "country" in readers:
                r = readers["country"].country(ip)
                row["geo_cc"] = (r.country.iso_code or r.registered_country.iso_code or "")
            else:
                row["geo_cc"] = ""
        except Exception:
            row["geo_cc"] = ""

        # City + location
        try:
            if "city" in readers:
                r = readers["city"].city(ip)
                row["geo_city"] = (r.city.name or "")
                loc = getattr(r, "location", None)
                if loc is not None:
                    row["geo_lat"] = loc.latitude
                    row["geo_lon"] = loc.longitude
                    row["geo_acc_km"] = getattr(loc, "accuracy_radius", None)
                else:
                    row["geo_lat"] = np.nan
                    row["geo_lon"] = np.nan
                    row["geo_acc_km"] = np.nan
            else:
                row["geo_city"] = ""
                row["geo_lat"] = np.nan
                row["geo_lon"] = np.nan
                row["geo_acc_km"] = np.nan
        except Exception:
            row["geo_city"] = ""
            row["geo_lat"] = np.nan
            row["geo_lon"] = np.nan
            row["geo_acc_km"] = np.nan

        # ASN
        try:
            if "asn" in readers:
                r = readers["asn"].asn(ip)
                row["geo_asn"] = r.autonomous_system_number
                row["geo_as_org"] = (r.autonomous_system_organization or "")
            else:
                row["geo_asn"] = np.nan
                row["geo_as_org"] = ""
        except Exception:
            row["geo_asn"] = np.nan
            row["geo_as_org"] = ""

        # Domain
        try:
            if "domain" in readers:
                r = readers["domain"].domain(ip)
                row["geo_domain"] = getattr(r, "domain", "") or ""
            else:
                row["geo_domain"] = ""
        except Exception:
            row["geo_domain"] = ""

        # ISP / Organization
        try:
            if "isp" in readers:
                r = readers["isp"].isp(ip)
                row["geo_isp"] = getattr(r, "isp", "") or ""
                row["geo_org"] = getattr(r, "organization", "") or ""

                # ASN fallback: when ASN DB is not available, use ISP fields if present
                if "asn" not in readers:
                    asn_fallback = getattr(r, "autonomous_system_number", None)
                    asorg_fallback = getattr(r, "autonomous_system_organization", "") or ""
                    if row.get("geo_asn") is np.nan or pd.isna(row.get("geo_asn")):
                        row["geo_asn"] = asn_fallback
                    if not row.get("geo_as_org"):
                        row["geo_as_org"] = asorg_fallback
            else:
                row["geo_isp"] = ""
                row["geo_org"] = ""
        except Exception:
            row["geo_isp"] = ""
            row["geo_org"] = ""

        # Connection type
        try:
            if "contype" in readers:
                r = readers["contype"].connection_type(ip)
                row["geo_contype"] = getattr(r, "connection_type", "") or ""
            else:
                row["geo_contype"] = ""
        except Exception:
            row["geo_contype"] = ""

        rows.append(row)

    geo = pd.DataFrame(rows)
    out = df.merge(geo, on="src", how="left")

    # string fields
    for c in ["geo_cc","geo_city","geo_domain","geo_as_org","geo_isp","geo_org","geo_contype"]:
        if c in out:
            out[c] = out[c].fillna("")

    # numeric casts
    if "geo_asn" in out: out["geo_asn"] = pd.to_numeric(out["geo_asn"], errors="coerce").astype("Int64")
    for c in ["geo_lat", "geo_lon", "geo_acc_km"]:
        if c in out:
            out[c] = pd.to_numeric(out[c], errors="coerce")

    # close readers cleanly
    try:
        for rd in readers.values():
            rd.close()
    except Exception:
        pass

    return out

# Loaders
def load_cispa_files() -> pd.DataFrame:
    paths = sorted([p for p in AMPPOT_INDIR.glob("amppot-*.csv") if "ynu" not in p.name])
    log(f"[load] CISPA files matched: {len(paths)}")
    rows = []
    for i, p in enumerate(paths, 1):
        log(f"[load] CISPA [{i}/{len(paths)}] reading {p.name} ...")
        df = pd.read_csv(p, sep=",", engine="c", dtype=str, encoding="utf-8", low_memory=False)
        n0 = len(df)
        log(f"[load]   shape={df.shape}  columns={list(df.columns)}")

        # normalize columns
        if "src" not in df.columns and "target" in df.columns:
            df["src"] = df["target"]

        # timestamps → naive UTC
        if "t_start" in df.columns:
            df["t_start"] = to_naive_utc(df["t_start"])
        if "t_end" in df.columns:
            df["t_end"] = to_naive_utc(df["t_end"])

        # numeric
        if "dport" in df.columns:
            df["dport"] = pd.to_numeric(df["dport"], errors="coerce").astype("Int64")
        if "packets" in df.columns:
            df["packets"] = pd.to_numeric(df["packets"], errors="coerce").fillna(0).astype("Int64")

        df["source"] = "cispa"
        df["honeypot_type"] = "emulated"

        keep = ["dport","src","t_start","t_end","packets",
                "countrycode","city","domain","asnum","asorg","hostname",
                "source","honeypot_type"]
        rows.append(df[[c for c in keep if c in df.columns]])
        log(f"[load]   kept_columns={list(rows[-1].columns)} kept_rows={len(rows[-1])} (file_rows={n0})")
    return pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()

def load_ynu_files() -> pd.DataFrame:
    paths = sorted(AMPPOT_INDIR.glob("amppot-ynu_jihye_*.csv"))
    log(f"[load] YNU files matched: {len(paths)}")
    rows = []
    for i, p in enumerate(paths, 1):
        log(f"[load] YNU   [{i}/{len(paths)}] reading {p.name} ...")
        df = pd.read_csv(p, sep=",", engine="c", dtype=str, encoding="utf-8", low_memory=False)
        n0 = len(df)
        log(f"[load]   shape={df.shape}  columns={list(df.columns)}")

        # column mapping
        df["src"]     = df.get("target")
        df["t_start"] = df.get("starttime")
        df["t_end"]   = df.get("endtime")

        if "t_start" in df.columns:
            df["t_start"] = to_naive_utc(df["t_start"])
        if "t_end" in df.columns:
            df["t_end"]   = to_naive_utc(df["t_end"])

        if "dport" in df.columns:
            df["dport"] = pd.to_numeric(df["dport"], errors="coerce").astype("Int64")
        if "totalpacket" in df.columns:
            df["packets"] = pd.to_numeric(df["totalpacket"], errors="coerce").fillna(0).astype("Int64")

        modes = df.get("mode",   pd.Series([""]*len(df)))
        pots  = df.get("amppot", pd.Series([""]*len(df)))
        df["source"] = "ynu"
        df["honeypot_type"] = [ynu_mode_to_type(m, a) for m, a in zip(modes, pots)]

        keep = ["dport","src","t_start","t_end","packets",
                "country","countrycode","city","domain","asnum","asorg","hostname",
                "source","honeypot_type"]
        df2 = df[[c for c in keep if c in df.columns]].copy()

        before = len(df2)
        df2 = df2.drop_duplicates(subset=["src","dport","t_start","t_end","honeypot_type"], keep="first")
        log(f"[dedup: YNU by (src,dport,t_start,t_end,honeypot_type)] {p.name}: {before} -> {len(df2)}")

        rows.append(df2)
        log(f"[load]   kept_columns={list(df2.columns)} kept_rows={len(df2)} (file_rows={n0})")
    return pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()

# Load + merge + normalize
def load_all() -> pd.DataFrame:
    t0 = time.time()
    cispa = load_cispa_files()
    ynu   = load_ynu_files()

    log(f"[load] cispa rows total: {len(cispa)} | cols={list(cispa.columns)}")
    log(f"[load] ynu   rows total: {len(ynu)}   | cols={list(ynu.columns)}")

    if cispa.empty and ynu.empty:
        raise SystemExit(f"No input rows parsed. Check files under: {AMPPOT_INDIR}")

    all_df = pd.concat([cispa, ynu], ignore_index=True, sort=False)

    for c in ["t_start","t_end"]:
        if c in all_df.columns:
            all_df[c] = pd.to_datetime(all_df[c], errors="coerce")
    for c in ["dport","packets","asnum"]:
        if c in all_df.columns:
            all_df[c] = pd.to_numeric(all_df[c], errors="coerce")

    # filter by START/END using t_start
    all_df = all_df[(all_df["t_start"] >= START) & (all_df["t_start"] <= END)].copy()
    n0 = len(all_df)
    all_df = all_df[all_df["t_start"].notna()].copy()
    if len(all_df) != n0:
        log(f"[filter] dropped rows without t_start: {n0} -> {len(all_df)}")

    # GeoIP enrichment (adds cc/city/lat/lon/acc/asn/asorg/domain/isp/org/contype)
    all_df = geoip_enrich(all_df.assign(src=all_df["src"].astype(str)))

    return all_df

# Final normalized view
def make_final_view(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    # ensure column exists to avoid .get(None) errors
    if "countrycode" not in out.columns:
        out["countrycode"] = ""

    # fill country/city/domain/asn/asorg if missing, from GeoIP
    if "geo_cc" in out.columns:
        miss = out["countrycode"].isna() | (out["countrycode"].astype(str)=="")
        out.loc[miss, "countrycode"] = out.loc[miss, "geo_cc"]

    if "geo_city" in out.columns:
        if "city" not in out.columns:
            out["city"] = ""
        miss = out["city"].isna() | (out["city"].astype(str)=="")
        out.loc[miss, "city"] = out["geo_city"]

    if "geo_domain" in out.columns:
        if "domain" not in out.columns:
            out["domain"] = ""
        miss = out["domain"].isna() | (out["domain"].astype(str)=="")
        out.loc[miss, "domain"] = out["geo_domain"]

    if "geo_asn" in out.columns:
        if "asnum" not in out.columns:
            out["asnum"] = pd.Series([pd.NA]*len(out), dtype="Int64")
        else:
            out["asnum"] = pd.to_numeric(out["asnum"], errors="coerce").astype("Int64")
        out["geo_asn"] = pd.to_numeric(out["geo_asn"], errors="coerce").astype("Int64")
        miss = out["asnum"].isna()
        out.loc[miss, "asnum"] = out["geo_asn"]

    if "geo_as_org" in out.columns:
        if "asorg" not in out.columns:
            out["asorg"] = ""
        miss = out["asorg"].isna() | (out["asorg"].astype(str)=="")
        out.loc[miss, "asorg"] = out["geo_as_org"]

    # produce a clean, fixed schema:
    final = pd.DataFrame({
        "target":        out["src"].astype(str),
        "dport":         pd.to_numeric(out["dport"], errors="coerce").astype("Int64"),
        "t_start":       out["t_start"],
        "t_end":         out["t_end"],
        "packets":       pd.to_numeric(out["packets"], errors="coerce").fillna(0).astype("Int64"),

        "countrycode":   out.get("countrycode","").astype(str).str.upper(),
        "city":          out.get("city",""),
        "latitude":      pd.to_numeric(out.get("geo_lat"), errors="coerce"),
        "longitude":     pd.to_numeric(out.get("geo_lon"), errors="coerce"),
        "loc_acc_km":    pd.to_numeric(out.get("geo_acc_km"), errors="coerce"),

        "domain":        out.get("domain",""),

        "asnum":         pd.to_numeric(out.get("asnum"), errors="coerce").astype("Int64") if "asnum" in out else pd.Series([pd.NA]*len(out), dtype="Int64"),
        "asorg":         out.get("asorg","").astype(str),

        # from GeoIP2-ISP.mmdb
        "isp":           out.get("geo_isp","").astype(str),
        "org":           out.get("geo_org","").astype(str),

        # from GeoIP2-Connection-Type.mmdb
        "contype":       out.get("geo_contype","").astype(str),

        # passthrough if present in sources (e.g., YNU)
        "hostname":      out.get("hostname","").astype(str),

        "source":        out["source"].str.lower(),
        "honeypot_type": out["honeypot_type"],
    })

    if COUNTRY_FILTER:
        n0 = len(final)
        final = final[final["countrycode"].isin(COUNTRY_FILTER) | final["countrycode"].eq("")].copy()
        log(f"[filter] country {COUNTRY_FILTER}: {n0} -> {len(final)}")

    final["month"] = final["t_start"].dt.to_period("M").astype(str)
    final["year"]  = final["t_start"].dt.year.astype(int)
    log(f"[final] rows={len(final)} months={final['month'].nunique()}")
    return final

# Writer
def write_monthly_partitions(df: pd.DataFrame, scope: str):
    base = OUTDIR / "enriched_monthly_all" / scope
    base.mkdir(parents=True, exist_ok=True)
    groups = list(df.groupby(["year","month"], sort=True))
    log(f"[write] {scope}: months={len(groups)}")
    for (year, month), g in groups:
        year_dir = base / f"{year}"
        year_dir.mkdir(parents=True, exist_ok=True)
        out_path = year_dir / f"{month}.csv"
        g.drop(columns=["month","year"], errors="ignore").to_csv(out_path, index=False)
        log(f"[write] {scope} -> {out_path} (rows={len(g)})")

# Main
def main():
    t0 = time.time()
    df = load_all()
    view = make_final_view(df)

    write_monthly_partitions(view, "all")
    write_monthly_partitions(view[view["source"]=="cispa"].copy(), "cispa")
    write_monthly_partitions(view[view["source"]=="ynu"].copy(), "ynu")

    log("----- SUMMARY -----")
    try:
        log(view.groupby(["source","honeypot_type"]).size().rename("rows").to_string())
    except Exception:
        pass
    log(f"months written: {view['month'].nunique()}  total rows: {len(view)}")
    log(f"TOTAL TIME: {time.time()-t0:.1f}s")

if __name__ == "__main__":
    main()
