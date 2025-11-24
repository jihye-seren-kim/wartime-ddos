# Data Enrichment Pipelines

These two scripts prepare AmpPot honeypot logs for downstream analysis by successively enriching each record with **GeoIP** and **RDAP** metadata.
Both stages are modular, parallel-safe, and designed for reproducible monthly exports.

---

## Stage 1 — MaxMind Enrichment (`maxmind_enrichment.py`)

### Purpose

Merge and normalize raw AmpPot logs from CISPA and YNU, perform IP-level enrichment with MaxMind GeoIP2 databases, and output unified monthly partitions.

### Input

* CISPA: `amppot_monthly/amppot-YYYY-MM-DD.csv` → `honeypot_type=emulated`
* YNU: `amppot_monthly/amppot-ynu_jihye_YYYYMM.csv` → `honeypot_type=agnostic/proxied`

### Output

```
$OUTDIR/enriched_monthly_all/<scope>/<YYYY>/<YYYY-MM>.csv
(scope ∈ {all, cispa, ynu})
```

### Enriched Fields

`target`, `dport`, `t_start`, `t_end`, `packets`, `countrycode`, `city`, `latitude`, `longitude`, `loc_acc_km`, `domain`, `asnum`, `asorg`, `isp`, `org`, `contype`, `source`, `honeypot_type`

### GeoIP Databases

| Database               | Adds                                     |
| ---------------------- | ---------------------------------------- |
| GeoIP2-Country         | Country ISO code                         |
| GeoIP2-City            | City name + lat/lon + accuracy (km)      |
| GeoLite2-ASN           | ASN number + organization                |
| GeoIP2-Domain          | Domain                                   |
| GeoIP2-ISP             | ISP name + organization                  |
| GeoIP2-Connection-Type | Connection type (e.g., broadband/mobile) |

### Typical Run

```bash
export AMPPOT_INDIR=amppot_monthly
export OUTDIR=out_amp_wartime
export START=2022-01-01 END=2025-06-30
export GEOIP_COUNTRY=GeoIP2-Country.mmdb
export GEOIP_CITY=GeoIP2-City.mmdb
export GEOIP_ASN=GeoLite2-ASN.mmdb
export GEOIP_DOMAIN=GeoIP2-Domain.mmdb
export GEOIP_ISP=GeoIP2-ISP.mmdb
export GEOIP_CONTYPE=GeoIP2-Connection-Type.mmdb
python3 maxmind_enrichment.py
```

> Restrict output to certain countries:
> `COUNTRY_FILTER="RU,UA" python3 maxmind_enrichment.py`

### Processing Steps

1. Load CISPA + YNU data → unified schema
2. Normalize timestamps to UTC and apply date filters
3. Run MaxMind lookups (GeoIP country/city/ASN/etc.)
4. Fill missing fields from GeoIP values
5. Partition by year and month → CSV export

---

## Stage 2 — RDAP Enrichment (`rdap_enrichment.py`)

### Purpose

Add RDAP metadata for each IP address and derive **RU/UA consensus labels** while filtering out known CDN/cloud infrastructure.

### Input / Output

| Type   | Example                                              |
| ------ | ---------------------------------------------------- |
| Input  | `$OUTDIR/enriched_monthly_all/all/YYYY/YYYY-MM.csv`  |
| Output | `$OUTDIR/enriched_monthly_rdap/all/YYYY/YYYY-MM.csv` |

### Added Columns

`rdap_ok`, `rdap_net_cc`, `rdap_org`, `rdap_cidr`, `rir`, `rdap_error`, `country_consensus`, `consensus_rule`

### Environment Example

```bash
export PART_DIR=out_amp_wartime/enriched_monthly_all/all
export OUT_DIR=out_amp_wartime/enriched_monthly_rdap/all
export RDAP_CACHE=out_amp_wartime/rdap_cache.jsonl
export RDAP_WORKERS=64
export RDAP_QPS=6
export RDAP_BURST=24
export CDN_EXCLUDE=1
export RDAP_ONLY_RUUA=1
export SHARD_TOTAL=4
export SHARD_IDX=0
python3 rdap_enrichment.py
```

### Key Features

* Multi-threaded RDAP lookups with token-bucket rate-limit and exponential backoff
* Append-only JSONL cache for resumable runs
* Optional CDN/cloud filter (ASN / domain / org heuristics)
* `country_consensus` and `consensus_rule` resolve RU/UA label agreement between MaxMind and RDAP
* Supports sharding (`SHARD_TOTAL`, `SHARD_IDX`) for parallel processing

### Processing Steps

1. Load RDAP cache (if exists)
2. Read monthly CSV partition → apply shard filter
3. Optionally exclude CDN/cloud rows
4. Perform RDAP queries with retry and rate-limit
5. Merge results back into CSV + add consensus columns
6. Write atomically (`.tmp → .csv`) with progress and error logs

---

## End-to-End Flow

```
(AmpPot raw logs)
   │
   ├── maxmind_enrichment.py
   │     → enriched_monthly_all/<scope>/<YYYY>/<YYYY-MM>.csv
   │
   └── rdap_enrichment.py
         → enriched_monthly_rdap/<scope>/<YYYY>/<YYYY-MM>.csv
```

---

## Notes

* Both scripts are **idempotent** and safe to rerun (`SKIP_IF_EXISTS=1`).
* `RDAP_CACHE` is reused across shards or sessions for efficiency.
* Use `CDN_EXCLUDE=1` for infrastructure cleanup; false for raw coverage studies.
* Dependencies:

```bash
pip install pandas numpy tqdm ipwhois geoip2
```
