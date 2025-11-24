# Protocol Analyzer (*`protocol-analyzer.py`* — count & pps)

Analyzes amplification-attack sessions by protocol across Russia/Ukraine (RU/UA) using both count and pps shares.
The script builds monthly stacks and two combined tables covering
ALL, RU-all, UA-all, and six honeypot scopes (RU/UA × agnostic / proxied / emulated).

---

## What the Script Reads

- Input files: `all_v2/YYYY/YYYY-MM.csv`
- Required columns:

| Column             | Description                       |
| ------------------ | --------------------------------- |
| `t_start`, `t_end` | UTC timestamps (parseable to UTC) |
| `dport`            | Destination port                  |
| `countrycode`      | e.g., RU / UA                     |
| `consensus_rule`   | Keep strict only                  |
| `packets`          | Packet count per session          |
| `honeypot_type`    | agnostic / proxied / emulated     |

---

## Key Concepts & Helper Functions

| Concept              | Function                                                 | Description                                                                  |
| -------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Protocol mapping     | `map_port_to_proto()`                                    | Maps known UDP amplification ports to protocol names (DNS, NTP, SSDP, etc.). |
| Protocol collapsing  | `canonical_protocol()`                                   | Keeps only “important” protocols; merges others into “Others.”               |
| Time conversion      | `to_utc()`, `week_bounds_monday()`, `iter_week_starts()` | Normalizes timestamps to UTC and iterates weekly Monday-start intervals.     |
| Scope initialization | `mk_scope_bucket()`                                      | Creates nested dicts `{counts/packets/dur}[protocol][week]` for each scope.  |
| DataFrame conversion | `dict_to_week_df()`                                      | Converts nested weekly dicts into Pandas DataFrames for later aggregation.   |

### COUNT

* Number of active sessions in each ISO week.
* A single session spanning multiple weeks is counted once per week it overlaps.

### PPS

[
PPS = \frac{\sum packets}{\sum duration_\text{(seconds)}} \text{ per month and protocol}
]

### Scopes

| Type                       | Description                                                                         | Examples                                                                               |
| ---------------------------| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Base scopes                | Overall country-level data buckets                                                  | `ALL`, `RU`, `UA`                                                                      |
| Honeypot scopes (c-scopes) | For each honeypot type (agnostic / proxied / emulated), data grouped by ALL, RU, UA | `RU-agnostic`, `RU-proxied`, `RU-emulated`, `UA-agnostic`, `UA-proxied`, `UA-emulated` |

---

## Processing Pipeline (Main Functions)

| Step                   | Function                                                                 | Description                                                           |
| -----------------------| ------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| 1. Enumerate CSVs      | `enumerate_all_files()`                                                  | Finds all input CSVs by year/month.                                   |
| 2. Verify structure    | `ensure_columns()`                                                       | Checks if required columns exist.                                     |
| 3. Load in chunks      | Loop inside `process_all()`                                              | Reads 200k-row chunks to avoid memory overflow.                       |
| 4. Filter valid rows   | `process_all()`                                                          | Keeps only RU/UA + strict + valid start/end times.                    |
| 5. Label protocols     | `map_port_to_proto() → canonical_protocol()`                             | Maps each row’s port to a protocol category.                          |
| 6. Weekly distribution | Inside `process_all()`                                                   | Splits each session by week, computes overlap fractions.              |
| 7. Accumulate stats    | `base_scopes` & `c_scopes` updates                                       | Adds `count`, `packets`, and `duration` values per (week × protocol). |
| 8. Weekly → Monthly    | `process_scope_dual()`                                                   | Resamples weekly DataFrames to monthly totals; computes % shares.     |
| 9. Visualization       | `stacked_area_monthly()` & `panel_top10_monthly_share_by_honeypot_2x3()` | Draws monthly protocol distribution and 2×3 panel plots.              |
| 10. Tables (CSV/TeX)   | `write_six_scopes_cnt_pps()` & `write_all_ru_ua_and_six_cnt_pps()`       | Outputs LaTeX-ready tables with COUNT/PPS by scope.                   |
| 11. Entrypoint         | `main()`                                                                 | Runs the entire process sequentially.                                 |

---

## Outputs

All files are saved under `OUTDIR` (default: `out_protocol`).

### Figures

* `monthly_share_protocol_<SCOPE>_count.pdf`
* `monthly_share_protocol_<SCOPE>_pps.pdf`
   * (For RU/UA: alias → `overall_russia_*`, `overall_ukraine_*`)

* 2×3 Honeypot Panels
  * `panel_top10_monthly_share_by_honeypot_2x3_count.(png|pdf)`
  * `panel_top10_monthly_share_by_honeypot_2x3_pps.(png|pdf)`

### Tables (CSV + LaTeX)

#### Six Scopes Only

* `overall_percentages_six_scopes_cnt_pps.csv`
* `table_overall_percentages_six_scopes_cnt_pps.tex`

  * Columns: RU-agn.(C,P), RU-prox.(C,P), RU-emul.(C,P), UA-agn.(C,P), UA-prox.(C,P), UA-emul.(C,P)

#### ALL + RU-all + UA-all + Six Scopes

* `overall_percentages_all_ru_ua_and_six_cnt_pps.csv`
* `table_overall_percentages_all_ru_ua_and_six_cnt_pps.tex`

  * Columns: ALL(C,P), RU-all(C,P), UA-all(C,P), plus the six above

### Totals 

* `monthly_totals_<SCOPE>.csv` — monthly session totals (COUNT baseline)
* `weekly_totals_<SCOPE>.csv` — weekly session totals

> `PPS` shows normalized packet rate per month & protocol; `COUNT` shows weekly presence of sessions → long sessions influence multiple weeks.

---

## How to Run

```bash
# 1) Place monthly CSVs under: all_v2/YYYY/YYYY-MM.csv
# 2) (optional) adjust YEARS / MONTHS_BY_YEAR in the script

python3 protocol-analyzer.py
```

### Optional Tweaks

* `CHUNKSIZE` — balance speed vs. memory
* `OUTDIR` — change output directory
* `PORT_TO_PROTO` — add/remove protocol mappings
* `TARGET_COUNTRIES` — restrict to RU or UA only
