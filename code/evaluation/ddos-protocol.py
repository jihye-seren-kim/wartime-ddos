#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol Analyzer with COUNT and PPS — with a single combined table
covering ALL, RU-all, UA-all and six scopes (RU/UA × agnostic/proxied/emulated).

Outputs:
- overall_percentages_all_ru_ua_and_six_cnt_pps.csv
- table_overall_percentages_all_ru_ua_and_six_cnt_pps.tex
  (Columns: ALL(C,P), RU-all(C,P), UA-all(C,P),
            RU-agn.(C,P), RU-prox.(C,P), RU-emul.(C,P),
            UA-agn.(C,P), UA-prox.(C,P), UA-emul.(C,P))
- Six-scope table (cnt|pps):
  * overall_percentages_six_scopes_cnt_pps.csv
  * table_overall_percentages_six_scopes_cnt_pps.tex
- Panels (cnt / pps):
  * panel_top10_monthly_share_by_honeypot_2x3_count.(png|pdf)
  * panel_top10_monthly_share_by_honeypot_2x3_pps.(png|pdf)
  * overall_russia_monthly_share_count.pdf / overall_russia_monthly_share_pps.pdf
  * overall_ukraine_monthly_share_count.pdf / overall_ukraine_monthly_share_pps.pdf
"""

from pathlib import Path
from collections import defaultdict
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.dates import MonthLocator, DateFormatter
import matplotlib as mpl  

try:
    from tqdm.auto import tqdm
except Exception:
    def tqdm(x, *a, **k): return x

# Config
BASE_DIR = Path("all_v2")

YEARS = [2022, 2023, 2024, 2025]
MONTHS_BY_YEAR = {
    2022: list(range(1, 13)),
    2023: list(range(1, 13)),
    2024: list(range(1, 13)),
    2025: list(range(1, 7)),
}

# Input columns
START_COL   = "t_start"
END_COL     = "t_end"
PKT_COL     = "packets"
COUNTRY_COL = "countrycode"
CONS_COL    = "consensus_rule"
DPORT_COL   = "dport"
HONTYPE_COL = "honeypot_type"

TARGET_COUNTRIES = ["RU", "UA"]

CHUNKSIZE = 200_000
USECOLS_BASE = [START_COL, END_COL, COUNTRY_COL, CONS_COL, DPORT_COL, HONTYPE_COL, PKT_COL]
DTYPE_MAP = {
    START_COL: str, END_COL: str, COUNTRY_COL: str, CONS_COL: str,
    DPORT_COL: str, HONTYPE_COL: str, PKT_COL: str
}

OUTDIR = Path("out_protocol")
OUTDIR.mkdir(parents=True, exist_ok=True)

# Matplotlib style
plt.rcParams.update({
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.dpi": 160,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.color": "#9aa0a6",
})

# Port → Protocol
PORT_TO_PROTO = {
    53:   "DNS",
    69:   "TFTP",
    111:  "Portmap",
    123:  "NTP",
    137:  "NetBIOS",
    161:  "SNMP",
    177:  "XDMCP",
    1900: "SSDP",
    19:   "Chargen",
    389:  "CLDAP",
    520:  "RIP",
    11211:"Memcached",
    7:    "Echo",
    5353: "mDNS",
    3702: "WS-Discovery",
    3283: "ARD",
    5683: "CoAP",
    3478: "STUN/TURN",
    17:   "QOTD",
}

IMPORTANT_PROTOCOLS = [
    "DNS", "NTP", "WS-Discovery", "Chargen", "SNMP",
    "ARD", "CLDAP", "CoAP", "SSDP"
]

DISPLAY_ORDER = [
    "DNS", "NTP", "WS-Discovery", "SSDP", "CLDAP",
    "SNMP", "Chargen", "ARD", "CoAP", "Others"
]

# Fixed protocol colors
# \definecolor{clrDNS}{rgb}{0.1216,0.4667,0.7059}

PROTOCOL_COLORS = {
    "DNS": (0.1216, 0.4667, 0.7059),                  # clrDNS - deep blue
    "NTP": (0.6824, 0.7804, 0.9098),                  # clrNTP - light blue
    "WS-Discovery": (1.0000, 0.4980, 0.0549),         # clrWSDiscovery - vivid orange
    "SSDP": (0.8902, 0.4667, 0.7608),                 # clrSSDP - pinkish magenta
    "CLDAP": (0.1020, 0.6000, 0.2000),                # clrCLDAP - strong green
    "SNMP": (0.5569, 0.8667, 0.4235),                 # clrSNMP - soft lime green
    "Chargen": (0.8431, 0.1882, 0.1216),              # clrChargen - red
    "Apple Remote Desktop": (0.7019, 0.7019, 0.7019), # clrAppleRemoteDesktop - gray
    "CoAP": (0.5804, 0.4039, 0.7412),                 # clrCoAP - purple
    "Others": (0.75, 0.70, 0.88),                      # clrOthers - light lavender
}

def map_port_to_proto(dport_val) -> str:
    try:
        port = int(str(dport_val).strip())
    except Exception:
        return "Unknown"
    return PORT_TO_PROTO.get(port, f"port{port}")

def canonical_protocol(label: str) -> str:
    if label in IMPORTANT_PROTOCOLS:
        return label
    return "Others"

# Time helpers
def to_utc(x) -> pd.Timestamp:
    t = pd.Timestamp(x)
    if t.tz is None:
        return t.tz_localize("UTC")
    return t.tz_convert("UTC")

def week_bounds_monday(dt: pd.Timestamp):
    dt = to_utc(dt)
    start = (dt.normalize() - pd.Timedelta(days=int(dt.weekday())))
    end = start + pd.Timedelta(days=7)
    return start, end

def iter_week_starts(a_start: pd.Timestamp, a_end: pd.Timestamp):
    ws, _ = week_bounds_monday(a_start)
    we, _ = week_bounds_monday(a_end)
    cur = ws
    while cur <= we:
        yield cur
        cur += pd.Timedelta(days=7)

# IO 
def enumerate_all_files():
    files = []
    for y in YEARS:
        for m in MONTHS_BY_YEAR[y]:
            f = BASE_DIR / f"{y}" / f"{y}-{m:02d}.csv"
            if f.exists():
                files.append(f)
    return files

def ensure_columns(first_file):
    head = pd.read_csv(first_file, nrows=1)
    need = [DPORT_COL, CONS_COL, COUNTRY_COL, START_COL, END_COL, PKT_COL]
    missing = [c for c in need if c not in head.columns]
    if missing:
        raise RuntimeError(f"Missing columns {missing}. Columns: {list(head.columns)}")
    return True

# Plot helpers 
def stacked_area_monthly(df_month_proto, title, pdf_path, color_map_global):
    if df_month_proto.empty:
        return
    pct = df_month_proto.div(df_month_proto.sum(axis=1).replace(0, np.nan), axis=0) * 100.0
    pct = pct.fillna(0.0)
    fig, ax = plt.subplots(figsize=(12, 6))
    cols = [c for c in DISPLAY_ORDER if c in df_month_proto.columns]
    x = pct.index
    y = [pct[col].values for col in cols]
    colors = [color_map_global[col] for col in cols]
    ax.stackplot(x, *y, labels=cols, colors=colors, linewidth=0.5, edgecolor="white")
    ax.set_title(title)
    ax.set_ylabel("Percent (%)")
    ax.set_xlabel("Date")
    ax.set_ylim(0, 100)
    ax.set_xlim(x.min(), x.max())
    ax.margins(x=0)
    ax.xaxis.set_major_locator(MonthLocator(interval=4))
    ax.xaxis.set_major_formatter(DateFormatter("%Y-%m"))
    for lbl in ax.get_xticklabels():
        lbl.set_rotation(45); lbl.set_ha("right")
    fig.tight_layout()
    fig.savefig(pdf_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

# Global color map 
def build_global_color_map(all_labels):
    color_map = {}
    for name in DISPLAY_ORDER:
        if name in all_labels and name in PROTOCOL_COLORS:
            color_map[name] = PROTOCOL_COLORS[name]
    for name in all_labels:
        if name not in color_map:
            color_map[name] = PROTOCOL_COLORS.get("Others", (0.7, 0.7, 0.7))
    return color_map

def collapse_to_important(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    keep = [c for c in df.columns if c in IMPORTANT_PROTOCOLS]
    others_cols = [c for c in df.columns if c not in keep]
    out = pd.DataFrame(index=df.index)
    for c in IMPORTANT_PROTOCOLS:
        out[c] = df[c] if c in df.columns else 0
    out["Others"] = df[others_cols].sum(axis=1) if others_cols else 0
    out = out[[c for c in DISPLAY_ORDER if c in out.columns]]
    return out

def mk_scope_bucket():
    return {
        "counts": defaultdict(lambda: defaultdict(int)),
        "packets": defaultdict(lambda: defaultdict(float)),
        "dur": defaultdict(lambda: defaultdict(float)),
    }

def dict_to_week_df(proto_map, dtype=float):
    if not proto_map:
        return pd.DataFrame()
    weeks_sets = [set(d.keys()) for d in proto_map.values()]
    if not weeks_sets:
        return pd.DataFrame()
    weeks = sorted(set().union(*weeks_sets))
    protos = sorted(proto_map.keys())
    df = pd.DataFrame(0, index=weeks, columns=protos, dtype=dtype)
    for proto_lbl, wdict in proto_map.items():
        for wk, val in wdict.items():
            df.at[wk, proto_lbl] = df.at[wk, proto_lbl] + dtype(val)
    return df

# Process (count + pps) 
def process_scope_dual(df_week_cnt: pd.DataFrame,
                       df_week_pkt: pd.DataFrame,
                       df_week_dur: pd.DataFrame,
                       scope_name: str,
                       outdir: Path,
                       color_map_global):
    """Return (overall_count_series, overall_pps_series) with DISPLAY_ORDER index."""
    if (df_week_cnt is None or df_week_cnt.empty) and \
       (df_week_pkt is None or df_week_pkt.empty) and \
       (df_week_dur is None or df_week_dur.empty):
        print(f"[{scope_name}] No data.")
        return None, None

    # COUNT
    m_cnt_raw = (df_week_cnt.resample("MS").sum() if df_week_cnt is not None else pd.DataFrame())
    m_cnt = collapse_to_important(m_cnt_raw) if not m_cnt_raw.empty else pd.DataFrame()

    # PPS
    if df_week_pkt is not None and df_week_dur is not None and not df_week_pkt.empty and not df_week_dur.empty:
        m_pkt_raw = df_week_pkt.resample("MS").sum()
        m_dur_raw = df_week_dur.resample("MS").sum()
        m_pps_raw = m_pkt_raw / m_dur_raw.replace(0, np.nan)  # packets/sec
        m_pps = collapse_to_important(m_pps_raw.fillna(0.0))
    else:
        m_pps = pd.DataFrame()

    # Monthly stacks 
    if not m_cnt.empty:
        stacked_area_monthly(
            m_cnt,
            title=f"",
            pdf_path=str(outdir / f"monthly_share_protocol_{scope_name}_count.pdf"),
            color_map_global=color_map_global
        )
        # Overall RU/UA alias files (Count)
        if scope_name in ("RU", "UA"):
            tag = "overall_russia" if scope_name == "RU" else "overall_ukraine"
            stacked_area_monthly(
                m_cnt,
                title=f"",
                pdf_path=str(outdir / f"{tag}_monthly_share_count.pdf"),
                color_map_global=color_map_global
            )

        monthly_totals = pd.DataFrame({"total_attacks": m_cnt_raw.sum(axis=1).astype(int)})
        weekly_totals  = pd.DataFrame({"total_attacks": df_week_cnt.sum(axis=1).astype(int)})
        monthly_totals.to_csv(outdir / f"monthly_totals_{scope_name}.csv")
        weekly_totals.to_csv(outdir / f"weekly_totals_{scope_name}.csv")

    if not m_pps.empty:
        stacked_area_monthly(
            m_pps,
            title=f"",
            pdf_path=str(outdir / f"monthly_share_protocol_{scope_name}_pps.pdf"),
            color_map_global=color_map_global
        )
        # Overall RU/UA alias files (PPS)
        if scope_name in ("RU", "UA"):
            tag = "overall_russia" if scope_name == "RU" else "overall_ukraine"
            stacked_area_monthly(
                m_pps,
                title=f"",
                pdf_path=str(outdir / f"{tag}_monthly_share_pps.pdf"),
                color_map_global=color_map_global
            )

    # Overall %
    ser_cnt = None
    ser_pps = None

    if not m_cnt.empty:
        totals_cnt = m_cnt.sum(axis=0)
        percent_overall_cnt = (totals_cnt / totals_cnt.sum()) * 100.0
        (outdir / f"protocol_overall_share_count_{scope_name}.csv").write_text(
            percent_overall_cnt.round(2).to_csv(header=["Percent"]), encoding="utf-8"
        )
        ser_cnt = percent_overall_cnt.reindex(DISPLAY_ORDER).fillna(0.0)

    if not m_pps.empty:
        totals_pps = m_pps.sum(axis=0)
        percent_overall_pps = (totals_pps / totals_pps.sum()) * 100.0
        (outdir / f"protocol_overall_share_pps_{scope_name}.csv").write_text(
            percent_overall_pps.round(2).to_csv(header=["Percent"]), encoding="utf-8"
        )
        ser_pps = percent_overall_pps.reindex(DISPLAY_ORDER).fillna(0.0)

    return ser_cnt, ser_pps

# 2×3 Panel (COUNT / PPS) 
def panel_top10_monthly_share_by_honeypot_2x3(c_scopes: dict, outdir: Path, color_map_global, mode: str):
    rows = ["agnostic", "proxied", "emulated"]
    cols = ["RU", "UA"]

    fig, axes = plt.subplots(nrows=3, ncols=2, figsize=(14, 10), sharex=True)
    any_data = False
    global_xmin, global_xmax = None, None

    for r, ct in enumerate(rows):
        for c, country in enumerate(cols):
            ax = axes[r, c]
            bkt = c_scopes.get(ct, {}).get(country, None)
            if not bkt:
                ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes); ax.set_yticks([]); continue

            if mode == "count":
                df_week = dict_to_week_df(bkt["counts"], dtype=float)
                if df_week.empty:
                    ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes); ax.set_yticks([]); continue
                df_month_raw = df_week.resample("MS").sum()
                df_month = collapse_to_important(df_month_raw)
            else:
                df_pkt = dict_to_week_df(bkt["packets"], dtype=float)
                df_dur = dict_to_week_df(bkt["dur"], dtype=float)
                if df_pkt.empty or df_dur.empty:
                    ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes); ax.set_yticks([]); continue
                df_month_pkt = df_pkt.resample("MS").sum()
                df_month_dur = df_dur.resample("MS").sum()
                df_month_pps_raw = df_month_pkt / df_month_dur.replace(0, np.nan)
                df_month = collapse_to_important(df_month_pps_raw.fillna(0.0))

            if df_month.empty or df_month.sum().sum() == 0:
                ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes); ax.set_yticks([]); continue

            any_data = True
            pct = df_month.div(df_month.sum(axis=1).replace(0, np.nan), axis=0) * 100.0
            pct = pct.fillna(0.0)

            cols_ordered = [col for col in DISPLAY_ORDER if col in pct.columns]
            x = pct.index
            y = [pct[col].values for col in cols_ordered]
            colors = [color_map_global[col] for col in cols_ordered]

            ax.stackplot(x, *y, labels=cols_ordered, colors=colors, linewidth=0.5, edgecolor="white")
            ax.set_ylim(0, 100)
            ax.set_title(f"")
            if c == 0:
                ax.set_ylabel("Percent (%)")

            local_min, local_max = x.min(), x.max()
            global_xmin = local_min if global_xmin is None else min(global_xmin, local_min)
            global_xmax = local_max if global_xmax is None else max(global_xmax, local_max)

            ax.xaxis.set_major_locator(MonthLocator(interval=4))
            ax.xaxis.set_major_formatter(DateFormatter("%Y-%m"))
            for lbl in ax.get_xticklabels():
                lbl.set_rotation(45); lbl.set_ha("right")

    if global_xmin is not None and global_xmax is not None:
        for ax in axes.ravel():
            ax.set_xlim(global_xmin, global_xmax)
            ax.margins(x=0)

    axes[-1, 0].set_xlabel("Date")
    axes[-1, 1].set_xlabel("Date")

    fig.tight_layout()
    out_png = outdir / f"panel_top10_monthly_share_by_honeypot_2x3_{mode}.png"
    out_pdf = outdir / f"panel_top10_monthly_share_by_honeypot_2x3_{mode}.pdf"
    fig.savefig(out_png, dpi=160, bbox_inches="tight")
    fig.savefig(out_pdf, dpi=160, bbox_inches="tight")
    plt.close(fig)
    if any_data:
        print(f"[PANEL-{mode.upper()}] Wrote {out_png}")
        print(f"[PANEL-{mode.upper()}] Wrote {out_pdf}")
    else:
        print(f"[PANEL-{mode.upper()}] No data.")

# Combined table writer: 6 scopes (cnt|pps)
def write_six_scopes_cnt_pps(cnt_map: dict, pps_map: dict, outdir: Path):
    scopes = ["RU-agnostic","RU-proxied","RU-emulated","UA-agnostic","UA-proxied","UA-emulated"]

    df_cnt = pd.DataFrame({k: cnt_map.get(k, pd.Series(0.0, index=DISPLAY_ORDER)).reindex(DISPLAY_ORDER).fillna(0.0)
                           for k in scopes})
    df_pps = pd.DataFrame({k: pps_map.get(k, pd.Series(0.0, index=DISPLAY_ORDER)).reindex(DISPLAY_ORDER).fillna(0.0)
                           for k in scopes})

    wide = pd.concat({"Cnt": df_cnt, "PPS": df_pps}, axis=1)
    wide.to_csv(outdir / "overall_percentages_six_scopes_cnt_pps.csv", float_format="%.1f")

    color_macro = {
        "DNS": "clrDNS", "NTP": "clrNTP", "WS-Discovery": "clrWSDiscovery", "SSDP": "clrSSDP",
        "CLDAP": "clrCLDAP", "SNMP": "clrSNMP", "Chargen": "clrChargen",
        "ARD": "clrARD", "CoAP": "clrCoAP", "Others": "clrOthers",
    }
    head_scopes = ["RU-agn.", "RU-prox.", "RU-emul.", "UA-agn.", "UA-prox.", "UA-emul."]
    header_line1 = " & " + " & ".join([f"\\multicolumn{{2}}{{c}}{{{h}}}" for h in head_scopes]) + r" \\"
    header_line2 = "Protocol & " + " & ".join(["Cnt & PPS"]*6) + r" \\"

    lines = []
    for proto in DISPLAY_ORDER:
        cm = color_macro.get(proto, "clrOthers")
        label = f"\\legbox{{{cm}}}{{{proto}}}"
        vals = []
        for k in scopes:
            vals.append(f"{df_cnt.at[proto,k]:.1f} & {df_pps.at[proto,k]:.1f}")
        lines.append(f"{label} & " + " & ".join(vals) + r" \\")
    tex = r"""\begin{table}[t]
\raggedright
\scriptsize
\caption{Overall percentages by protocol for six scopes (RU/UA $\times$ agnostic/proxied/emulated): \textbf{Count} vs. \textbf{PPS}.}
\label{tab:overall-percentages-six-scopes}
\setlength{\tabcolsep}{4pt}
\renewcommand{\arraystretch}{1.05}
\begin{tabular}{l*{6}{cc}}
\toprule
""" + header_line1 + r"""
\midrule
""" + header_line2 + r"""
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
\end{table}
"""
    (outdir / "table_overall_percentages_six_scopes_cnt_pps.tex").write_text(tex, encoding="utf-8")
    print("[COMBINED-6] Wrote overall_percentages_six_scopes_cnt_pps.csv and table_overall_percentages_six_scopes_cnt_pps.tex")

# Combined table writer 
def write_all_ru_ua_and_six_cnt_pps(cnt_map: dict, pps_map: dict, outdir: Path):
    """
    Build ONE big table with columns:
      ALL(C,P), RU-all(C,P), UA-all(C,P),
      RU-agn.(C,P), RU-prox.(C,P), RU-emul.(C,P),
      UA-agn.(C,P), UA-prox.(C,P), UA-emul.(C,P)
    """
    cols_all = [
        ("ALL", "ALL"),
        ("RU", "RU-all"),
        ("UA", "UA-all"),
        ("RU-agnostic", "RU-agn."),
        ("RU-proxied",  "RU-prox."),
        ("RU-emulated", "RU-emul."),
        ("UA-agnostic", "UA-agn."),
        ("UA-proxied",  "UA-prox."),
        ("UA-emulated", "UA-emul."),
    ]

    # Build DataFrames for Count/PPS
    def get_series(d, key):
        return d.get(key, pd.Series(0.0, index=DISPLAY_ORDER)).reindex(DISPLAY_ORDER).fillna(0.0)

    df_cnt = pd.concat({alias: get_series(cnt_map, key) for key, alias in cols_all}, axis=1)
    df_pps = pd.concat({alias: get_series(pps_map, key) for key, alias in cols_all}, axis=1)

    # Save CSV (multi-index columns: ('Cnt', alias) / ('PPS', alias))
    wide = pd.concat({"Cnt": df_cnt, "PPS": df_pps}, axis=1)
    wide.to_csv(outdir / "overall_percentages_all_ru_ua_and_six_cnt_pps.csv", float_format="%.1f")

    # LaTeX table
    color_macro = {
        "DNS": "clrDNS", "NTP": "clrNTP", "WS-Discovery": "clrWSDiscovery", "SSDP": "clrSSDP",
        "CLDAP": "clrCLDAP", "SNMP": "clrSNMP", "Chargen": "clrChargen",
        "ARD": "clrARD", "CoAP": "clrCoAP", "Others": "clrOthers",
    }

    human_headers = [alias for _, alias in cols_all] 
    header_line1 = " & " + " & ".join([f"\\multicolumn{{2}}{{c}}{{{h}}}" for h in human_headers]) + r" \\"
    header_line2 = "Protocol & " + " & ".join(["Count & pps"]*len(human_headers)) + r" \\"

    lines = []
    for proto in DISPLAY_ORDER:
        cm = color_macro.get(proto, "clrOthers")
        label = f"\\legbox{{{cm}}}{{{proto}}}"
        vals = []
        for alias in human_headers:
            vals.append(f"{df_cnt.at[proto,alias]:.1f} & {df_pps.at[proto,alias]:.1f}")
        lines.append(f"{label} & " + " & ".join(vals) + r" \\")
    tex = r"""\begin{table}[t]
\raggedright
\scriptsize
\caption{Overall percentages by protocol across ALL, RU-all, UA-all, and six honeypot scopes: \textbf{Count} vs. \textbf{PPS}.}
\label{tab:overall-percentages-all-ru-ua-six}
\setlength{\tabcolsep}{4pt}
\renewcommand{\arraystretch}{1.05}
\begin{tabular}{l*{9}{cc}}
\toprule
""" + header_line1 + r"""
\midrule
""" + header_line2 + r"""
\midrule
""" + "\n".join(lines) + r"""
\bottomrule
\end{tabular}
\end{table}
"""
    (outdir / "table_overall_percentages_all_ru_ua_and_six_cnt_pps.tex").write_text(tex, encoding="utf-8")
    print("[COMBINED-ALL+6] Wrote overall_percentages_all_ru_ua_and_six_cnt_pps.csv and table_overall_percentages_all_ru_ua_and_six_cnt_pps.tex")

# Main flow 
def process_all():
    files = enumerate_all_files()
    if not files:
        raise FileNotFoundError(f"No input CSVs in {BASE_DIR.resolve()}")
    ensure_columns(files[0])

    # Base scopes
    base_scopes = { "ALL": mk_scope_bucket(), "RU": mk_scope_bucket(), "UA": mk_scope_bucket() }

    # Honeypot-type scopes for ALL/RU/UA
    contype_values = ["agnostic", "proxied", "emulated"]
    c_scopes = { ct: { "ALL": mk_scope_bucket(), "RU": mk_scope_bucket(), "UA": mk_scope_bucket() }
                 for ct in contype_values }

    for fpath in tqdm(files, desc="Files", unit="file"):
        for chunk in pd.read_csv(
            fpath, usecols=USECOLS_BASE, dtype=DTYPE_MAP,
            chunksize=CHUNKSIZE, low_memory=False, on_bad_lines="skip", engine="c"
        ):
            s   = pd.to_datetime(chunk[START_COL], errors="coerce", utc=True)
            e   = pd.to_datetime(chunk[END_COL],   errors="coerce", utc=True)
            cc  = chunk[COUNTRY_COL].astype(str).str.upper()
            con = chunk[CONS_COL].astype(str).str.lower()
            dp  = chunk[DPORT_COL].astype(str)
            pkt = pd.to_numeric(chunk[PKT_COL], errors="coerce")
            ht  = (chunk[HONTYPE_COL].astype(str).str.lower().str.strip()
                   if HONTYPE_COL in chunk.columns else pd.Series(["unknown"]*len(chunk)))

            # RU/UA + strict only
            mask = (s.notna() & e.notna() & (e > s) & (con == "strict") & (cc.isin(TARGET_COUNTRIES)))
            if not mask.any():
                continue

            s = s[mask]; e = e[mask]; cc = cc[mask]; dp = dp[mask]; ht = ht[mask]; pkt = pkt[mask].fillna(0)
            proto = dp.map(map_port_to_proto).map(canonical_protocol)

            for s_i, e_i, ccode, proto_lbl, honeypot_type, K_i in zip(s.values, e.values, cc.values, proto.values, ht.values, pkt.values):
                s_i = to_utc(s_i); e_i = to_utc(e_i)
                D_i = max((e_i - s_i).total_seconds(), 1.0)
                for ws in iter_week_starts(s_i, e_i):
                    w_start = ws; w_end = ws + pd.Timedelta(days=7)
                    overlap = (min(e_i, w_end) - max(s_i, w_start)).total_seconds()
                    if overlap <= 0:
                        continue
                    frac = overlap / D_i

                    for key in ["ALL", ccode]:
                        base_scopes[key]["counts"][proto_lbl][ws]  += 1
                        base_scopes[key]["packets"][proto_lbl][ws] += float(K_i) * frac
                        base_scopes[key]["dur"][proto_lbl][ws]     += overlap

                    if honeypot_type in c_scopes:
                        for key in ["ALL", ccode]:
                            c_scopes[honeypot_type][key]["counts"][proto_lbl][ws]  += 1
                            c_scopes[honeypot_type][key]["packets"][proto_lbl][ws] += float(K_i) * frac
                            c_scopes[honeypot_type][key]["dur"][proto_lbl][ws]     += overlap

    # Colors
    color_map_global = build_global_color_map(set(IMPORTANT_PROTOCOLS + ["Others"]))

    # Process scopes -> overall series maps
    percent_cnt_map, percent_pps_map = {}, {}

    for scope_name, bucket in base_scopes.items():
        df_week_cnt = dict_to_week_df(bucket["counts"], dtype=float)
        df_week_pkt = dict_to_week_df(bucket["packets"], dtype=float)
        df_week_dur = dict_to_week_df(bucket["dur"], dtype=float)
        ser_cnt, ser_pps = process_scope_dual(df_week_cnt, df_week_pkt, df_week_dur,
                                              scope_name, OUTDIR, color_map_global)
        if ser_cnt is not None: percent_cnt_map[scope_name] = ser_cnt
        if ser_pps is not None: percent_pps_map[scope_name] = ser_pps

    for ct, scope_dict in c_scopes.items():
        ct_dir = OUTDIR / f"by_honeypot_{ct}"
        ct_dir.mkdir(parents=True, exist_ok=True)
        for scope_name, bucket in scope_dict.items():
            df_week_cnt = dict_to_week_df(bucket["counts"], dtype=float)
            df_week_pkt = dict_to_week_df(bucket["packets"], dtype=float)
            df_week_dur = dict_to_week_df(bucket["dur"], dtype=float)
            ser_cnt, ser_pps = process_scope_dual(df_week_cnt, df_week_pkt, df_week_dur,
                                                  f"{ct.upper()}_{scope_name}", ct_dir, color_map_global)
            if scope_name in ("RU","UA"):
                key = f"{scope_name}-{ct}"
                if ser_cnt is not None: percent_cnt_map[key] = ser_cnt
                if ser_pps is not None: percent_pps_map[key] = ser_pps

    # Panels
    panel_top10_monthly_share_by_honeypot_2x3(c_scopes, OUTDIR, color_map_global, mode="count")
    panel_top10_monthly_share_by_honeypot_2x3(c_scopes, OUTDIR, color_map_global, mode="pps")

    # six-scope table
    write_six_scopes_cnt_pps(percent_cnt_map, percent_pps_map, OUTDIR)

    write_all_ru_ua_and_six_cnt_pps(percent_cnt_map, percent_pps_map, OUTDIR)

# Entrypoint
def main():
    process_all()

if __name__ == "__main__":
    main()
