"""
===============================================================================
DDoS Daily Metrics Analyzer
-------------------------------------------------------------------------------
Purpose:
    This script processes DDoS attack logs that include start and end timestamps
    (t_start, t_end) and total packet counts. It distributes packets across all
    calendar days spanned by each attack, proportionally to the time overlap
    (duration-weighted), and computes daily metrics for visualization.

Methodology:
    1. Load and clean data:
        - Read CSV file containing columns: t_start, t_end, packets.
        - Convert timestamps to datetime, packets to numeric.
        - Drop invalid or missing rows; keep only rows with t_end >= t_start.
    2. Duration-weighted expansion:
        - For each attack event:
            • Calculate total duration in seconds.
            • For each calendar day overlapping with [t_start, t_end]:
                - Compute the number of seconds the attack overlapped that day.
                - Allocate packets proportionally to that overlap fraction:
                      packets_day = total_packets × (overlap_seconds / total_duration)
        - Result: each attack contributes multiple (date, event, packets) records.
    3. Daily aggregation:
        - Group by date and compute:
              count: total number of active attacks on that date
              sum: total (duration-weighted) packets on that date
              mean: average packets per attack on that date
              max: maximum packets for any attack that day
              pps_avg: average packets per second = sum / 86,400
    4. Visualization:
        - Plot four subplots (Count / Sum / Mean / Max) over daily x-axis.
        - Format x-axis in YYYY-MM-DD; fix range to Jan 1–31 for clarity.
    5. Output:
        - Save results to:
              • ddos_daily_metrics.csv  (numerical table)
              • ddos_daily_metrics.pdf  (graphical figure)
    6. Interpretation:
        - count: number of attack events (active that day)
        - sum: total packets apportioned to that day
        - mean: average packets per attack
        - max: peak packets from the largest attack that day
        - pps_avg: day-level average packets/second (traffic intensity)

Notes:
    - 
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.dates import DayLocator, DateFormatter
from datetime import timedelta

# config
FILE_PATH = "enriched_monthly_rdap/all_v2/2022/2022-01.csv"
START_COL = "t_start"   # attack start timestamp
END_COL   = "t_end"     # attack end timestamp
PKT_COL   = "packets"   # total packets for the attack/event

# load & clean
df = pd.read_csv(FILE_PATH)
df[START_COL] = pd.to_datetime(df[START_COL], errors="coerce")
df[END_COL]   = pd.to_datetime(df[END_COL],   errors="coerce")
df[PKT_COL]   = pd.to_numeric(df[PKT_COL], errors="coerce")

df = df.dropna(subset=[START_COL, END_COL, PKT_COL]).copy()
df = df[df[END_COL] >= df[START_COL]].copy()

# helpers
def day_bounds(d):
    """Return (start, end) timestamps for a given date (one full day)."""
    start = pd.Timestamp(d).floor("D")
    end   = start + pd.Timedelta(days=1)
    return start, end

def overlap_seconds(a_start, a_end, b_start, b_end):
    """Calculate number of overlapping seconds between two intervals."""
    start = max(a_start, b_start)
    end   = min(a_end, b_end)
    sec = (end - start).total_seconds()
    return max(0.0, sec)

# expand each attack across days it spans
records = []
for _, r in df.iterrows():
    s, e, p = r[START_COL], r[END_COL], float(r[PKT_COL])

    total_secs = max((e - s).total_seconds(), 0.0)
    if total_secs == 0:  # instant event
        d0 = s.floor("D")
        records.append((d0, 1, p))
        continue

    d = s.floor("D")
    last_day = e.floor("D")
    while d <= last_day:
        ds, de = day_bounds(d)
        secs = overlap_seconds(s, e, ds, de)
        if secs > 0:
            apportioned = p * (secs / total_secs)
            records.append((d, 1, apportioned))
        d += timedelta(days=1)

# build daily statistics
expanded = pd.DataFrame(records, columns=["date", "event_count", "packets"])
if expanded.empty:
    raise ValueError("No valid events found in dataset.")

daily_stats = (
    expanded.groupby("date")
            .agg(count=("event_count", "sum"),
                 sum=("packets", "sum"),
                 mean=("packets", "mean"),
                 max=("packets", "max"))
            .sort_index()
)

# compute average packets per second
daily_stats["pps_avg"] = daily_stats["sum"] / 86400.0

# visualization 
plt.figure(figsize=(24, 18))

# 1) daily event count
plt.subplot(4, 1, 1)
plt.plot(daily_stats.index, daily_stats["count"], marker='o', linewidth=1, color="steelblue")
plt.title("Daily DDoS Metrics (duration-weighted packets per day)")
plt.ylabel("Count (# of Events)")

# 2) total packets
plt.subplot(4, 1, 2)
plt.plot(daily_stats.index, daily_stats["sum"], marker='o', linewidth=1, color="darkorange")
plt.ylabel("Total Packets per Day")

# 3) average packets per event
plt.subplot(4, 1, 3)
plt.plot(daily_stats.index, daily_stats["mean"], marker='o', linewidth=1, color="forestgreen")
plt.ylabel("Average Packets per Event")

# 4) maximum packets (peak)
plt.subplot(4, 1, 4)
plt.plot(daily_stats.index, daily_stats["max"], marker='o', linewidth=1, color="firebrick")
plt.ylabel("Max Packets (Peak)")
plt.xlabel("Date (Daily)")

# format x-axis (daily ticks, fixed month)
for ax in plt.gcf().axes:
    ax.xaxis.set_major_locator(DayLocator(interval=1))
    ax.xaxis.set_major_formatter(DateFormatter("%Y-%m-%d"))
    ax.set_xlim(pd.Timestamp("2022-01-01"), pd.Timestamp("2022-01-31"))
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

plt.tight_layout()
plt.savefig("ddos_daily_metrics.pdf", dpi=150)
plt.show()

# save results
daily_stats.to_csv("ddos_daily_metrics.csv")
print("[Saved] ddos_daily_metrics.csv, ddos_daily_metrics.pdf")

