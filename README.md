# Characterizing Wartime DDoS Attacks (CyCon 2026) - tentative

This repository provides the analysis scripts and reproducible figure-generation code for the paper:

> J. Kim et al. (2026), *Characterizing Wartime DDoS Attacks: Insights from a 3.5-Year Honeypot Analysis*, NATO CCDCOE CyCon 2026.

## Overview

This project provides the complete analytical pipeline used for our 3.5-year longitudinal honeypot study. 
It includes preprocessing, enrichment, temporal alignment, protocol composition, AS-type analysis, connection-type distribution, and figure/table generation for the paper. 
Due to data-sensitivity and volume, only anonymized sample CSVs are included. Full data access requires approval from the originating dataset provider.

## Repository Structure
```
wartime-ddos-analysis/
│
├── code/
│   ├── 00_/            # shared helpers (time handling, map_port_to_proto, etc.)
│   ├── 01_/        # raw → enriched CSV transformation (GeoIP, ASN, RDAP)
│   ├── 02_/   # weekly aggregation + event correlation
│   ├── 03_/    # protocol share (Count, PPS)
│   ├── 04_/   # AS-type, sectoral and connection-type trends
│   ├── 05_/        # stacked plots, heatmaps, ECDFs, violin plots
│   ├── .py  # unified entry for protocol-related figures
│   ├── .sh               # reproduce all figures/tables
│   └── README_CODE.md           # per-module usage
│
├── data/
│   ├── sample/                  # small anonymized demo subset
│   │   ├── 2024-01_sample.csv
│   │   └── 2024-02_sample.csv
│   └── README_DATA.md
│
├── paper/
│   ├── cycon2026_draft.pdf
│   └── figures/                 # generated figures for submission
│
├── environment.yml              # conda environment (recommended)
├── requirements.txt
├── LICENSE
└── CITATION.cff
```
