# Characterizing Wartime DDoS Attacks - tentative

## Overview

This project provides the complete analytical pipeline used for our 3.5-year longitudinal honeypot study. 
It includes preprocessing, enrichment, temporal alignment, protocol composition, AS-type analysis, connection-type distribution, and figure/table generation for the paper. 
Due to data-sensitivity and volume, only anonymized sample CSVs are included. Full data access requires approval from the originating dataset provider.

## Repository Structure
```
wartime-ddos-analysis/
│
├── code/
│   ├── enrichment/                  
│   │   ├── README-data.md
│   │   └── maxmind_enrichment.py
│   │   └── rdap_enrichment.py
│   └── evaluation/
│   │   ├── README-eval.md
│   │   └── country-analyzer.py
│   │   ├── domain-analyzer.py
│   │   └── protocol-analyzer.py
│   └── README.md           
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
├── requirements.txt
├── LICENSE
└── CITATION.cff
```
