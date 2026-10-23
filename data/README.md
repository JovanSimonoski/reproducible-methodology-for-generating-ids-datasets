# data/

Local data root of the pipeline. Only this README is versioned; everything
else here is ignored by git (raw captures and datasets are large and are
distributed separately). The layout follows the common
`raw → interim → processed` convention, plus `release/` for the finished,
distributable datasets, and uses one sub-folder per **capture** (one recording
campaign, e.g. `07`, `10`).

```
data/
├── raw/                        INPUT: as delivered, never modified by the pipeline
│   └── <capture>/
│       ├── pcap/               capture appliance output: MM/DD/HH/mm/<epoch>.pcap (+ .pcap.idx)
│       └── attacklog/          attacklog JSON exports of the attackers in this capture
│
├── interim/                    WORKING FILES: regenerable, safe to delete
│   └── <capture>/
│       ├── fragments/          per-pcap NFStream flow fragments (.parquet + .meta.json)
│       ├── manifest.csv        one row per pcap: size, packets, time range, flows, status
│       ├── errors.log          tracebacks of failed pcaps
│       └── extract_config.json NFStream configuration used
│
├── processed/                  RESULTS PER CAPTURE
│   └── <capture>/
│       ├── parquet/            flow dataset, partitioned date=YYYY-MM-DD/hour=HH
│       ├── flows.csv           flows (186 columns)
│       ├── flows_labeled.csv   flows + label
│       ├── run_metadata.json   extraction versions, configuration, stitching counts
│       ├── validation_report.json
│       └── labeling_summary.json
│
├── anonymization/              PRIVATE: never publish, never put in a release
│   └── public_ip_map.csv       real public IP -> pseudonym; the key that undoes the anonymization
│
└── release/                    FINISHED DATASETS (what you hand to others; public IPs pseudonymized)
    └── <name>/
        ├── <flows>.csv         all captures + capture_id      (CSV names set in the build config)
        ├── <labeled>.csv       same rows + capture_id + label
        ├── README.md           dataset card
        ├── DATASET_STATISTICS.md
        ├── build_summary.json
        └── provenance/         per-capture reports, pcap manifests, attacklog exports,
                                relabel overrides
```

| Stage | Written by | Can be regenerated from |
|---|---|---|
| `raw/` | you (copy the capture and the attackers' exports here) | – |
| `interim/` | `flow-extraction/extract.py` | `raw/` |
| `processed/` | `flow-extraction/consolidate.py`, `validate.py`, `export_csv.py`, `flow-labeling/label_flows.py` | `interim/` + `raw/` |
| `anonymization/` | `dataset-unification/build_dataset.py` (created on the first anonymized build, extended later) | – (back it up: without it, rebuilds get new pseudonyms) |
| `release/` | `dataset-unification/build_dataset.py`, `dataset-analysis/analyze_dataset.py` | `processed/` + `interim/` + `raw/` + `dataset-info/` + `anonymization/` |

`raw/`, `interim/` and `processed/` hold the real addresses; only `release/`
is anonymized.

`scripts/process_capture.sh <capture>` fills `interim/<capture>/` and
`processed/<capture>/`; `scripts/build_release.sh` fills `release/`.

To keep the data somewhere else (another disk, a shared drive), point
`DATA_ROOT` at it for `process_capture.sh` and `data_root` in the build
config, or replace this folder with a symlink.

## Captures of the thesis dataset

| Capture | Traffic window (UTC) | pcaps | Attackers |
|---|---|---|---|
| `07` | 2026-07-14 07:45 → 2026-07-17 08:43 | 439 | attacker_1, attacker_2, attacker_3, attacker_5 |
| `10` | 2026-10-01 00:00 → 2026-10-13 08:41 | 1,781 | attacker_4, attacker_7 |
