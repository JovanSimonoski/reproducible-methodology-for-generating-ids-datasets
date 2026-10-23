# Pipeline Scripts

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Two Bash scripts chain the components into the full pipeline over the
[standard data layout](../data/README.md). Run them from anywhere, under Linux
or WSL; they locate the repository themselves.

| Script | What it does |
|---|---|
| `process_capture.sh <capture>` | `data/raw/<capture>/` → `data/processed/<capture>/`: extract flows per pcap, stitch, validate, export CSV, label. |
| `build_release.sh [config]` | `data/processed/*` → `data/release/<name>/`: unify the captures named in the config (default `dataset-info/build-config.json`), apply relabel overrides, pseudonymize public IPs, write the statistics report. |

```bash
export PYTHON=~/ids-venv/bin/python     # venv from flow-extraction/requirements.txt
bash scripts/process_capture.sh 07
bash scripts/process_capture.sh 10
bash scripts/build_release.sh
```

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `PYTHON` | both | `python3` | Interpreter with NFStream (processing) and pandas + pyarrow (analysis). |
| `DATA_ROOT` | `process_capture.sh` | `<repo>/data` | Data root. `build_release.sh` takes it from the build config. |
| `WORKERS` | `process_capture.sh` | 4 | Parallel extraction workers. |
| `STAGE_DIR` | `process_capture.sh` | `~/ids-staged` | Linux-side pcap staging cache (see flow-extraction). |

Both scripts stop at the first failing step: a failed pcap extraction, a
failed validation check, or a broken build integrity check.

Processing is resumable: re-running `process_capture.sh` after an interrupt
skips pcaps whose fragments already exist. Delete `data/interim/<capture>/`
to force a full re-extraction.
