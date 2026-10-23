# Flow Extraction

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Turns the packet captures of one capture campaign into a flow-level dataset
with [NFStream](https://www.nfstream.org/): **one row = one bidirectional
flow**, 186 columns (see [DATA_DICTIONARY.md](DATA_DICTIONARY.md)). Flows that
the capture appliance's file rotation split across pcap files are stitched back
together, the result is validated against the raw packet counts, and it is
exported to CSV for [flow-labeling](../flow-labeling/README.md). IPs and ports
are kept un-anonymized because labeling joins on them.

## Requirements

Linux or **WSL2 Ubuntu 24.04** (NFStream has no native Windows support),
Python 3.12, and a virtual environment:

```bash
python3 -m venv ~/ids-venv
~/ids-venv/bin/pip install -r flow-extraction/requirements.txt   # nfstream 6.6.0, pandas, pyarrow
```

## Running

Commands run from the repository root. The easiest way is the pipeline script,
which runs all steps below plus labeling for one capture in the
[standard data layout](../data/README.md):

```bash
PYTHON=~/ids-venv/bin/python bash scripts/process_capture.sh 10
```

The individual steps, for capture `10`:

```bash
PY=~/ids-venv/bin/python
C=10

# 1. per-pcap extraction (resumable: rerun after an interrupt, finished files are skipped)
$PY flow-extraction/extract.py --input-dir data/raw/$C/pcap --capture-id $C \
    --work-dir data/interim/$C --workers 4

# 2. stitch fragments, add derived columns, write the partitioned Parquet dataset
$PY flow-extraction/consolidate.py --work-dir data/interim/$C --output-dir data/processed/$C

# 3. validation report (exits nonzero if any check fails)
$PY flow-extraction/validate.py --work-dir data/interim/$C --output-dir data/processed/$C

# 4. CSV export for labeling
$PY flow-extraction/export_csv.py --dataset-dir data/processed/$C/parquet \
    --out data/processed/$C/flows.csv
```

### `extract.py` options

| Option | Default | Meaning |
|---|---|---|
| `--input-dir` | required | Directory searched recursively for `*.pcap` (never written to). |
| `--work-dir` | required | Where fragments, manifest and logs go. |
| `--capture-id` | empty | Prefixed to every recorded pcap path (`source_pcap`), e.g. `10/10/01/00/00/<epoch>.pcap`, so flows of different captures stay distinguishable after unification. |
| `--workers` | 4 | Pcaps processed in parallel, each in its own subprocess. |
| `--n-meters` | 1 | NFStream meter processes per pcap. With more than one, NFStream numbers flows in arrival order across processes, so `flow_id` and row order change from run to run. Keep 1 for reproducible ids; parallelism comes from `--workers`. |
| `--idle-timeout` / `--active-timeout` | 120 / 1800 s | NFStream flow expiry. |
| `--accounting-mode` | 0 | Byte accounting (0 = full L2 frame bytes). |
| `--splt` / `--n-dissections` | 20 / 20 | Early-packet sequence length, nDPI dissection depth. |
| `--stage-dir` | `~/ids-staged` | Linux-side copy of each pcap (see *Staging* below); `--no-stage` reads in place. |
| `--limit`, `--files-list` | – | Pilot runs: first N files, or an explicit list of paths relative to `--input-dir`. |

All settings are recorded in `extract_config.json` and `run_metadata.json`.

## Outputs

```
data/interim/<capture>/
  fragments/<capture>/<mirrored tree>/<epoch>.parquet   flow fragments of one pcap
  fragments/<capture>/<mirrored tree>/<epoch>.meta.json per-file packet scan + timing
  manifest.csv          one row per pcap: size, packets, first/last ts, flows, status, error
  errors.log            full tracebacks of failed files (empty when all succeed)
  extract_config.json   exact NFStream configuration used
data/processed/<capture>/
  parquet/date=YYYY-MM-DD/hour=HH/part-*.parquet  the flow dataset (hive-partitioned, zstd)
  run_metadata.json     tool versions, configuration, stitching counts
  validation_report.json
  flows.csv             CSV export (list columns serialized as JSON arrays)
```

## Design decisions (and why)

- **NFStream 6.6.0**, API introspected rather than assumed. Everything that
  adds columns is on: `statistical_analysis=True`, `splt_analysis=20`,
  `n_dissections=20`. Not enabled (add no traffic columns / harmful offline):
  `system_visibility_mode` (host-OS process introspection),
  `performance_report` (live-capture tuning), `bpf_filter` (drops traffic),
  `max_nflows` (truncation cap).
- **One meter per pcap** (`n_meters=1`): flow ids are assigned in the order
  flows are emitted, which is deterministic with a single meter. Flow content
  does not depend on the meter count.
- **`accounting_mode=0` = full L2 frame bytes**, verified empirically (mode
  totals vs capinfos). Byte columns are comparable only within this mode.
- **Timezone: UTC.** The capture appliance names each file after its first
  packet's timestamp and buckets directories in UTC.
- **File-boundary handling: per-file extraction + post-hoc stitching.**
  Fragments sharing a canonical key with a gap ≤ idle_timeout across a file
  boundary are merged (exact sums; exact pooled mean/stddev including the seam
  gap; SPLT continued across the seam; reversed-orientation continuations
  swapped before merging). Chains are re-cut at active_timeout to mimic
  NFStream on an unsplit capture. Residual edge flows carry
  `truncated_start`/`truncated_end`. This keeps extraction resumable and
  parallel.
- **Isolation:** each pcap is processed in its own subprocess, so a segfault or
  corrupt file is logged to `errors.log` and the run continues.
- **Staging:** under WSL, pcaps are copied to the Linux filesystem before
  reading (the /mnt/c bridge caps NFStream at ~23 MB/s vs ~127 MB/s local).
  The cache is safe to delete after a run.
- The input directory is never written to.

## Validation

`validate.py` writes `validation_report.json` and fails when any of these is
violated:

- every pcap extracted (failed files are listed);
- packet reconciliation: packets in flows vs. the independent pcap scan. The
  difference must consist of non-IP layer-2 frames (spanning tree, ARP, …),
  which are outside flow scope by definition;
- fragment packets = final dataset packets (nothing lost while stitching);
- no duplicate `flow_id`, no negative durations, no zero-packet flows, no
  timestamps outside the capture window.

It also reports capture gaps over 30 s, distributions, protocol mix and top
talkers. Results for the thesis captures are in
[dataset-info/DATASET_STATISTICS.md](../dataset-info/DATASET_STATISTICS.md).

## Known limitations

- `expiration_id` is constant 0 when every pcap is shorter than the active
  timeout (see the data dictionary); use the truncation flags instead.
- Stitched flows (`n_fragments > 1`): statistics are exact pooled values, but
  nDPI fields come from the head fragment (a mid-stream continuation alone
  would have been classified worse, so this is the better value).
- Active-timeout re-cutting during stitching operates at fragment granularity.
- TLS fingerprints (`client_fingerprint` JA4 / `server_fingerprint`) exist only
  for completed handshakes, so they are sparse in scan-heavy traffic.
- The `.idx` siblings of each pcap are a capture-appliance time-seek index
  (first/last epoch + interval offsets); they are redundant for full-file
  extraction and are ignored.
