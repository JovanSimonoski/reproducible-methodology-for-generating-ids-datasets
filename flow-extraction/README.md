# Flow-Extraction Pipeline

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Turns the read-only pcap corpus in `sec-dataset/` (439 ten-minute pcaps,
2026-07-14 07:45 → 2026-07-17 08:50 UTC, 8,534,197 packets, single 802.1Q
VLAN 1017) into a flow-level Parquet dataset: **one row = one bidirectional
flow**, 188 columns. Labels are joined later from separate JSON files; this
pipeline deliberately keeps `src_ip`/`dst_ip`/ports un-anonymized and adds a
direction-independent `canonical_key` so those joins are exact.

## Requirements

Runs under **WSL2 Ubuntu 24.04** (NFStream has no native Windows support),
Python 3.12, with a venv at `~/ids-venv`:

```bash
# From the unified repository root:
cd flow-extraction
python3 -m venv ~/ids-venv
~/ids-venv/bin/pip install -r requirements.txt   # nfstream 6.6.0, pandas, pyarrow
```

## Running

```bash
PY=~/ids-venv/bin/python
IN=/path/to/dataset/sec-dataset      # read-only
WORK=/path/to/dataset/output/full-work
OUT=/path/to/dataset/output/full

# 1. per-pcap extraction (resumable: rerun after interrupt, done files are skipped)
$PY extract.py --input-dir "$IN" --work-dir "$WORK" --workers 4 --stage-dir ~/ids-staged
# pilot variants: --limit 5, or --files-list list.txt (relative paths)

# 2. stitch fragments, add derived columns, write partitioned dataset
$PY consolidate.py --work-dir "$WORK" --output-dir "$OUT"

# 3. validation report (exits nonzero if any check fails)
$PY validate.py --work-dir "$WORK" --output-dir "$OUT"
```

Timeouts (`--idle-timeout 120 --active-timeout 1800`), `--accounting-mode 0`,
`--splt 20`, `--n-dissections 20` are the defaults and are recorded in
`extract_config.json` / `run_metadata.json`. The full corpus runs in ~10
minutes on a 4-worker laptop (extraction 333 s, consolidation 270 s).

## Outputs

```
output/full-work/
  intermediate/<mirrored tree>/<epoch>.parquet    one file per input pcap (fragments)
  intermediate/<...>/<epoch>.meta.json            per-file scan + timing ground truth
  manifest.csv          one row per input pcap: size, packets, first/last ts,
                        flows, status, error
  errors.log            full tracebacks of any failed file (empty this run)
  extract_config.json   exact NFStream configuration used
output/full/
  dataset/date=YYYY-MM-DD/hour=HH/part-*.parquet  the dataset (hive-partitioned, zstd)
  run_metadata.json     versions, config, strategy, counts
  validation_report.json
output/data_dictionary.md                         every column: name, type, units, meaning
```

## Design decisions (and why)

- **NFStream 6.6.0**, API introspected rather than assumed. Everything that
  adds columns is on: `statistical_analysis=True`, `splt_analysis=20`,
  `n_dissections=20`. Not enabled (add no traffic columns / harmful offline):
  `system_visibility_mode` (host-OS process introspection), `n_meters` /
  `performance_report` (live-capture tuning), `bpf_filter` (drops traffic),
  `max_nflows` (truncation cap).
- **`accounting_mode=0` = full L2 frame bytes** — verified empirically (mode
  totals vs capinfos). Byte columns are comparable only within this mode.
- **Timezone: UTC.** Filenames equal the first packet timestamp to the
  microsecond (all 439 verified); directory buckets match UTC, not local time.
- **File-boundary handling: per-file extraction + post-hoc stitching.**
  Fragments sharing a canonical key with a gap ≤ idle_timeout across a file
  boundary are merged (exact sums; exact pooled mean/stddev including the seam
  gap; SPLT continued across the seam; reversed-orientation continuations
  swapped before merging). Chains are re-cut at active_timeout to mimic
  NFStream on an unsplit capture. Residual edge flows carry
  `truncated_start`/`truncated_end`. This preserved resumability/parallelism
  and repaired 1,589 split flows (~0.09% of rows; up to 3 fragments).
- **Isolation:** each pcap is processed in its own subprocess — a segfault or
  corrupt file is logged to `errors.log` and the run continues.
- **Staging:** pcaps are copied to the WSL filesystem before reading (the
  /mnt/c bridge caps NFStream at ~23 MB/s vs ~127 MB/s local). Cache lives in
  `~/ids-staged (as configured above)` (~2 GB; safe to delete after a run).
- The source directory is never written to.

## Validation results (this run)

- 439/439 files ok, 0 failed. No missing 10-minute windows, no gaps > 30 s.
- **Packet reconciliation exact:** 8,534,197 frames = 8,298,630 IP packets
  (100% of them in flows) + 130,146 STP + 105,394 ARP + 27 RARP. NFStream
  dropped nothing; non-IP L2 frames are outside flow scope by definition.
- 1,796,455 flows; 0 duplicate `flow_id`s, 0 negative durations, 0 zero-packet
  flows, all timestamps inside the capture window.
- Flow mix: 84% TCP, 15% UDP, plus IGMP/ICMP. Median flow is 2 packets /
  128 bytes — the corpus is dominated by scan-like traffic (75% of flows are
  nDPI `Unknown`), consistent with a security dataset; top talkers are RFC1918
  hosts 192.168.71.x / 192.168.77.x.

## Known limitations

- `expiration_id` is a per-file artifact (see data dictionary); use the
  truncation flags instead.
- Stitched flows (`n_fragments > 1`): statistics are exact pooled values, but
  nDPI fields come from the head fragment (a mid-stream continuation alone
  would have been classified worse, so this is the better value).
- Active-timeout re-cutting during stitching operates at fragment granularity
  (never triggered in this corpus: `recut_active_timeout` = 0 everywhere).
- TLS fingerprints (`client_fingerprint` JA4 / `server_fingerprint`) are
  present on only 152 / 83 flows — the corpus's TLS is mostly handshake-less
  scan traffic.
- The `.idx` siblings of each pcap are a capture-appliance time-seek index
  (first/last epoch + interval offsets); they are redundant for full-file
  extraction and are ignored.

## CSV export for labelling

After validation, export the consolidated dataset for use with the [flow-labelling component](../flow-labeling/README.md):

```bash
$PY export_csv.py --dataset-dir "$OUT/dataset" --out "$OUT/flows.csv"
```