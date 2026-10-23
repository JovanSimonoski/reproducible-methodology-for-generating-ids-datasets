# Flow Labelling

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Assigns labels to the CSV produced by [flow-extraction](../flow-extraction/README.md), using JSON execution records exported by [attacklog](../attacklog/README.md).

## Requirements and inputs

Python 3.10 or later; only standard-library modules are used. Supply a flow CSV containing `src_ip`, `dst_ip`, `dst_port`, `protocol`, `bidirectional_first_seen_ms`, and `bidirectional_last_seen_ms`, together with the attacklog JSON exports of the attackers who took part in that capture. Flow timestamps are UTC epoch milliseconds and protocol values are numeric.

## Running

From the repository root, for capture `10` in the [standard data layout](../data/README.md) (this is step 5 of `scripts/process_capture.sh`):

```bash
python3 flow-labeling/label_flows.py \
    --flows     data/processed/10/flows.csv \
    --attacklog data/raw/10/attacklog \
    --out       data/processed/10/flows_labeled.csv \
    --summary   data/processed/10/labeling_summary.json
```

| Option | Default | Meaning |
|---|---|---|
| `--flows` | required | Input flow CSV. |
| `--attacklog` | required | One or more attacklog JSON files and/or directories (every `*.json` inside, sorted by name). Pass only the exports of attackers active in this capture, e.g. one directory per capture. |
| `--out` | required | Output CSV: the input columns plus `label`. Must differ from `--flows`; written atomically. |
| `--summary` | required | Output JSON summary. |
| `--tolerance-ms` | 1000 | Widening of each record's time window on both sides. |
| `--no-fallback` | off | Disable the tuple fallback (see below). |

## Attribution procedure

The script matches the attacker source address, exact destination address, protocol, and destination port (including port ranges and lists). It first looks for overlap between the flow interval and a recorded execution interval, expanded by the tolerance at each end. When multiple records qualify, the nearest interval centre wins.

With tuple fallback enabled, a flow with no overlapping interval is assigned to the nearest execution matching the same addresses, protocol, and destination port, without a maximum time-distance limit. This recovers scans whose attacklog timestamps drifted, whose end was logged too early, or that were repeated without being logged.

Unmatched flows receive `BENIGN`. This is the unmatched category, not independent confirmation that the traffic is harmless: target → attacker traffic (reverse-shell callbacks, payload downloads) and attacker traffic to unlogged services are also `BENIGN`. Matching uses the recorded forward direction; destination CIDR blocks and IP ranges are not expanded by this implementation. Records without an end time or with unsupported protocols are skipped. Equal-distance ties retain the first candidate, so keep the order of `--attacklog` arguments (and file names inside directories) when reproducing a run.

Flows that the rules attribute wrongly can be corrected later, reviewed flow by flow, with the relabel overrides of [dataset-unification](../dataset-unification/README.md).

## Outputs

- A CSV retaining the input columns and appending `label`, containing the matched `attack_name` or `BENIGN`.
- A JSON summary with the attacklog files used, label counts, time-window and fallback counts, per-record matches (records that matched no flow have both counts at 0), and attribution settings.

Retain these outputs with their input flows and execution records to support repeatable analysis.
