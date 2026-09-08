# Flow Labelling

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Assigns labels to the CSV produced by [flow-extraction](../flow-extraction/README.md), using JSON execution records exported by [attacklog](../attacklog/README.md).

## Requirements and inputs

Python 3.10 or later; only standard-library modules are used. Supply a flow CSV containing `src_ip`, `dst_ip`, `dst_port`, `protocol`, `bidirectional_first_seen_ms`, and `bidirectional_last_seen_ms`, together with a directory of attacklog JSON exports. Flow timestamps are UTC epoch milliseconds and protocol values are numeric.

## Running

From the unified repository root, run the following in Bash (for example, WSL). Replace the example paths with your data locations. Set all four variables to override the original laboratory paths embedded in the script.

```bash
mkdir -p /path/to/dataset/output
ATTACKLOG_DIR=/path/to/attacklog-exports \
IN_CSV=/path/to/dataset/output/flows.csv \
OUT_CSV=/path/to/dataset/output/flows_labelled.csv \
SUMMARY=/path/to/dataset/output/labelling_summary.json \
python3 flow-labeling/label_flows.py
```

Use distinct input and output CSV paths. Existing output files are overwritten.

## Attribution procedure

The script matches the attacker source address, exact destination address, protocol, and destination port (including port ranges and lists). It first looks for overlap between the flow interval and a recorded execution interval, expanded by one second at each end. When multiple records qualify, the nearest interval centre wins.

With tuple fallback enabled, a flow with no overlapping interval is assigned to the nearest execution matching the same addresses, protocol, and destination port, without a maximum time-distance limit. Defaults are `TOLERANCE_MS = 1000` and `ENABLE_TUPLE_FALLBACK = True`, defined in the script.

Unmatched flows receive `BENIGN`. This is the unmatched category, not independent confirmation that the traffic is harmless. Matching uses the recorded forward direction; destination CIDR blocks and IP ranges are not expanded by this implementation. Records without an end time or with unsupported protocols are skipped. Equal-distance ties retain the first candidate, so preserve JSON filenames and record order when reproducing a run.

## Outputs

- A CSV retaining the input columns and appending `label`, containing the matched `attack_name` or `BENIGN`.
- A JSON summary with label counts, time-window and fallback counts, per-record matches, and attribution settings.

Retain these outputs with their input flows and execution records to support repeatable analysis.