"""Export the consolidated Parquet dataset to a single CSV file.

- Rows stream partition-by-partition in chronological order (memory-bounded).
- The three Parquet list columns (splt_direction, splt_ps, splt_piat_ms) are
  serialized as JSON array strings, since CSV has no list type. All 186
  columns are kept (the hive partition keys date/hour are not written).
- Written atomically (tmp file + rename).
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pyarrow.parquet as pq

LIST_COLS = ("splt_direction", "splt_ps", "splt_piat_ms")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", required=True, type=Path,
                    help="the hive-partitioned dataset directory")
    ap.add_argument("--out", required=True, type=Path, help="output .csv path")
    args = ap.parse_args()

    parts = sorted(args.dataset_dir.rglob("*.parquet"))
    if not parts:
        raise SystemExit(f"no parquet files under {args.dataset_dir}")

    tmp = args.out.with_suffix(".csv.tmp")
    t0 = time.time()
    rows_out = 0
    header = None
    with open(tmp, "w", newline="") as fh:
        import csv as csvmod
        writer = csvmod.writer(fh)
        for i, p in enumerate(parts):
            table = pq.read_table(p)
            cols = table.column_names
            if header is None:
                header = cols
                writer.writerow(header)
            elif cols != header:
                raise SystemExit(f"schema mismatch in {p}: {cols} != {header}")
            data = table.to_pydict()
            list_idx = {c: cols.index(c) for c in LIST_COLS if c in cols}
            columns = [data[c] for c in cols]
            for row in zip(*columns):
                row = list(row)
                for c, idx in list_idx.items():
                    row[idx] = json.dumps(row[idx])
                writer.writerow(row)
                rows_out += 1
            if (i + 1) % 10 == 0 or i == len(parts) - 1:
                print(f"[{i + 1}/{len(parts)}] {rows_out} rows, "
                      f"{time.time() - t0:.0f}s", flush=True)
    tmp.replace(args.out)
    size = args.out.stat().st_size
    print(f"Wrote {rows_out} rows, {len(header)} columns, "
          f"{size / 1e9:.2f} GB -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
