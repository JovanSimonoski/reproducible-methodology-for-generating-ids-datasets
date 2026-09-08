"""Validate the consolidated flow dataset against the manifest.

Checks (all reported, none silently passed over):
  - files found vs processed vs failed reconciliation
  - packet reconciliation: sum of flow packets vs ground-truth pcap scan counts
  - physically impossible values (negative durations, zero-packet flows,
    timestamps outside the capture window)
  - duration / packet / byte distributions
  - capture-window continuity (gaps between consecutive files)
  - flow counts by protocol, top talkers
  - duplicate flow_id / duplicate (canonical_key, first_seen) rows

Writes validation_report.json next to the dataset and prints a summary.
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import pyarrow.dataset as ds

from common import utc_from_ms, write_json


def pctiles(values, pts=(0, 25, 50, 75, 95, 99, 100)):
    if len(values) == 0:
        return {}
    vs = sorted(values)
    out = {}
    for p in pts:
        idx = min(len(vs) - 1, int(round(p / 100 * (len(vs) - 1))))
        out[f"p{p}"] = vs[idx]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work-dir", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()

    report = {}

    # ---- manifest reconciliation -------------------------------------------
    manifest = list(csv.DictReader(open(args.work_dir / "manifest.csv")))
    by_status = Counter(r["status"] for r in manifest)
    ok_rows = [r for r in manifest if r["status"] in ("ok", "skipped")]
    total_pcap_packets = sum(int(r["packet_count"]) for r in ok_rows)
    total_fragment_packets = sum(int(r["flow_packets_total"]) for r in ok_rows)
    report["files"] = {
        "manifest_rows": len(manifest),
        "by_status": dict(by_status),
        "failed_files": [r["source_pcap"] for r in manifest if r["status"] == "failed"],
    }
    report["packets"] = {
        "pcap_scan_total": total_pcap_packets,
        "flow_packets_total": total_fragment_packets,
        "delta_unaccounted": total_pcap_packets - total_fragment_packets,
        "delta_pct": round(100 * (total_pcap_packets - total_fragment_packets)
                           / total_pcap_packets, 4) if total_pcap_packets else None,
    }

    # capture-window continuity from the manifest
    times = sorted((float(r["first_packet_ts"]), float(r["last_packet_ts"]))
                   for r in ok_rows)
    gaps = []
    for (f1, l1), (f2, l2) in zip(times, times[1:]):
        gap = f2 - l1
        if gap > 30:
            gaps.append({"after_ts": l1, "gap_seconds": round(gap, 1)})
    report["capture_gaps_over_30s"] = gaps
    report["capture_window_utc"] = {
        "first_packet": str(utc_from_ms(times[0][0] * 1000)),
        "last_packet": str(utc_from_ms(max(l for _, l in times) * 1000)),
    }

    # ---- dataset checks -----------------------------------------------------
    dataset = ds.dataset(args.output_dir / "dataset", format="parquet",
                         partitioning="hive")
    cols = ["flow_id", "canonical_key", "protocol", "src_ip", "dst_ip",
            "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
            "bidirectional_duration_ms", "bidirectional_packets",
            "bidirectional_bytes", "n_fragments", "truncated_start",
            "truncated_end", "recut_active_timeout"]
    tbl = dataset.to_table(columns=cols)
    n = tbl.num_rows
    report["flows"] = {"rows": n}

    col = {c: tbl.column(c).to_pylist() for c in cols}

    dataset_packets = sum(col["bidirectional_packets"])
    report["packets"]["dataset_flow_packets"] = dataset_packets
    report["packets"]["dataset_vs_fragments_delta"] = (
        total_fragment_packets - dataset_packets)

    # impossible values
    first_ts = times[0][0] * 1000
    last_ts = max(l for _, l in times) * 1000
    impossible = {
        "negative_duration": sum(1 for d in col["bidirectional_duration_ms"] if d < 0),
        "zero_packet_flows": sum(1 for p in col["bidirectional_packets"] if p <= 0),
        "zero_byte_flows": sum(1 for b in col["bidirectional_bytes"] if b <= 0),
        "first_seen_before_capture": sum(
            1 for t in col["bidirectional_first_seen_ms"] if t < first_ts - 1000),
        "last_seen_after_capture": sum(
            1 for t in col["bidirectional_last_seen_ms"] if t > last_ts + 1000),
        "last_before_first": sum(
            1 for f, l in zip(col["bidirectional_first_seen_ms"],
                              col["bidirectional_last_seen_ms"]) if l < f),
    }
    report["impossible_values"] = impossible

    # distributions
    report["distributions"] = {
        "duration_s": pctiles([d / 1000 for d in col["bidirectional_duration_ms"]]),
        "packets": pctiles(col["bidirectional_packets"]),
        "bytes": pctiles(col["bidirectional_bytes"]),
        "n_fragments": dict(Counter(col["n_fragments"])),
    }
    report["stitching"] = {
        "stitched_flows": sum(1 for x in col["n_fragments"] if x > 1),
        "recut_active_timeout": sum(1 for x in col["recut_active_timeout"] if x),
        "truncated_start": sum(1 for x in col["truncated_start"] if x),
        "truncated_end": sum(1 for x in col["truncated_end"] if x),
    }

    # protocol counts and top talkers
    report["protocol_flow_counts"] = dict(Counter(col["protocol"]).most_common())
    ip_flows = Counter()
    ip_bytes = Counter()
    for s, d, b in zip(col["src_ip"], col["dst_ip"], col["bidirectional_bytes"]):
        ip_flows[s] += 1
        ip_flows[d] += 1
        ip_bytes[s] += b
        ip_bytes[d] += b
    report["top_talkers_by_flows"] = dict(ip_flows.most_common(10))
    report["top_talkers_by_bytes"] = dict(ip_bytes.most_common(10))

    # duplicates
    dup_flow_ids = n - len(set(col["flow_id"]))
    key_first = Counter(zip(col["canonical_key"], col["bidirectional_first_seen_ms"]))
    dup_key_first = sum(c - 1 for c in key_first.values() if c > 1)
    report["duplicates"] = {
        "duplicate_flow_id_rows": dup_flow_ids,
        "duplicate_key_plus_first_seen_rows": dup_key_first,
    }

    write_json(args.output_dir / "validation_report.json", report)
    print(json.dumps(report, indent=2, default=str))

    problems = []
    if by_status.get("failed"):
        problems.append(f"{by_status['failed']} files failed extraction")
    if dup_flow_ids:
        problems.append(f"{dup_flow_ids} duplicate flow_id rows")
    for k, v in impossible.items():
        if v:
            problems.append(f"{v} rows with {k}")
    if report["packets"]["dataset_vs_fragments_delta"] != 0:
        problems.append("fragment/dataset packet totals disagree")
    print("\nPROBLEMS: " + ("; ".join(problems) if problems else "none"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
