#!/usr/bin/env python3
"""
label_flows.py  -  Automatic labeling of NFStream flow records from attacklog output.

Joins attacklog JSON exports (one structured record per attack attempt) against
the flow CSV produced by flow-extraction and appends a single `label` column whose
value is the `attack_name` of the matching attack, or BENIGN for everything else.

Matching (hybrid, per the thesis "Automatic Labeling" methodology):

  Join key : src_ip + dst_ip + dst_port + protocol
             (dst_port matched against the attack's single port / range / list;
              the attacker's src_port is not recorded, so it is ignored.)

  1. TIME-WINDOW (primary, authoritative)
     A forward flow (src_ip == attacker) is labeled with an attack whose
     [t_start, t_end] window - widened by +/- tolerance for clock jitter -
     overlaps the flow's [first_seen, last_seen]. If several qualify (rare, only
     at window edges) the nearest window-centre wins.

     Time is REQUIRED because the 4-tuple is not unique: a target's port 80, say,
     is shared by the port-scan and every web attack against it. Only the time
     window separates them.

  2. TUPLE FALLBACK (for out-of-sync / mis-logged sessions; --no-fallback disables it)
     A forward flow that matches no window but still matches an attack's
     src+dst+port+proto tuple is assigned to the nearest same-tuple window.
     This recovers scans whose attacklog timestamp drifted from NTP, whose end
     time was logged too early, or that were not logged at all, without ever
     stealing a flow already claimed in step 1.

Everything else - background/infrastructure traffic, reverse-shell callbacks
(target -> attacker; not recorded by design), and attacker traffic to a service
that was never logged - is labeled BENIGN.

Pure standard library; no third-party dependencies (matches the attacklog tool).
"""

import argparse
import csv
import glob
import json
import os
import sys
import time
from datetime import datetime, timezone
from collections import defaultdict, Counter

BENIGN_LABEL = "BENIGN"
DEFAULT_TOLERANCE_MS = 1000  # +/- 1 s clock-jitter tolerance for the time window

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}

# CSV columns used for matching
COL_SRC_IP = "src_ip"
COL_DST_IP = "dst_ip"
COL_DST_PORT = "dst_port"
COL_PROTO = "protocol"
COL_FIRST = "bidirectional_first_seen_ms"
COL_LAST = "bidirectional_last_seen_ms"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def iso_to_ms(s):
    """'2026-07-14T19:14:10.245Z' -> epoch milliseconds (UTC)."""
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def parse_ports(spec):
    """'513' -> [(513,513)]; '1-65535' -> [(1,65535)]; '22,80,443' -> [(22,22),(80,80),(443,443)]."""
    intervals = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            intervals.append((int(lo), int(hi)))
        else:
            intervals.append((int(part), int(part)))
    return intervals


def port_in(port, intervals):
    return any(lo <= port <= hi for lo, hi in intervals)


def attacklog_files(paths):
    """Expand files and directories (every *.json inside, sorted) in the given order."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.json"))))
        elif os.path.isfile(p):
            files.append(p)
        else:
            sys.exit(f"--attacklog path not found: {p}")
    if not files:
        sys.exit(f"No attacklog JSON files found in {paths}")
    return files


# --------------------------------------------------------------------------- #
# Load attacklog records
# --------------------------------------------------------------------------- #
def load_records(files):
    records = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for r in data:
            if not r.get("t_end"):
                # open attack with no end time -> cannot form a window; skip.
                continue
            proto = PROTO_NUM.get(str(r["protocol"]).lower())
            if proto is None:
                continue
            t0 = iso_to_ms(r["t_start"])
            t1 = iso_to_ms(r["t_end"])
            records.append({
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "ports": parse_ports(r["dst_port"]),
                "proto": proto,
                "t0": t0,
                "t1": t1,
                "center": (t0 + t1) // 2,
                "name": r["attack_name"],
                "attacker_id": r.get("attacker_id"),
                "attack_id": r.get("attack_id"),
                "src_file": os.path.basename(path),
                "n_time": 0,       # flows matched by time window
                "n_fallback": 0,   # flows matched by tuple fallback
            })
    return records


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Label a flow CSV with attack names from attacklog JSON exports.")
    ap.add_argument("--flows", required=True, help="input flow CSV (from flow-extraction/export_csv.py)")
    ap.add_argument("--attacklog", required=True, nargs="+",
                    help="attacklog JSON export(s) and/or directories of them (all *.json, sorted); "
                         "records are matched in the order given")
    ap.add_argument("--out", required=True, help="output labeled CSV (input columns + label)")
    ap.add_argument("--summary", required=True, help="output JSON labeling summary")
    ap.add_argument("--tolerance-ms", type=int, default=DEFAULT_TOLERANCE_MS,
                    help="time-window widening on each side (default %(default)s)")
    ap.add_argument("--no-fallback", action="store_true", help="disable the tuple fallback (step 2)")
    args = ap.parse_args()
    if os.path.abspath(args.flows) == os.path.abspath(args.out):
        sys.exit("--out must differ from --flows")
    tolerance_ms = args.tolerance_ms
    enable_fallback = not args.no_fallback

    t_start = time.time()
    files = attacklog_files(args.attacklog)
    records = load_records(files)

    # Group records by (src_ip, dst_ip, proto) for O(1) candidate lookup.
    by_key = defaultdict(list)
    for idx, r in enumerate(records):
        by_key[(r["src_ip"], r["dst_ip"], r["proto"])].append(idx)
    attacker_ips = {r["src_ip"] for r in records}

    print(f"Loaded {len(records)} attack records from {len(files)} file(s): "
          f"{', '.join(os.path.basename(f) for f in files)}")
    print(f"Attacker source IPs: {sorted(attacker_ips)}")
    print(f"Reading : {args.flows}")
    print(f"Writing : {args.out}")
    print(f"Tolerance: +/-{tolerance_ms} ms   Tuple fallback: {enable_fallback}\n")

    label_counts = Counter()
    match_type = Counter()      # 'time' / 'fallback' / 'benign'
    n_rows = 0

    csv.field_size_limit(10 ** 9)
    tmp_out = args.out + ".tmp"
    with open(args.flows, "r", newline="", encoding="utf-8") as fin, \
         open(tmp_out, "w", newline="", encoding="utf-8") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)

        header = next(reader)
        col = {c: i for i, c in enumerate(header)}
        for needed in (COL_SRC_IP, COL_DST_IP, COL_DST_PORT, COL_PROTO, COL_FIRST, COL_LAST):
            if needed not in col:
                sys.exit(f"Required column '{needed}' not found in CSV header.")
        i_src, i_dst = col[COL_SRC_IP], col[COL_DST_IP]
        i_dport, i_proto = col[COL_DST_PORT], col[COL_PROTO]
        i_first, i_last = col[COL_FIRST], col[COL_LAST]

        writer.writerow(header + ["label"])

        for row in reader:
            n_rows += 1
            label = BENIGN_LABEL
            mtype = "benign"

            src = row[i_src]
            if src in attacker_ips:                      # forward attack traffic only
                dst = row[i_dst]
                try:
                    proto = int(row[i_proto])
                except ValueError:
                    proto = -1
                cand_idx = by_key.get((src, dst, proto))
                if cand_idx:
                    try:
                        dport = int(row[i_dport])
                    except ValueError:
                        dport = -1
                    try:
                        f_ms = int(row[i_first]); l_ms = int(row[i_last])
                    except ValueError:
                        f_ms = l_ms = None

                    tuple_hits = [ri for ri in cand_idx if port_in(dport, records[ri]["ports"])]
                    if tuple_hits and f_ms is not None:
                        fcenter = (f_ms + l_ms) // 2
                        # 1) time-window match
                        best_ri, best_d = None, None
                        for ri in tuple_hits:
                            r = records[ri]
                            if l_ms < r["t0"] - tolerance_ms or f_ms > r["t1"] + tolerance_ms:
                                continue
                            d = abs(fcenter - r["center"])
                            if best_d is None or d < best_d:
                                best_d, best_ri = d, ri
                        if best_ri is not None:
                            records[best_ri]["n_time"] += 1
                            label, mtype = records[best_ri]["name"], "time"
                        elif enable_fallback:
                            # 2) tuple fallback -> nearest same-tuple window
                            fb_ri, fb_d = None, None
                            for ri in tuple_hits:
                                d = abs(fcenter - records[ri]["center"])
                                if fb_d is None or d < fb_d:
                                    fb_d, fb_ri = d, ri
                            if fb_ri is not None:
                                records[fb_ri]["n_fallback"] += 1
                                label, mtype = records[fb_ri]["name"], "fallback"

            writer.writerow(row + [label])
            label_counts[label] += 1
            match_type[mtype] += 1

            if n_rows % 200000 == 0:
                print(f"  ...{n_rows:,} rows  ({time.time()-t_start:.0f}s)")
    os.replace(tmp_out, args.out)

    # ----------------------------------------------------------------------- #
    # Report
    # ----------------------------------------------------------------------- #
    elapsed = time.time() - t_start
    labeled = n_rows - label_counts[BENIGN_LABEL]
    print(f"\nDone. {n_rows:,} rows in {elapsed:.0f}s")
    print(f"  labeled (attack): {labeled:,} ({100*labeled/n_rows:.1f}%)")
    print(f"    - by time window : {match_type['time']:,}")
    print(f"    - by tuple fallback: {match_type['fallback']:,}")
    print(f"  {BENIGN_LABEL:<16}: {label_counts[BENIGN_LABEL]:,} ({100*label_counts[BENIGN_LABEL]/n_rows:.1f}%)")

    print("\nLabel distribution (attacks only, by flow count):")
    for name, cnt in sorted(((k, v) for k, v in label_counts.items() if k != BENIGN_LABEL),
                            key=lambda kv: -kv[1]):
        print(f"  {name:<45}{cnt:,}")

    zero = [r for r in records if r["n_time"] == 0 and r["n_fallback"] == 0]
    print(f"\nAttack records that matched ZERO flows (dry-runs / no captured traffic): {len(zero)}/{len(records)}")
    for r in zero:
        w0 = datetime.fromtimestamp(r["t0"] / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {r['attacker_id']:<11} {r['name']:<42} {w0}  ports={r['ports']}")

    summary = {
        "input_csv": args.flows,
        "output_csv": args.out,
        "attacklog_files": [os.path.basename(f) for f in files],
        "benign_label": BENIGN_LABEL,
        "tolerance_ms": tolerance_ms,
        "tuple_fallback_enabled": enable_fallback,
        "attacker_source_ips": sorted(attacker_ips),
        "total_flows": n_rows,
        "labeled_flows": labeled,
        "matched_by_time_window": match_type["time"],
        "matched_by_tuple_fallback": match_type["fallback"],
        "benign_flows": label_counts[BENIGN_LABEL],
        "attack_records_total": len(records),
        "attack_records_with_zero_flows": len(zero),
        "label_distribution": dict(sorted(label_counts.items(), key=lambda kv: -kv[1])),
        "per_record_matches": [
            {"attacker_id": r["attacker_id"], "attack_name": r["name"],
             "attack_id": r["attack_id"], "src_file": r["src_file"],
             "t_start_ms": r["t0"], "t_end_ms": r["t1"],
             "flows_by_time": r["n_time"], "flows_by_fallback": r["n_fallback"]}
            for r in records
        ],
        "elapsed_seconds": round(elapsed, 1),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(args.summary, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\nSummary written to: {args.summary}")


if __name__ == "__main__":
    main()
