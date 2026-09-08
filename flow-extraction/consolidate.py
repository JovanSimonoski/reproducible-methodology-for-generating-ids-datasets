"""Consolidate per-pcap fragment parquets into the final flow dataset.

Streaming, chronological pass over the intermediate outputs of extract.py:

1. STITCH flow fragments split by the 10-minute file rotation. A fragment in
   file N+1 continues a fragment chain from file N when they share a canonical
   key and the gap between them is <= idle_timeout (exactly NFStream's flow
   continuation rule). Chains are re-cut at active_timeout (at fragment
   granularity) to keep flow semantics consistent with an unsplit capture.
   Merge math:
     - packets / bytes / TCP-flag counters: summed
     - first/last seen and durations: recomputed from the union
     - min/max of packet sizes and inter-arrivals: combined min/max
     - mean/stddev of packet sizes: exact pooled-moment combination
     - mean/stddev of inter-arrivals: exact pooled-moment combination
       including the seam gap between fragments (which is known)
     - SPLT: the head fragment's sequence is the true flow head; if it has
       fewer than N entries, it is extended from the continuation fragment
       (seam gap becomes the appended packet's inter-arrival time)
     - nDPI application fields: head fragment's values win; a later
       fragment's value is used only when the head's is null/Unknown
     - direction columns of a continuation seen in reverse orientation are
       swapped before merging
2. DERIVED columns (rates, ratios, address/port flags, UTC calendar fields,
   truncation flags, stable flow_id).
3. Writes Parquet partitioned by date=YYYY-MM-DD/hour=HH (UTC, flow start),
   plus run_metadata.json. Memory-bounded: partitions are flushed once the
   stream has safely moved past them.

Stddev convention: NFStream reports SAMPLE standard deviation (ddof=1),
verified empirically against SPLT sequences during the pilot run.
"""

import argparse
import json
import math
import os
import platform
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from common import (
    FRAGMENT_EXTRA_TYPES,
    NFLOW_TYPES,
    WELL_KNOWN_PORT_MAX,
    ip_flags,
    records_to_table,
    utc_from_ms,
    write_json,
)

STDDEV_DDOF = 1  # NFStream reports sample stddev (verified in pilot)

STAT_FAMILIES = ("bidirectional", "src2dst", "dst2src")
FLAGS = ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin")

DIR_BLOCK_SUFFIXES = (
    "first_seen_ms", "last_seen_ms", "duration_ms", "packets", "bytes",
    "min_ps", "mean_ps", "stddev_ps", "max_ps",
    "min_piat_ms", "mean_piat_ms", "stddev_piat_ms", "max_piat_ms",
)


# ---------------------------------------------------------------------------
# moment merging
# ---------------------------------------------------------------------------


def _merge_two(n1, mean1, std1, n2, mean2, std2):
    """Pool (count, mean, sample-stddev) of two disjoint samples."""
    if n1 == 0:
        return n2, mean2, std2
    if n2 == 0:
        return n1, mean1, std1
    n = n1 + n2
    mean = (n1 * mean1 + n2 * mean2) / n
    m2_1 = (std1 ** 2) * max(n1 - STDDEV_DDOF, 0)
    m2_2 = (std2 ** 2) * max(n2 - STDDEV_DDOF, 0)
    delta = mean2 - mean1
    m2 = m2_1 + m2_2 + delta * delta * n1 * n2 / n
    std = math.sqrt(m2 / (n - STDDEV_DDOF)) if n > STDDEV_DDOF else 0.0
    return n, mean, std


def merge_moments(parts):
    """Pool a list of (count, mean, sample_stddev) tuples."""
    n, mean, std = 0, 0.0, 0.0
    for pn, pmean, pstd in parts:
        n, mean, std = _merge_two(n, mean, std, pn, pmean or 0.0, pstd or 0.0)
    return n, mean, std


# ---------------------------------------------------------------------------
# fragment orientation
# ---------------------------------------------------------------------------


def _swap_dir(name):
    if "src2dst" in name:
        return name.replace("src2dst", "dst2src")
    if "dst2src" in name:
        return name.replace("dst2src", "src2dst")
    return name


def frag_get(frag, field, reversed_):
    return frag[_swap_dir(field)] if reversed_ else frag[field]


# ---------------------------------------------------------------------------
# chain state
# ---------------------------------------------------------------------------


class Chain:
    __slots__ = ("row", "piat_n", "splt_len", "fragment_ids", "source_pcaps",
                 "head_file", "tail_file", "recut", "n_fragments")

    def __init__(self, frag, splt_n, file_rel, recut=False):
        self.row = dict(frag)  # head fragment defines orientation & identity
        self.piat_n = {fam: max(0, frag[f"{fam}_packets"] - 1)
                       for fam in STAT_FAMILIES}
        self.splt_len = min(frag["bidirectional_packets"], splt_n)
        self.fragment_ids = [frag["fragment_id"]]
        self.source_pcaps = [file_rel]
        self.head_file = file_rel
        self.tail_file = file_rel
        self.recut = recut
        self.n_fragments = 1

    def is_reversed(self, frag):
        r = self.row
        return not (
            (frag["src_ip"], frag["src_port"]) == (r["src_ip"], r["src_port"])
            and (frag["dst_ip"], frag["dst_port"]) == (r["dst_ip"], r["dst_port"])
        )

    def extend(self, frag, splt_n, file_rel):
        rev = self.is_reversed(frag)
        row = self.row

        # seams per family, computed before any counter is updated
        seams = {}
        for fam in STAT_FAMILIES:
            if row[f"{fam}_packets"] > 0 and frag_get(frag, f"{fam}_packets", rev) > 0:
                seams[fam] = (frag_get(frag, f"{fam}_first_seen_ms", rev)
                              - row[f"{fam}_last_seen_ms"])
        bidir_seam = seams["bidirectional"]  # both sides always have >=1 packet

        for fam in STAT_FAMILIES:
            chain_pkts = row[f"{fam}_packets"]
            frag_pkts = frag_get(frag, f"{fam}_packets", rev)
            if frag_pkts == 0:
                continue
            if chain_pkts == 0:
                # direction previously unseen: adopt fragment's block wholesale
                for suffix in DIR_BLOCK_SUFFIXES:
                    row[f"{fam}_{suffix}"] = frag_get(frag, f"{fam}_{suffix}", rev)
                for flag in FLAGS:
                    row[f"{fam}_{flag}_packets"] = frag_get(
                        frag, f"{fam}_{flag}_packets", rev)
                self.piat_n[fam] = max(0, frag_pkts - 1)
                continue

            # packet-size moments (counts = packet counts)
            _, mean, std = merge_moments([
                (chain_pkts, row[f"{fam}_mean_ps"], row[f"{fam}_stddev_ps"]),
                (frag_pkts, frag_get(frag, f"{fam}_mean_ps", rev),
                 frag_get(frag, f"{fam}_stddev_ps", rev)),
            ])
            row[f"{fam}_mean_ps"] = mean
            row[f"{fam}_stddev_ps"] = std
            row[f"{fam}_min_ps"] = min(row[f"{fam}_min_ps"],
                                       frag_get(frag, f"{fam}_min_ps", rev))
            row[f"{fam}_max_ps"] = max(row[f"{fam}_max_ps"],
                                       frag_get(frag, f"{fam}_max_ps", rev))

            # inter-arrival moments: chain piats + seam + fragment piats
            frag_piat_n = max(0, frag_pkts - 1)
            n, mean, std = merge_moments([
                (self.piat_n[fam], row[f"{fam}_mean_piat_ms"],
                 row[f"{fam}_stddev_piat_ms"]),
                (1, float(seams[fam]), 0.0),
                (frag_piat_n, frag_get(frag, f"{fam}_mean_piat_ms", rev),
                 frag_get(frag, f"{fam}_stddev_piat_ms", rev)),
            ])
            row[f"{fam}_mean_piat_ms"] = mean
            row[f"{fam}_stddev_piat_ms"] = std
            mins, maxs = [float(seams[fam])], [float(seams[fam])]
            if self.piat_n[fam] > 0:
                mins.append(row[f"{fam}_min_piat_ms"])
                maxs.append(row[f"{fam}_max_piat_ms"])
            if frag_piat_n > 0:
                mins.append(frag_get(frag, f"{fam}_min_piat_ms", rev))
                maxs.append(frag_get(frag, f"{fam}_max_piat_ms", rev))
            row[f"{fam}_min_piat_ms"] = min(mins)
            row[f"{fam}_max_piat_ms"] = max(maxs)
            self.piat_n[fam] = n

            row[f"{fam}_packets"] += frag_pkts
            row[f"{fam}_bytes"] += frag_get(frag, f"{fam}_bytes", rev)
            row[f"{fam}_last_seen_ms"] = frag_get(frag, f"{fam}_last_seen_ms", rev)
            row[f"{fam}_duration_ms"] = (row[f"{fam}_last_seen_ms"]
                                         - row[f"{fam}_first_seen_ms"])
            for flag in FLAGS:
                f = f"{fam}_{flag}_packets"
                row[f] += frag_get(frag, f, rev)

        # SPLT extension from the continuation fragment
        if self.splt_len < splt_n:
            frag_valid = min(frag["bidirectional_packets"], splt_n)
            for i in range(frag_valid):
                if self.splt_len >= splt_n:
                    break
                d = frag["splt_direction"][i]
                if rev and d in (0, 1):
                    d = 1 - d
                piat = float(bidir_seam) if i == 0 else float(frag["splt_piat_ms"][i])
                for col, val in (("splt_direction", d),
                                 ("splt_ps", frag["splt_ps"][i]),
                                 ("splt_piat_ms", piat)):
                    lst = row[col]
                    if self.splt_len < len(lst):
                        lst[self.splt_len] = val
                    else:
                        lst.append(val)
                self.splt_len += 1

        # nDPI fields: head wins unless head is null/Unknown
        if (row.get("application_name") in (None, "", "Unknown")
                and frag.get("application_name") not in (None, "", "Unknown")):
            for f in ("application_name", "application_category_name",
                      "application_is_guessed", "application_confidence"):
                row[f] = frag.get(f)
        for f in ("requested_server_name", "client_fingerprint",
                  "server_fingerprint", "user_agent", "content_type"):
            if row.get(f) in (None, "") and frag.get(f) not in (None, ""):
                row[f] = frag.get(f)

        row["expiration_id"] = frag["expiration_id"]
        self.fragment_ids.append(frag["fragment_id"])
        if file_rel != self.source_pcaps[-1]:
            self.source_pcaps.append(file_rel)
        self.tail_file = file_rel
        self.n_fragments += 1


# ---------------------------------------------------------------------------
# derived columns
# ---------------------------------------------------------------------------


def _rate(num, dur_ms):
    return (num * 1000.0 / dur_ms) if dur_ms > 0 else None


def _ratio(a, b):
    return (a / b) if b else None


def finalize(chain, splt_n, idle_ms, file_info, corpus_first_rel, corpus_last_rel):
    row = chain.row
    out = dict(row)

    out["flow_id"] = chain.fragment_ids[0]
    out["n_fragments"] = chain.n_fragments
    out["fragment_ids"] = ",".join(chain.fragment_ids)
    out["source_pcap"] = chain.head_file
    out["source_pcaps"] = ",".join(chain.source_pcaps)
    out["recut_active_timeout"] = chain.recut

    # Truncation flags: interior boundaries were repaired by stitching, so a
    # flow can only be silently cut at the corpus edges or next to a
    # failed/missing neighbour file.
    head = file_info[chain.head_file]
    tail = file_info[chain.tail_file]
    starts_near_edge = (row["bidirectional_first_seen_ms"]
                        - head["first_ts"] * 1000.0) <= idle_ms
    ends_near_edge = (tail["last_ts"] * 1000.0
                      - row["bidirectional_last_seen_ms"]) <= idle_ms
    out["truncated_start"] = bool(
        starts_near_edge and (chain.head_file == corpus_first_rel
                              or not head["prev_ok"]))
    out["truncated_end"] = bool(
        ends_near_edge and (chain.tail_file == corpus_last_rel
                            or not tail["next_ok"]))

    out["duration_s"] = row["bidirectional_duration_ms"] / 1000.0
    for fam in STAT_FAMILIES:
        fdur = row[f"{fam}_duration_ms"]
        out[f"{fam}_pps"] = _rate(row[f"{fam}_packets"], fdur)
        out[f"{fam}_bps"] = _rate(row[f"{fam}_bytes"], fdur)
    out["bytes_ratio_updown"] = _ratio(row["src2dst_bytes"], row["dst2src_bytes"])
    out["packets_ratio_updown"] = _ratio(row["src2dst_packets"],
                                         row["dst2src_packets"])

    out["is_ipv4"] = row["ip_version"] == 4
    out["is_ipv6"] = row["ip_version"] == 6
    out["is_tcp"] = row["protocol"] == 6
    out["is_udp"] = row["protocol"] == 17
    out["is_other_protocol"] = row["protocol"] not in (6, 17)

    sp, sm, sb = ip_flags(row["src_ip"])
    dp, dm, db = ip_flags(row["dst_ip"])
    out["src_is_private"], out["src_is_multicast"], out["src_is_broadcast"] = sp, sm, sb
    out["dst_is_private"], out["dst_is_multicast"], out["dst_is_broadcast"] = dp, dm, db

    src_wk = row["src_port"] < WELL_KNOWN_PORT_MAX
    dst_wk = row["dst_port"] < WELL_KNOWN_PORT_MAX
    out["src_port_wellknown"] = src_wk
    out["dst_port_wellknown"] = dst_wk
    if src_wk != dst_wk:
        out["service_port"] = row["src_port"] if src_wk else row["dst_port"]
    else:
        out["service_port"] = min(row["src_port"], row["dst_port"])

    start = utc_from_ms(row["bidirectional_first_seen_ms"])
    out["start_date"] = start.strftime("%Y-%m-%d")
    out["start_hour"] = start.hour
    out["start_minute"] = start.minute
    out["start_day_of_week"] = start.weekday()  # Monday = 0

    # flattened SPLT (null beyond the valid entries)
    valid = min(chain.splt_len, splt_n)
    for i in range(splt_n):
        if i < valid:
            out[f"splt_direction_{i}"] = row["splt_direction"][i]
            out[f"splt_ps_{i}"] = row["splt_ps"][i]
            out[f"splt_piat_ms_{i}"] = row["splt_piat_ms"][i]
        else:
            out[f"splt_direction_{i}"] = None
            out[f"splt_ps_{i}"] = None
            out[f"splt_piat_ms_{i}"] = None
    return out


def final_type_map(splt_n):
    t = dict(NFLOW_TYPES)
    t.update(FRAGMENT_EXTRA_TYPES)  # fragment_id (head), source_pcap, canonical_key
    t.update({
        "flow_id": pa.string(),
        "n_fragments": pa.int64(),
        "fragment_ids": pa.string(),
        "source_pcaps": pa.string(),
        "recut_active_timeout": pa.bool_(),
        "truncated_start": pa.bool_(),
        "truncated_end": pa.bool_(),
        "duration_s": pa.float64(),
        "bytes_ratio_updown": pa.float64(),
        "packets_ratio_updown": pa.float64(),
        "is_ipv4": pa.bool_(), "is_ipv6": pa.bool_(),
        "is_tcp": pa.bool_(), "is_udp": pa.bool_(), "is_other_protocol": pa.bool_(),
        "src_is_private": pa.bool_(), "src_is_multicast": pa.bool_(),
        "src_is_broadcast": pa.bool_(),
        "dst_is_private": pa.bool_(), "dst_is_multicast": pa.bool_(),
        "dst_is_broadcast": pa.bool_(),
        "src_port_wellknown": pa.bool_(), "dst_port_wellknown": pa.bool_(),
        "service_port": pa.int64(),
        "start_date": pa.string(), "start_hour": pa.int64(),
        "start_minute": pa.int64(), "start_day_of_week": pa.int64(),
    })
    for fam in STAT_FAMILIES:
        t[f"{fam}_pps"] = pa.float64()
        t[f"{fam}_bps"] = pa.float64()
    for i in range(splt_n):
        t[f"splt_direction_{i}"] = pa.int64()
        t[f"splt_ps_{i}"] = pa.int64()
        t[f"splt_piat_ms_{i}"] = pa.float64()
    return t


# ---------------------------------------------------------------------------
# partitioned output
# ---------------------------------------------------------------------------


class PartitionWriter:
    def __init__(self, out_dir, type_map):
        self.out_dir = out_dir
        self.type_map = type_map
        self.buffers = defaultdict(list)
        self.part_index = defaultdict(int)
        self.rows_written = 0

    def add(self, row):
        self.buffers[(row["start_date"], row["start_hour"])].append(row)

    def flush_before(self, horizon_ms, margin_ms):
        for key in list(self.buffers):
            date, hour = key
            part_start = datetime.strptime(date, "%Y-%m-%d").replace(
                tzinfo=timezone.utc).timestamp() * 1000 + hour * 3600 * 1000
            part_end = part_start + 3600 * 1000
            if part_end + margin_ms < horizon_ms:
                self._write(key)

    def flush_all(self):
        for key in list(self.buffers):
            self._write(key)

    def _write(self, key):
        rows = self.buffers.pop(key)
        if not rows:
            return
        date, hour = key
        pdir = self.out_dir / f"date={date}" / f"hour={hour:02d}"
        pdir.mkdir(parents=True, exist_ok=True)
        path = pdir / f"part-{self.part_index[key]:04d}.parquet"
        self.part_index[key] += 1
        table = records_to_table(rows, self.type_map)
        tmp = str(path) + ".tmp"
        pq.write_table(table, tmp, compression="zstd")
        os.replace(tmp, path)
        self.rows_written += len(rows)


# ---------------------------------------------------------------------------
# main streaming pass
# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description="CSAD consolidation: stitch + derive + partition")
    ap.add_argument("--work-dir", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()

    with open(args.work_dir / "extract_config.json") as fh:
        config = json.load(fh)
    nf = config["nfstream_config"]
    idle_ms = nf["idle_timeout"] * 1000
    active_ms = nf["active_timeout"] * 1000
    splt_n = nf["splt_analysis"]

    inter = args.work_dir / "intermediate"
    metas = []
    for meta_path in sorted(inter.rglob("*.meta.json")):
        with open(meta_path) as fh:
            m = json.load(fh)
        m["_parquet"] = meta_path.with_name(
            meta_path.name.replace(".meta.json", ".parquet"))
        if not m["_parquet"].exists():
            raise SystemExit(f"meta without parquet: {meta_path}")
        metas.append(m)
    if not metas:
        raise SystemExit("no intermediate outputs found")
    metas.sort(key=lambda m: m["scan"]["first_ts"])

    # per-file adjacency info for the truncation flags
    file_info = {}
    for i, m in enumerate(metas):
        prev_ok = i > 0 and (
            m["scan"]["first_ts"] - metas[i - 1]["scan"]["last_ts"]) * 1000 <= idle_ms
        next_ok = i < len(metas) - 1 and (
            metas[i + 1]["scan"]["first_ts"] - m["scan"]["last_ts"]) * 1000 <= idle_ms
        file_info[m["source_pcap"]] = {
            "first_ts": m["scan"]["first_ts"],
            "last_ts": m["scan"]["last_ts"],
            "prev_ok": prev_ok,
            "next_ok": next_ok,
        }
    corpus_first_rel = metas[0]["source_pcap"]
    corpus_last_rel = metas[-1]["source_pcap"]

    out_dataset = args.output_dir / "dataset"
    out_dataset.mkdir(parents=True, exist_ok=True)
    writer = PartitionWriter(out_dataset, final_type_map(splt_n))

    stats = {"fragments_in": 0, "flows_out": 0, "stitched_flows": 0,
             "max_fragments": 1, "recut_active_timeout": 0,
             "truncated_start": 0, "truncated_end": 0}
    t0 = time.time()

    def emit(chain):
        row = finalize(chain, splt_n, idle_ms, file_info,
                       corpus_first_rel, corpus_last_rel)
        stats["flows_out"] += 1
        if chain.n_fragments > 1:
            stats["stitched_flows"] += 1
            stats["max_fragments"] = max(stats["max_fragments"], chain.n_fragments)
        if chain.recut:
            stats["recut_active_timeout"] += 1
        stats["truncated_start"] += row["truncated_start"]
        stats["truncated_end"] += row["truncated_end"]
        writer.add(row)

    carried = {}  # canonical_key -> Chain open at the previous file's end
    for fi, m in enumerate(metas):
        rel = m["source_pcap"]
        frags = pq.read_table(m["_parquet"]).to_pylist()
        frags.sort(key=lambda r: r["bidirectional_first_seen_ms"])
        stats["fragments_in"] += len(frags)
        file_last_ms = m["scan"]["last_ts"] * 1000

        open_now = {}  # key -> chain currently open while scanning this file
        for frag in frags:
            key = frag["canonical_key"]
            cur = open_now.pop(key, None)
            if cur is None:
                cur = carried.pop(key, None)
            if cur is not None:
                gap = (frag["bidirectional_first_seen_ms"]
                       - cur.row["bidirectional_last_seen_ms"])
                if 0 <= gap <= idle_ms:
                    if (frag["bidirectional_last_seen_ms"]
                            - cur.row["bidirectional_first_seen_ms"]) <= active_ms:
                        cur.extend(frag, splt_n, rel)
                        open_now[key] = cur
                        continue
                    # continuation would exceed active_timeout: cut like
                    # NFStream would, continuation becomes a new flow
                    emit(cur)
                    open_now[key] = Chain(frag, splt_n, rel, recut=True)
                    continue
                emit(cur)  # not a continuation; the old chain is finished
            open_now[key] = Chain(frag, splt_n, rel)

        # carried chains never touched by this file cannot continue (the next
        # boundary is > idle_timeout away): finalize them
        for chain in carried.values():
            emit(chain)

        # chains still active near this file's end are carried to the next file
        carried = {}
        for key, chain in open_now.items():
            if file_last_ms - chain.row["bidirectional_last_seen_ms"] <= idle_ms:
                carried[key] = chain
            else:
                emit(chain)

        writer.flush_before(m["scan"]["first_ts"] * 1000,
                            active_ms + 2 * 600 * 1000)
        if (fi + 1) % 25 == 0 or fi == len(metas) - 1:
            print(f"[{fi + 1}/{len(metas)}] {rel} | flows out {stats['flows_out']} "
                  f"| open chains {len(carried)} | {time.time() - t0:.0f}s",
                  flush=True)

    for chain in carried.values():
        emit(chain)
    writer.flush_all()

    import nfstream
    import pandas
    meta_out = {
        "run_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_versions": {
            "python": platform.python_version(),
            "nfstream": nfstream.__version__,
            "pandas": pandas.__version__,
            "pyarrow": pa.__version__,
        },
        "extract_config": config,
        "boundary_strategy": (
            "per-file extraction, post-hoc stitching on (canonical_key, gap <= "
            "idle_timeout), re-cut at active_timeout, truncation flags for "
            "corpus edges / failed neighbours"),
        "stddev_convention": f"sample stddev (ddof={STDDEV_DDOF})",
        "accounting_mode_meaning": "0 = link-layer (L2) bytes per packet",
        "timezone": "UTC (directory layout verified as UTC-bucketed)",
        "counts": {**stats, "rows_written": writer.rows_written,
                   "input_files": len(metas)},
    }
    write_json(args.output_dir / "run_metadata.json", meta_out)
    print(json.dumps(meta_out["counts"], indent=2))
    print(f"Dataset: {out_dataset}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
