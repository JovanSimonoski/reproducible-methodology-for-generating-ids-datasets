"""Extract flows from ONE pcap with NFStream and write a fragment parquet.

Invoked as a subprocess by extract.py so that a crash (including a segfault
in native code) is isolated to this file. Writes:
  <out>.parquet  — one row per flow fragment, full NFStream schema + bookkeeping
  <out>.meta.json — file-level ground truth (packet scan) + extraction stats

Exit code 0 on success; nonzero with a traceback on stderr otherwise.
"""

import argparse
import json
import os
import sys
import time

import pyarrow.parquet as pq
from nfstream import NFStreamer

from common import (
    FRAGMENT_EXTRA_TYPES,
    NFLOW_TYPES,
    canonical_key,
    records_to_table,
    scan_pcap,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="path of pcap to read (may be a staged copy)")
    ap.add_argument("--rel", required=True, help="relative path of the ORIGINAL pcap (recorded as source_pcap)")
    ap.add_argument("--out", required=True, help="output parquet path (written atomically)")
    ap.add_argument("--meta", required=True, help="output meta json path")
    ap.add_argument("--idle-timeout", type=int, required=True)
    ap.add_argument("--active-timeout", type=int, required=True)
    ap.add_argument("--accounting-mode", type=int, required=True)
    ap.add_argument("--splt", type=int, required=True)
    ap.add_argument("--n-dissections", type=int, required=True)
    args = ap.parse_args()

    t0 = time.time()
    scan = scan_pcap(args.pcap)

    file_stem = os.path.basename(args.rel).rsplit(".pcap", 1)[0]

    streamer = NFStreamer(
        source=args.pcap,
        decode_tunnels=True,
        promiscuous_mode=False,
        statistical_analysis=True,
        splt_analysis=args.splt,
        n_dissections=args.n_dissections,
        accounting_mode=args.accounting_mode,
        idle_timeout=args.idle_timeout,
        active_timeout=args.active_timeout,
    )

    records = []
    nflow_keys = None
    for flow in streamer:
        if nflow_keys is None:
            nflow_keys = list(flow.keys())
        rec = dict(zip(flow.keys(), flow.values()))
        rec["fragment_id"] = f"{file_stem}-{flow.id}"
        rec["source_pcap"] = args.rel
        rec["canonical_key"] = canonical_key(
            flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol
        )
        records.append(rec)

    # Fail loudly if this NFStream version emits fields our schema doesn't know.
    if nflow_keys is not None:
        unknown = [k for k in nflow_keys if k not in NFLOW_TYPES]
        if unknown:
            raise RuntimeError(
                f"NFStream emitted fields missing from NFLOW_TYPES: {unknown}. "
                "Update common.py rather than dropping them."
            )

    type_map = dict(NFLOW_TYPES)
    type_map.update(FRAGMENT_EXTRA_TYPES)
    table = records_to_table(records, type_map)

    tmp = args.out + ".tmp"
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, args.out)

    flows_pkts = sum(r["bidirectional_packets"] for r in records)
    meta = {
        "source_pcap": args.rel,
        "pcap_size_bytes": os.path.getsize(args.pcap),
        "scan": scan,
        "n_flows": len(records),
        "flow_packets_total": flows_pkts,
        "extract_seconds": round(time.time() - t0, 3),
        "config": {
            "idle_timeout": args.idle_timeout,
            "active_timeout": args.active_timeout,
            "accounting_mode": args.accounting_mode,
            "splt_analysis": args.splt,
            "n_dissections": args.n_dissections,
        },
    }
    tmp = args.meta + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(meta, fh, indent=2)
    os.replace(tmp, args.meta)
    return 0


if __name__ == "__main__":
    sys.exit(main())
