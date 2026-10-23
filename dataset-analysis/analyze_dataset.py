#!/usr/bin/env python3
"""
analyze_dataset.py  -  Generate DATASET_STATISTICS.md for a dataset release.

Reads a release directory written by dataset-unification/build_dataset.py:

  <labeled csv>                     every flow column + capture_id + label
  build_summary.json                captures, label counts, applied relabels
  provenance/<capture>/             run_metadata.json, validation_report.json,
                                    labeling_summary.json, manifest.csv, attacklog/*.json

and writes DATASET_STATISTICS.md into the same directory (optionally also into
--info-dir). Every number in the report is computed here; nothing is typed in by
hand, so the report can be regenerated after each rebuild.

Requires pandas and pyarrow (requirements.txt).
"""

import argparse
import csv
import glob
import json
import math
import os
import shutil
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv

BENIGN_LABEL = "BENIGN"
LABEL_COL = "label"
CAPTURE_COL = "capture_id"
REPORT_NAME = "DATASET_STATISTICS.md"
LIST_COLS = ("splt_direction", "splt_ps", "splt_piat_ms")  # JSON copies of the flat splt_* columns
FULL_SCAN = "nmap-full-portscan"
FLAGS = ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin")
PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 50: "ESP", 132: "SCTP"}
PLATFORMS = {"ms2": "Metasploitable 2", "ms3": "Metasploitable 3", "vulnhub": "VulHub"}
TECHNIQUE_RULES = (
    ("-revshell", "Remote code execution (reverse shell)"),
    ("sqlmap", "SQL injection"),
    ("sqli", "SQL injection"),
    ("xss", "Cross-site scripting"),
    ("cmdinject", "OS command injection"),
    ("lfi", "Local file inclusion"),
    ("ssti", "Server-side template injection"),
    ("wordlist", "Brute force (wordlist)"),
    ("-dos", "Denial of service"),
    ("-enum", "Service enumeration"),
    ("cve-", "Known-vulnerability exploit (CVE/CNVD)"),
    ("cnvd-", "Known-vulnerability exploit (CVE/CNVD)"),
)
NDPI_TEXT = ("requested_server_name", "user_agent", "content_type",
             "client_fingerprint", "server_fingerprint")
STRING_COLS = {"src_ip", "src_mac", "src_oui", "dst_ip", "dst_mac", "dst_oui", "application_name",
               "application_category_name", *NDPI_TEXT, "fragment_id", "fragment_ids", "source_pcap",
               "source_pcaps", "canonical_key", "flow_id", "start_date", CAPTURE_COL, LABEL_COL}
# Columns that identify a flow, host, capture or absolute time (not behaviour).
IDENTIFYING = ["flow_id", "id", "fragment_id", "fragment_ids", "canonical_key", "source_pcap",
               "source_pcaps", "expiration_id", "src_ip", "dst_ip", "src_mac", "dst_mac", "src_oui",
               "dst_oui", "start_date", "start_hour", "start_minute", "start_day_of_week", CAPTURE_COL]

# Columns pulled into pandas for the analysis (everything else only feeds the column audit).
ANALYSIS_COLS = [
    CAPTURE_COL, LABEL_COL, "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "ip_version", "bidirectional_first_seen_ms", "bidirectional_last_seen_ms", "duration_s",
    "bidirectional_packets", "bidirectional_bytes", "src2dst_packets", "dst2src_packets",
    "dst2src_syn_packets", "dst2src_rst_packets", "bidirectional_fin_packets",
    "application_name", "application_category_name", "application_is_guessed", *NDPI_TEXT,
    "n_fragments", "truncated_start", "truncated_end", "recut_active_timeout",
    "src_is_private", "dst_is_private", "dst_is_multicast", "dst_is_broadcast",
    "service_port", "start_date", "start_hour",
]


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #
def fint(n):
    return f"{int(n):,}"


def fpct(a, b, digits=2):
    if not b:
        return "–"
    if a == 0:
        return "0%"
    p = 100.0 * a / b
    return "<0.01%" if p < 0.01 else f"{p:.{digits}f}%"


def fnum(x, digits=2):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "–"
    return f"{x:,.{digits}f}"


def fbytes(b):
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if b >= div:
            return f"{b / div:.2f} {unit}"
    return f"{int(b)} B"


def fts(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M")


def iso_ms(s):
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def fdays(ms):
    return f"{ms / 86_400_000:.2f} d"


def clean(text):
    return str(text).replace("|", "/").replace("\n", " ").strip()


def table(headers, rows, align=None):
    align = align or "l" + "r" * (len(headers) - 1)
    sep = {"l": ":---", "r": "---:", "c": ":---:"}
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(sep[a] for a in align) + " |"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def details(summary, body):
    return f"<details>\n<summary>{summary}</summary>\n\n{body}\n\n</details>"


# --------------------------------------------------------------------------- #
# Label taxonomy (derived from the canonical attack_name)
# --------------------------------------------------------------------------- #
def technique(label):
    if label == BENIGN_LABEL:
        return "Benign"
    if label == FULL_SCAN:
        return "Port scan (full TCP range)"
    if label.endswith("-portscan"):
        return "Service scan (single port, pre-exploit)"
    for key, name in TECHNIQUE_RULES:
        if key in label:
            return name
    return "Other"


def platform(label):
    if label == BENIGN_LABEL:
        return "–"
    return PLATFORMS.get(label.split("-", 1)[0], "All targets")


def col_group(c):
    if c in (CAPTURE_COL, LABEL_COL):
        return "Dataset (capture, label)"
    if c.startswith("splt_"):
        return "Early-packet sequence (SPLT, first 20 packets)"
    if c.startswith("application_") or c in NDPI_TEXT:
        return "Application / nDPI"
    if c in ("flow_id", "id", "expiration_id", "canonical_key", "src_ip", "dst_ip", "src_port",
             "dst_port", "protocol", "ip_version", "vlan_id", "tunnel_id", "src_mac", "dst_mac",
             "src_oui", "dst_oui"):
        return "Identity and keys"
    if c in ("fragment_id", "fragment_ids", "source_pcap", "source_pcaps", "n_fragments",
             "truncated_start", "truncated_end", "recut_active_timeout"):
        return "Provenance and stitching"
    if c.endswith(("_first_seen_ms", "_last_seen_ms", "_duration_ms")) or c in (
            "duration_s", "start_date", "start_hour", "start_minute", "start_day_of_week"):
        return "Timing"
    if any(c.endswith(f"_{f}_packets") for f in FLAGS):
        return "TCP flag counters"
    if c.endswith("_piat_ms"):
        return "Inter-arrival-time statistics"
    if c.endswith("_ps"):
        return "Packet-size statistics"
    if c.endswith(("_packets", "_bytes", "_pps", "_bps")) or c.endswith("_ratio_updown"):
        return "Volume and rates"
    if c.startswith(("is_", "src_is_", "dst_is_")) or c in (
            "src_port_wellknown", "dst_port_wellknown", "service_port"):
        return "Address / port / protocol flags"
    return "Other"


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def load_inputs(release_dir, build):
    """Per-capture provenance copied into the release by build_dataset.py."""
    caps = []
    for c in build["captures"]:
        cid = c["capture_id"]
        prov = os.path.join(release_dir, "provenance", cid)
        logs = sorted(glob.glob(os.path.join(prov, "attacklog", "*.json")))
        records = []
        for f in logs:
            with open(f, encoding="utf-8") as fh:
                for r in json.load(fh):
                    r["capture_id"] = cid
                    records.append(r)
        with open(os.path.join(prov, "manifest.csv"), newline="") as fh:
            manifest = list(csv.DictReader(fh))

        def js(name):
            with open(os.path.join(prov, name), encoding="utf-8") as fh:
                return json.load(fh)

        caps.append({"id": cid, "records": records, "manifest": manifest,
                     "attacklog_files": [os.path.basename(f) for f in logs],
                     "run": js("run_metadata.json"), "validation": js("validation_report.json"),
                     "labeling": js("labeling_summary.json")})
    return caps


def column_type(c):
    """Arrow type for columns that type inference cannot get right from the first block
    (text, booleans, mostly-null columns); None leaves the column to inference."""
    if c in STRING_COLS:
        return pa.string()
    if (c.startswith(("is_", "src_is_", "dst_is_")) or c.endswith("_port_wellknown")
            or c in ("truncated_start", "truncated_end", "recut_active_timeout")):
        return pa.bool_()
    if c.startswith(("splt_direction_", "splt_ps_")):
        return pa.int64()
    if c.startswith("splt_piat_ms_") or c.endswith(("_pps", "_bps", "_ratio_updown")):
        return pa.float64()
    return None


def read_dataset(path):
    """Read the labeled CSV; ambiguous columns get explicit types, the rest is inferred."""
    with open(path, newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    include = [h for h in header if h not in LIST_COLS]
    types = {c: t for c in include if (t := column_type(c)) is not None}
    tbl = pacsv.read_csv(
        path,
        read_options=pacsv.ReadOptions(block_size=1 << 26),
        convert_options=pacsv.ConvertOptions(column_types=types, include_columns=include,
                                             strings_can_be_null=False))
    return header, tbl


def column_audit(tbl):
    stats = []
    for name in tbl.column_names:
        col = tbl.column(name)
        distinct = pc.count_distinct(col, mode="all").as_py()
        stats.append({"name": name, "type": str(col.type), "nulls": col.null_count,
                      "distinct": distinct, "value": col[0].as_py() if distinct == 1 else None})
    return stats


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def build_report(release_dir):
    t0 = time.time()
    with open(os.path.join(release_dir, "build_summary.json"), encoding="utf-8") as fh:
        build = json.load(fh)
    flows_name, labeled_name = build["flows_csv"], build["labeled_csv"]
    flows_path = os.path.join(release_dir, flows_name)
    labeled_path = os.path.join(release_dir, labeled_name)
    caps = load_inputs(release_dir, build)
    cap_ids = [c["id"] for c in caps]

    print(f"Reading {labeled_path}")
    header, tbl = read_dataset(labeled_path)
    audit = column_audit(tbl)
    df = tbl.select(ANALYSIS_COLS).to_pandas()
    del tbl
    print(f"  {len(df):,} rows loaded ({time.time() - t0:.0f}s)")

    df[CAPTURE_COL] = df[CAPTURE_COL].astype("category")
    df[LABEL_COL] = df[LABEL_COL].astype("category")
    df["attack"] = df[LABEL_COL] != BENIGN_LABEL
    df["dur_ms"] = df["bidirectional_last_seen_ms"] - df["bidirectional_first_seen_ms"]
    N = len(df)
    att = df[df.attack]
    ben = df[~df.attack]
    NA, NB = len(att), len(ben)
    tot_pkts, tot_bytes = int(df.bidirectional_packets.sum()), int(df.bidirectional_bytes.sum())

    records = [r for c in caps for r in c["records"]]
    attacker_ip = {r["src_ip"]: r["attacker_id"] for r in records}
    target_platforms = defaultdict(set)
    for r in records:
        pre = r["attack_name"].split("-", 1)[0]
        target_platforms[r["dst_ip"]]  # every logged target, even if only scanned
        if pre in PLATFORMS:
            target_platforms[r["dst_ip"]].add(PLATFORMS[pre])

    def role(ip):
        if ip in attacker_ip:
            return "attacker"
        if ip in target_platforms:
            return "target"
        return "other"

    ips = pd.unique(pd.concat([df.src_ip, df.dst_ip], ignore_index=True))
    roles = {ip: role(ip) for ip in ips}
    df["src_role"] = df.src_ip.map(roles)
    df["dst_role"] = df.dst_ip.map(roles)
    t2a = df[(df.src_role == "target") & (df.dst_role == "attacker")]
    a2t_benign = df[(df.src_role == "attacker") & (df.dst_role == "target") & ~df.attack]

    def port_list(s, k=4):
        return ", ".join(f"{int(p)} ({fint(n)})" for p, n in s.value_counts().head(k).items())

    label_counts = df[LABEL_COL].value_counts()
    label_counts = label_counts[label_counts > 0]
    attack_labels = [l for l in label_counts.index if l != BENIGN_LABEL]
    per_cap_label = df.groupby([LABEL_COL, CAPTURE_COL], observed=True).size().unstack(fill_value=0)
    md = []
    add = md.append

    # ----------------------------------------------------------------------- #
    add(f"# {build['name']} — Statistics")
    add("")
    add(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by "
        f"`analyze_dataset.py` from `{labeled_name}` (dataset built "
        f"{build['generated_utc'][:16].replace('T', ' ')} UTC). Every number below is computed "
        "from the data and its provenance files. Times are UTC. Percentages are of all flows "
        "unless a column says otherwise.")
    add("")
    sections = ["At a glance", "Captures", "Labels and class balance", "Traffic profile per class",
                "Attack records, attackers and targets", "Flow characteristics",
                "Protocols and applications", "Ports", "Hosts and network", "Time",
                "Data quality and integrity", "Features (columns)", "Provenance and configuration"]
    add("**Contents:** " + " · ".join(
        f"[{i}. {s}](#{i}-{s.lower().replace(' ', '-').replace(',', '').replace('(', '').replace(')', '')})"
        for i, s in enumerate(sections, 1)))
    add("")

    # 1. At a glance --------------------------------------------------------- #
    span = {c["id"]: c["validation"]["capture_window_utc"] for c in caps}
    span_ms = {cid: iso_ms(v["last_packet"].replace(" ", "T")) - iso_ms(v["first_packet"].replace(" ", "T"))
               for cid, v in span.items()}
    pcaps = sum(len(c["manifest"]) for c in caps)
    pcap_bytes = sum(int(r["size_bytes"]) for c in caps for r in c["manifest"])
    frames = sum(c["validation"]["packets"]["pcap_scan_total"] for c in caps)
    add("## 1. At a glance")
    add("")
    add(table(["Metric", "Value"], [
        ["Flows (rows)", fint(N)],
        ["Attack flows", f"{fint(NA)} ({fpct(NA, N)})"],
        ["Benign flows", f"{fint(NB)} ({fpct(NB, N)})"],
        ["Classes", f"{len(label_counts)} ({len(attack_labels)} attack classes + {BENIGN_LABEL})"],
        ["Captures", f"{len(caps)} ({', '.join(cap_ids)})"],
        ["Traffic time covered", f"{sum(span_ms.values()) / 86_400_000:.2f} days ("
         + ", ".join(f"{cid}: {fdays(v)}" for cid, v in span_ms.items()) + ")"],
        ["Packets in flows", f"{fint(tot_pkts)} ({fpct(att.bidirectional_packets.sum(), tot_pkts)} in attack flows)"],
        ["Bytes in flows (L2 frames)", f"{fbytes(tot_bytes)} ({fpct(att.bidirectional_bytes.sum(), tot_bytes)} in attack flows)"],
        ["Unique IP addresses", fint(len(ips))],
        ["Attackers (source IPs)", fint(len(attacker_ip))],
        ["Target hosts", fint(len(target_platforms))],
        ["Logged attack records (attacklog)", f"{fint(len(records))} ("
         + ", ".join(f"{c['id']}: {len(c['records'])}" for c in caps) + ")"],
        ["Raw capture", f"{fint(pcaps)} pcap files, {fbytes(pcap_bytes)}, {fint(frames)} frames"],
        ["Columns", f"{len(header) - 2} flow columns + `{CAPTURE_COL}` + `{LABEL_COL}` = {len(header)}"],
        ["Files", f"`{flows_name}` {fbytes(os.path.getsize(flows_path))}, "
         f"`{labeled_name}` {fbytes(os.path.getsize(labeled_path))}"],
    ], "ll"))
    add("")

    # 2. Captures ------------------------------------------------------------ #
    add("## 2. Captures")
    add("")
    rows = []
    g = df.groupby(CAPTURE_COL, observed=True)
    cap_flows = g.size()
    cap_att = g.attack.sum()
    cap_pkts = g.bidirectional_packets.sum()
    cap_bytes = g.bidirectional_bytes.sum()
    cap_att_pkts = att.groupby(CAPTURE_COL, observed=True).bidirectional_packets.sum()
    cap_att_bytes = att.groupby(CAPTURE_COL, observed=True).bidirectional_bytes.sum()
    cap_classes = att.groupby(CAPTURE_COL, observed=True)[LABEL_COL].nunique()
    cap_ips = {cid: len(pd.unique(pd.concat([sub.src_ip, sub.dst_ip]))) for cid, sub in g}
    cap_stitched = g.n_fragments.apply(lambda s: int((s > 1).sum()))
    cap_trunc = g.apply(lambda s: int((s.truncated_start | s.truncated_end).sum()), include_groups=False)

    def per_cap(fn, total=None):
        vals = [fn(c) for c in caps]
        return vals + [total if total is not None else ""]

    def ip_pkts(c):
        return c["validation"]["packets"]["flow_packets_total"]

    metrics = [
        ("Traffic window start", per_cap(lambda c: span[c["id"]]["first_packet"][:16])),
        ("Traffic window end", per_cap(lambda c: span[c["id"]]["last_packet"][:16])),
        ("Duration", per_cap(lambda c: fdays(span_ms[c["id"]]), fdays(sum(span_ms.values())))),
        ("Pcap files (10-min rotation)", per_cap(lambda c: fint(len(c["manifest"])), fint(pcaps))),
        ("Pcap size", per_cap(lambda c: fbytes(sum(int(r["size_bytes"]) for r in c["manifest"])), fbytes(pcap_bytes))),
        ("Frames captured", per_cap(lambda c: fint(c["validation"]["packets"]["pcap_scan_total"]), fint(frames))),
        ("IP packets in flows", per_cap(lambda c: fint(ip_pkts(c)), fint(sum(ip_pkts(c) for c in caps)))),
        ("Frames in no flow (non-IP L2: STP, ARP, …)", per_cap(
            lambda c: f"{fint(c['validation']['packets']['delta_unaccounted'])} ({c['validation']['packets']['delta_pct']:.2f}%)",
            fint(sum(c["validation"]["packets"]["delta_unaccounted"] for c in caps)))),
        ("Flows", per_cap(lambda c: fint(cap_flows[c["id"]]), fint(N))),
        ("Share of dataset", per_cap(lambda c: fpct(cap_flows[c["id"]], N), "100%")),
        ("Attack flows", per_cap(lambda c: f"{fint(cap_att[c['id']])} ({fpct(cap_att[c['id']], cap_flows[c['id']])})",
                                 f"{fint(NA)} ({fpct(NA, N)})")),
        ("Benign flows", per_cap(lambda c: f"{fint(cap_flows[c['id']] - cap_att[c['id']])} "
                                           f"({fpct(cap_flows[c['id']] - cap_att[c['id']], cap_flows[c['id']])})",
                                 f"{fint(NB)} ({fpct(NB, N)})")),
        ("Packets in flows", per_cap(lambda c: fint(cap_pkts[c["id"]]), fint(tot_pkts))),
        ("…of which in attack flows", per_cap(lambda c: fpct(cap_att_pkts.get(c["id"], 0), cap_pkts[c["id"]]),
                                              fpct(att.bidirectional_packets.sum(), tot_pkts))),
        ("Bytes in flows", per_cap(lambda c: fbytes(cap_bytes[c["id"]]), fbytes(tot_bytes))),
        ("…of which in attack flows", per_cap(lambda c: fpct(cap_att_bytes.get(c["id"], 0), cap_bytes[c["id"]]),
                                              fpct(att.bidirectional_bytes.sum(), tot_bytes))),
        ("Average flows per hour", per_cap(lambda c: fint(cap_flows[c["id"]] / (span_ms[c["id"]] / 3_600_000)),
                                           fint(N / (sum(span_ms.values()) / 3_600_000)))),
        ("Attackers", per_cap(lambda c: str(len({r["src_ip"] for r in c["records"]})), str(len(attacker_ip)))),
        ("Target hosts", per_cap(lambda c: str(len({r["dst_ip"] for r in c["records"]})), str(len(target_platforms)))),
        ("Logged attack records", per_cap(lambda c: fint(len(c["records"])), fint(len(records)))),
        ("Attack classes present", per_cap(lambda c: str(cap_classes.get(c["id"], 0)), str(len(attack_labels)))),
        ("Unique IP addresses", per_cap(lambda c: fint(cap_ips[c["id"]]), fint(len(ips)))),
        ("Stitched flows (split by file rotation, repaired)", per_cap(lambda c: fint(cap_stitched[c["id"]]),
                                                                      fint(int((df.n_fragments > 1).sum())))),
        ("Flows cut at capture edges", per_cap(lambda c: fint(cap_trunc[c["id"]]), fint(int(cap_trunc.sum())))),
    ]
    for name, vals in metrics:
        rows.append([name] + vals)
    add(table(["Metric"] + [f"Capture {c}" for c in cap_ids] + ["Total"], rows))
    add("")
    nf_cfgs = [c["run"]["extract_config"]["nfstream_config"] for c in caps]
    lab_cfgs = [(c["labeling"]["tolerance_ms"], c["labeling"]["tuple_fallback_enabled"]) for c in caps]
    vlan = next((a for a in audit if a["name"] == "vlan_id"), None)
    notes = []
    if vlan and vlan["distinct"] == 1:
        notes.append(f"All traffic was captured on a single VLAN (id {vlan['value']}).")
    notes.append("The captures were processed with "
                 + ("the identical" if all(c == nf_cfgs[0] for c in nf_cfgs) else "differing")
                 + " extraction and "
                 + ("identical" if all(c == lab_cfgs[0] for c in lab_cfgs) else "differing")
                 + " labeling settings (section 13).")
    notes.append("Frames in no flow are layer-2 frames without an IP header (spanning tree, ARP, …); "
                 "NFStream builds flows from IP packets only, so their share is highest in captures "
                 "with little IP traffic.")
    add(" ".join(notes))
    add("")

    # 3. Labels -------------------------------------------------------------- #
    add("## 3. Labels and class balance")
    add("")
    add("### 3.1 Attack vs benign")
    add("")
    rows = []
    for c in caps:
        cid = c["id"]
        sub = df[df[CAPTURE_COL] == cid]
        a = sub.attack.sum()
        rows.append([cid, fint(len(sub)), fint(a), fpct(a, len(sub)), fint(len(sub) - a),
                     fpct(len(sub) - a, len(sub)), f"1 : {(len(sub) - a) / a:.3f}" if a else "–"])
    rows.append(["**Total**", fint(N), fint(NA), fpct(NA, N), fint(NB), fpct(NB, N), f"1 : {NB / NA:.3f}"])
    add(table(["Capture", "Flows", "Attack", "Attack %", "Benign", "Benign %", "Attack : benign"], rows))
    add("")

    tech = df.assign(technique=df[LABEL_COL].astype(str).map(technique),
                     platform=df[LABEL_COL].astype(str).map(platform))
    add("### 3.2 By attack technique")
    add("")
    add("Technique is derived from the canonical attack name. `-portscan` classes are the "
        "single-port service scan each attacker ran right before the matching exploit.")
    add("")
    tg = tech.groupby("technique").agg(classes=(LABEL_COL, "nunique"), flows=(LABEL_COL, "size"),
                                       packets=("bidirectional_packets", "sum"),
                                       bytes=("bidirectional_bytes", "sum")).sort_values("flows", ascending=False)
    add(table(["Technique", "Classes", "Flows", "% of all", "% of attacks", "Packets", "Bytes"], [
        [t, r.classes, fint(r.flows), fpct(r.flows, N), "–" if t == "Benign" else fpct(r.flows, NA),
         fint(r.packets), fbytes(r.bytes)] for t, r in tg.iterrows()]))
    add("")
    add("### 3.3 By target platform")
    add("")
    pg = tech[tech.attack].groupby("platform").agg(classes=(LABEL_COL, "nunique"), flows=(LABEL_COL, "size"),
                                                   targets=("dst_ip", "nunique")).sort_values("flows", ascending=False)
    add(table(["Platform", "Attack classes", "Target hosts", "Flows", "% of attacks", "% excl. full port scan"], [
        [p, r.classes, r.targets, fint(r.flows), fpct(r.flows, NA),
         "–" if p == "All targets" else fpct(r.flows, NA - label_counts.get(FULL_SCAN, 0))]
        for p, r in pg.iterrows()]))
    add("")
    scan_targets = att.loc[att[LABEL_COL] == FULL_SCAN, "dst_ip"].nunique()
    add(f"`All targets` is the full-range port scan (`{FULL_SCAN}`), which covers every port; "
        f"it hit {scan_targets} of the {len(target_platforms)} logged targets.")
    add("")
    add("### 3.4 All classes")
    add("")
    rows = []
    for i, (lab, n) in enumerate(label_counts.items(), 1):
        rows.append([i, f"`{lab}`", technique(lab), platform(lab), fint(n), fpct(n, N),
                     "–" if lab == BENIGN_LABEL else fpct(n, NA)]
                    + [fint(per_cap_label.loc[lab].get(cid, 0)) if lab in per_cap_label.index else "0"
                       for cid in cap_ids])
    add(table(["#", "Label", "Technique", "Platform", "Flows", "% of all", "% of attacks"]
              + [f"in {cid}" for cid in cap_ids], rows, "rlll" + "r" * (3 + len(cap_ids))))
    add("")
    add("### 3.5 Class balance")
    add("")
    att_counts = label_counts.drop(BENIGN_LABEL, errors="ignore")

    def eff_classes(counts):
        p = counts / counts.sum()
        return math.exp(-(p * p.apply(math.log)).sum())

    bins = [(100_000, None), (10_000, 99_999), (1_000, 9_999), (100, 999), (10, 99), (1, 9)]
    rows = []
    for lo, hi in bins:
        sel = att_counts[(att_counts >= lo) & ((att_counts <= hi) if hi else True)]
        rows.append([f"≥ {fint(lo)}" if hi is None else f"{fint(lo)} – {fint(hi)}", len(sel),
                     fint(sel.sum()), fpct(sel.sum(), NA)])
    add(table(["Flows per attack class", "Classes", "Flows", "% of attacks"], rows))
    add("")
    rest = att_counts.drop(FULL_SCAN, errors="ignore")
    add(table(["Balance metric", "Value"], [
        ["Largest / smallest attack class", f"{fint(att_counts.max())} / {fint(att_counts.min())} "
                                            f"= {att_counts.max() / att_counts.min():,.0f}×"],
        ["Median attack class size", fint(att_counts.median())],
        [f"`{FULL_SCAN}` share of attack flows", fpct(att_counts.get(FULL_SCAN, 0), NA)],
        ["Effective number of attack classes (exp of Shannon entropy)",
         f"{eff_classes(att_counts):.2f} of {len(att_counts)}"],
        ["Effective number of classes incl. benign", f"{eff_classes(label_counts):.2f} of {len(label_counts)}"],
        [f"Attack flows excluding `{FULL_SCAN}`", f"{fint(rest.sum())} in {len(rest)} classes"],
        ["…largest of those", ", ".join(f"`{l}` {fpct(n, rest.sum())}" for l, n in rest.head(4).items())],
    ], "ll"))
    add("")
    add(f"The largest class, `{att_counts.index[0]}`, holds {fpct(att_counts.iloc[0], NA)} of attack "
        f"flows, while the median attack class has {fint(att_counts.median())} flows. Training on "
        "this dataset needs class weighting, re-sampling, or a per-class evaluation "
        "(macro-averaged metrics) so that a classifier is not judged by its majority classes alone.")
    add("")

    # 4. Traffic profile per class ------------------------------------------- #
    add("## 4. Traffic profile per class")
    add("")
    add("Per-flow medians show what a typical flow of each class looks like. *No reply* is the "
        "share of flows where the responder sent nothing back. *SYN-ACK* is the share of TCP "
        "flows where the responder accepted the connection.")
    add("")
    tcp = df.protocol == 6
    prof = df.assign(noreply=df.dst2src_packets == 0, tcp=tcp,
                     synack=tcp & (df.dst2src_syn_packets > 0)).groupby(LABEL_COL, observed=True).agg(
        flows=("flow_id", "size"), pk_med=("bidirectional_packets", "median"),
        by_med=("bidirectional_bytes", "median"), by_mean=("bidirectional_bytes", "mean"),
        du_med=("duration_s", "median"), du_p95=("duration_s", lambda s: s.quantile(0.95)),
        noreply=("noreply", "mean"), tcp=("tcp", "sum"), synack=("synack", "sum"))
    prof = prof.loc[label_counts.index]
    add(table(["Label", "Flows", "Median packets", "Median bytes", "Mean bytes", "Median duration (s)",
               "p95 duration (s)", "No reply", "SYN-ACK (TCP)"], [
        [f"`{l}`", fint(r.flows), fnum(r.pk_med, 0), fnum(r.by_med, 0), fnum(r.by_mean, 0),
         fnum(r.du_med, 3), fnum(r.du_p95, 3), f"{100 * r.noreply:.1f}%",
         f"{100 * r.synack / r.tcp:.1f}%" if r.tcp else "–"] for l, r in prof.iterrows()]))
    add("")

    # 5. Attack records ------------------------------------------------------ #
    add("## 5. Attack records, attackers and targets")
    add("")
    add("Attackers bracket every attack with `attacklog start` / `attacklog end`. Each record "
        "holds the attacker, target IP, target port(s), protocol, attack name, UTC start/end "
        "time and an outcome (`success`, `ran` = executed without exploiting, `error`).")
    add("")
    add("### 5.1 How the labels were assigned")
    add("")
    applied = build.get("relabels_applied", [])
    anon_info = build.get("anonymization")
    rows = []

    def lab_row(name, fn, total_fn=None):
        vals = [fn(c) for c in caps]
        rows.append([name] + [fint(v) if isinstance(v, (int, float)) else v for v in vals]
                    + [fint(sum(vals)) if total_fn is None else total_fn(vals)])

    st = {c["id"]: Counter(r["status"] for r in c["records"]) for c in caps}
    zero = {c["id"]: [m for m in c["labeling"]["per_record_matches"]
                      if m["flows_by_time"] + m["flows_by_fallback"] == 0] for c in caps}
    lab_row("Logged attack records", lambda c: len(c["records"]))
    for s in ("success", "ran", "error"):
        lab_row(f"…status `{s}`", lambda c, s=s: st[c["id"]].get(s, 0))
    lab_row("Records that matched no flow", lambda c: len(zero[c["id"]]))
    lab_row("Flows labeled by time window (±1 s)", lambda c: c["labeling"]["matched_by_time_window"])
    lab_row("Flows labeled by tuple fallback", lambda c: c["labeling"]["matched_by_tuple_fallback"])
    lab_row("Manual overrides → another attack", lambda c: sum(
        1 for a in applied if a["capture_id"] == c["id"] and a["new_label"] != BENIGN_LABEL))
    lab_row("Manual overrides → BENIGN", lambda c: sum(
        1 for a in applied if a["capture_id"] == c["id"] and a["new_label"] == BENIGN_LABEL))
    lab_row("Final attack flows", lambda c: int(cap_att[c["id"]]))
    lab_row("Final benign flows", lambda c: int(cap_flows[c["id"]] - cap_att[c["id"]]))
    add(table(["Step"] + [f"Capture {c}" for c in cap_ids] + ["Total"], rows))
    add("")
    add("A flow from an attacker IP is labeled when its src IP, dst IP, dst port and protocol "
        "match a record and its time overlaps the record's window. If the addresses and port "
        "match but no window does, the flow goes to the nearest window with the same addresses "
        "and port (tuple fallback). Everything else is BENIGN. The manual overrides "
        "(`relabel_overrides.csv`) correct reviewed fallback mistakes and are applied only in "
        "this unified dataset.")
    add("")
    add("### 5.2 Attackers")
    add("")
    att_by_src = att.groupby("src_ip").size()
    rows = []
    for c in caps:
        by = defaultdict(list)
        for r in c["records"]:
            by[(r["attacker_id"], r["src_ip"])].append(r)
        for (aid, ip), rs in sorted(by.items()):
            s = Counter(r["status"] for r in rs)
            t0_, t1_ = min(iso_ms(r["t_start"]) for r in rs), max(iso_ms(r["t_end"]) for r in rs if r["t_end"])
            rows.append([aid, ip, c["id"], len(rs), s.get("success", 0), s.get("ran", 0), s.get("error", 0),
                         len({r["dst_ip"] for r in rs}), len({r["attack_name"] for r in rs}),
                         fint(att_by_src.get(ip, 0)), fpct(att_by_src.get(ip, 0), NA),
                         len({r["t_start"][:10] for r in rs}), f"{fts(t0_)} → {fts(t1_)}"])
    add(table(["Attacker", "Source IP", "Capture", "Records", "success", "ran", "error", "Targets",
               "Attack names", "Attack flows", "% of attacks", "Active days", "First start → last end"],
              rows, "lllrrrrrrrrrl"))
    add("")
    add("### 5.3 Targets")
    add("")
    att_by_dst = att.groupby("dst_ip").size()
    cls_by_dst = att.groupby("dst_ip")[LABEL_COL].nunique()
    rows = []
    by_t = defaultdict(list)
    for r in records:
        by_t[r["dst_ip"]].append(r)
    for ip in sorted(by_t, key=lambda x: tuple(int(o) for o in x.split("."))):
        rs = by_t[ip]
        rows.append([ip, " / ".join(sorted(target_platforms[ip])) or "unknown (scan only)",
                     ", ".join(sorted({r["capture_id"] for r in rs})),
                     ", ".join(sorted({r["attacker_id"] for r in rs})), len(rs),
                     fint(att_by_dst.get(ip, 0)), cls_by_dst.get(ip, 0)])
    add(table(["Target IP", "Platform (from attack names)", "Capture", "Attacked by", "Records",
               "Attack flows", "Attack classes"], rows, "lllllrr"))
    add("")
    add("### 5.4 Logged records per class")
    add("")
    rec_by = defaultdict(list)
    for r in records:
        rec_by[r["attack_name"]].append(r)
    zero_by = Counter(m["attack_name"] for z in zero.values() for m in z)
    rows = []
    for name in sorted(rec_by, key=lambda n: (-label_counts.get(n, 0), n)):
        rs = rec_by[name]
        s = Counter(r["status"] for r in rs)
        rows.append([f"`{name}`", len(rs), s.get("success", 0), s.get("ran", 0), s.get("error", 0),
                     zero_by.get(name, 0), len({r["attacker_id"] for r in rs}),
                     len({r["dst_ip"] for r in rs}), fint(label_counts.get(name, 0))])
    add(details(f"{len(rec_by)} attack names, {len(records)} records", table(
        ["Attack name", "Records", "success", "ran", "error", "Records with no flow", "Attackers",
         "Targets", "Flows in dataset"], rows)))
    add("")
    add("### 5.5 Records that matched no flow")
    add("")
    add("These records produced no matching traffic. Typical causes are dry runs or sessions "
        "repeated later, attacks that failed before sending anything, records logged against "
        "the wrong target, and records logged while the attacker's clock was out of sync. The "
        "attackers' notes often tell which.")
    add("")
    rec_by_id = {r["attack_id"]: r for r in records}
    rows = []
    for cid, zs in zero.items():
        for m in sorted(zs, key=lambda m: m["t_start_ms"]):
            r = rec_by_id.get(m["attack_id"], {})
            rows.append([cid, m["attacker_id"], f"`{m['attack_name']}`", r.get("dst_ip", ""),
                         r.get("dst_port", ""), fts(m["t_start_ms"]), r.get("status", ""),
                         clean(r.get("notes") or "")])
    add(details(f"{len(rows)} records", table(
        ["Capture", "Attacker", "Attack name", "Target", "Port(s)", "Start", "Status", "Attacker's note"],
        rows, "llllllll")))
    add("")
    add("### 5.6 Known labeling limitations")
    add("")
    fallback = sum(c["labeling"]["matched_by_tuple_fallback"] for c in caps)
    a2t_proto = a2t_benign.protocol.value_counts()
    add(f"- **Tuple fallback.** {fint(fallback)} attack flows ({fpct(fallback, NA)} of attack "
        "flows) match a record's addresses and port but fall outside every logged time window, so "
        "their label comes from the nearest window. Typical causes are a scan the attacker repeated "
        "without logging it, or an attack record left open too long.")
    top_t2a = set(t2a.dst_port.value_counts().head(4).index)
    port_notes = {80: "Port 80 is typically a payload download from an attacker-run web server.",
                  4444: "Port 4444 is Metasploit's default reverse-shell listener."}
    add(f"- **Target → attacker traffic is BENIGN.** attacklog records attacker-initiated traffic "
        f"only, so the {fint(len(t2a))} flows from targets to attackers are labeled BENIGN although "
        f"they belong to attacks. Main attacker-side ports: {port_list(t2a.dst_port)}. "
        + " ".join(note for p, note in port_notes.items() if p in top_t2a))
    n_ov_benign = sum(1 for a in applied if a["new_label"] == BENIGN_LABEL)
    add(f"- **Benign attacker → target flows.** {fint(len(a2t_benign))} flows: "
        + ", ".join(f"{fint(n)} {PROTO_NAMES.get(int(p), p)}" for p, n in a2t_proto.items()) + "."
        + (" ICMP flows (typically host-discovery pings) never match, because attack records "
           "name TCP or UDP." if a2t_proto.get(1, 0) else "")
        + " The rest match no attack record"
        + (f" or were set to BENIGN by one of the {n_ov_benign} manual overrides." if n_ov_benign else "."))
    add(f"- **Records without traffic.** {sum(len(z) for z in zero.values())} of {len(records)} "
        "records matched no flow (section 5.5). Before treating such an attack as missing, check "
        "whether it was repeated and logged again later.")
    add("")

    # 6. Flow characteristics ------------------------------------------------ #
    add("## 6. Flow characteristics")
    add("")
    add("### 6.1 Distributions")
    add("")
    qs = [0.25, 0.5, 0.75, 0.95, 0.99]
    rows = []
    for metric, col, digits in (("Duration (s)", "duration_s", 3), ("Packets", "bidirectional_packets", 0),
                                ("Bytes", "bidirectional_bytes", 0)):
        for gname, sub in (("all", df), ("attack", att), ("benign", ben)):
            q = sub[col].quantile(qs)
            rows.append([metric, gname, fnum(sub[col].mean(), digits)] + [fnum(q[x], digits) for x in qs]
                        + [fnum(sub[col].max(), digits)])
    add(table(["Metric", "Flows", "Mean", "p25", "Median", "p75", "p95", "p99", "Max"], rows, "llrrrrrrr"))
    add("")
    add("### 6.2 Direction and TCP behaviour")
    add("")
    beh = tech.assign(noreply=tech.dst2src_packets == 0, tcp=tech.protocol == 6,
                      synack=(tech.protocol == 6) & (tech.dst2src_syn_packets > 0),
                      rst=(tech.protocol == 6) & (tech.dst2src_packets > 0) & (tech.dst2src_syn_packets == 0)
                      & (tech.dst2src_rst_packets > 0),
                      fin=(tech.protocol == 6) & (tech.bidirectional_fin_packets > 0),
                      single=tech.bidirectional_packets == 1)

    def beh_row(name, s):
        t = s.tcp.sum()
        return [name, fint(len(s)), fpct(s.single.sum(), len(s), 1), fpct(s.noreply.sum(), len(s), 1),
                fint(t), fpct(s.synack.sum(), t, 1), fpct(s.rst.sum(), t, 1), fpct(s.fin.sum(), t, 1)]

    rows = [beh_row("**All flows**", beh), beh_row("**Attack**", beh[beh.attack]),
            beh_row("**Benign**", beh[~beh.attack])]
    for t in tg.index:
        if t != "Benign":
            rows.append(beh_row(t, beh[beh.technique == t]))
    add(table(["Group", "Flows", "Single-packet", "No reply", "TCP flows", "TCP SYN-ACK",
               "TCP rejected (RST)", "TCP with FIN"], rows))
    add("")
    note = "*TCP rejected* = the responder answered only with RST (closed port)."
    scan = beh[(beh[LABEL_COL] == FULL_SCAN) & beh.tcp]
    if len(scan):
        note += (f" For `{FULL_SCAN}`, {fpct(scan.rst.sum(), len(scan))} of the TCP probes were "
                 f"rejected and {fpct(scan.synack.sum(), len(scan))} accepted (open ports).")
    add(note)
    add("")

    # 7. Protocols and applications ------------------------------------------ #
    add("## 7. Protocols and applications")
    add("")
    add("### 7.1 Transport protocol")
    add("")
    pr = df.groupby("protocol").agg(flows=("attack", "size"), attack=("attack", "sum"),
                                    pkts=("bidirectional_packets", "sum"),
                                    bytes=("bidirectional_bytes", "sum")).sort_values("flows", ascending=False)
    add(table(["Protocol", "Flows", "% of all", "Attack flows", "Benign flows", "Attack share", "Packets", "Bytes"], [
        [f"{PROTO_NAMES.get(int(p), 'other')} ({int(p)})", fint(r.flows), fpct(r.flows, N), fint(r.attack),
         fint(r.flows - r.attack), fpct(r.attack, r.flows), fint(r.pkts), fbytes(r.bytes)]
        for p, r in pr.iterrows()]))
    add("")
    v = df.ip_version.value_counts()
    add("IP version: " + ", ".join(f"IPv{int(k)} {fint(n)} ({fpct(n, N)})" for k, n in v.items()) + ".")
    add("")
    add("### 7.2 Applications (nDPI)")
    add("")

    def app_table(sub, total, k):
        vc = sub.application_name.replace("", "(empty)").value_counts().head(k)
        a = sub[sub.attack].application_name.value_counts()
        return table(["Application", "Flows", "% of group", "Attack flows", "Benign flows"], [
            [app, fint(n), fpct(n, total), fint(a.get(app, 0)), fint(n - a.get(app, 0))] for app, n in vc.items()])

    add("Top 15 over all flows:")
    add("")
    add(app_table(df, N, 15))
    add("")
    add("Top 10 among attack flows and among benign flows:")
    add("")
    aa = att.application_name.value_counts().head(10)
    bb = ben.application_name.value_counts().head(10)
    rows = []
    for i in range(max(len(aa), len(bb))):
        rows.append([i + 1] + ([aa.index[i], fint(aa.iloc[i]), fpct(aa.iloc[i], NA)] if i < len(aa) else ["", "", ""])
                    + ([bb.index[i], fint(bb.iloc[i]), fpct(bb.iloc[i], NB)] if i < len(bb) else ["", "", ""]))
    add(table(["#", "Attack: application", "Flows", "% of attacks", "Benign: application", "Flows", "% of benign"],
              rows, "rlrrlrr"))
    add("")
    cat = df.application_category_name.value_counts().head(10)
    add("Top application categories: " + ", ".join(f"{c} {fpct(n, N)}" for c, n in cat.items()) + ".")
    add("")
    unk = int((df.application_name == "Unknown").sum())
    guessed = int((df.application_is_guessed == 1).sum())
    odd = att[~att.application_name.isin(["Unknown", "HTTP", "FTP_CONTROL", "TLS"])]
    short_unk = int(((df.application_name == "Unknown") & (df.bidirectional_packets <= 2)).sum())
    text = (f"nDPI could not identify the application for {fint(unk)} flows ({fpct(unk, N)}); "
            f"{fint(short_unk)} of them ({fpct(short_unk, unk)}) have at most 2 packets, i.e. no "
            f"payload to classify. {fint(guessed)} flows ({fpct(guessed, N)}) carry a guessed "
            "application.")
    if len(odd):
        text += (f" Of the {fint(len(odd))} attack flows with another application name (most common: "
                 + ", ".join(odd.application_name.value_counts().head(3).index) + "), "
                 f"{fint((odd.application_is_guessed == 1).sum())} are flagged `application_is_guessed` "
                 f"(inferred from the port) and {fint((odd[LABEL_COL] == FULL_SCAN).sum())} are "
                 f"`{FULL_SCAN}` probes.")
    add(text)
    add("")
    add("### 7.3 Application metadata availability")
    add("")
    rows = []
    for col in NDPI_TEXT:
        has = df[col] != ""
        rows.append([f"`{col}`", fint(has.sum()), fpct(has.sum(), N), fint((has & df.attack).sum()),
                     fint((has & ~df.attack).sum())])
    add(table(["Field", "Flows with a value", "% of all", "Attack", "Benign"], rows))
    add("")

    # 8. Ports --------------------------------------------------------------- #
    add("## 8. Ports")
    add("")
    targeted = att[att[LABEL_COL] != FULL_SCAN]
    add(f"Distinct destination ports: {fint(df.dst_port.nunique())} over all flows, "
        f"{fint(att.dst_port.nunique())} in attack flows "
        f"({fint(targeted.dst_port.nunique())} excluding `{FULL_SCAN}`), "
        f"{fint(ben.dst_port.nunique())} in benign flows.")
    add("")
    add(f"### 8.1 Destination ports of attack flows (excluding `{FULL_SCAN}`)")
    add("")
    vc = targeted.dst_port.value_counts().head(15)
    rows = []
    for port, n in vc.items():
        labs = targeted[targeted.dst_port == port][LABEL_COL].value_counts()
        labs = labs[labs > 0].head(3)
        rows.append([int(port), fint(n), fpct(n, len(targeted)),
                     ", ".join(f"`{l}` ({fint(c)})" for l, c in labs.items())])
    add(table(["Port", "Flows", "% of targeted attack flows", "Main classes"], rows, "rrrl"))
    add("")
    add("### 8.2 Service ports of benign flows")
    add("")
    vc = ben.service_port.value_counts().head(15)
    rows = []
    for port, n in vc.items():
        apps = ben[ben.service_port == port].application_name.value_counts().head(2)
        rows.append([int(port), fint(n), fpct(n, NB), ", ".join(f"{a} ({fpct(c, n, 0)})" for a, c in apps.items())])
    add(table(["Service port", "Flows", "% of benign", "Main applications"], rows, "rrrl"))
    add("")
    add("`service_port` is the well-known side of the flow (the lower port if neither or both are below 1024).")
    add("")

    # 9. Hosts and network --------------------------------------------------- #
    add("## 9. Hosts and network")
    add("")
    uniq_src, uniq_dst = df.src_ip.nunique(), df.dst_ip.nunique()
    v6 = sum(1 for ip in ips if ":" in ip)
    both_priv = int((df.src_is_private & df.dst_is_private).sum())
    add(table(["Metric", "Value"], [
        ["Unique source IPs", fint(uniq_src)], ["Unique destination IPs", fint(uniq_dst)],
        ["Unique IPs overall", f"{fint(len(ips))} ({fint(len(ips) - v6)} IPv4, {fint(v6)} IPv6)"],
        ["Flows between two private (RFC 1918 / ULA) addresses", f"{fint(both_priv)} ({fpct(both_priv, N)})"],
        ["Flows with a public or multicast endpoint", f"{fint(N - both_priv)} ({fpct(N - both_priv, N)})"],
        ["Flows to a multicast address", f"{fint(df.dst_is_multicast.sum())} ({fpct(df.dst_is_multicast.sum(), N)})"],
        ["Flows to the limited broadcast address", fint(df.dst_is_broadcast.sum())],
    ] + ([["Public IPs pseudonymized (documentation ranges)",
           f"{anon_info['public_ips_pseudonymized']} addresses in {fint(anon_info['flows_changed'])} flows; "
           f"kept unchanged: {', '.join(anon_info['public_ips_kept']) or 'none'}"]] if anon_info else []), "ll"))
    add("")
    add("### 9.1 Flows by host role")
    add("")
    add("Roles come from the attack logs: *attacker* = an attacker's source IP, *target* = a "
        "logged target, *other* = everything else (gateway, infrastructure, other lab hosts).")
    add("")
    rp = df.groupby(["src_role", "dst_role"]).agg(
        flows=("attack", "size"), attack=("attack", "sum"), bytes=("bidirectional_bytes", "sum")
    ).sort_values("flows", ascending=False)
    svc = df.groupby(["src_role", "dst_role", "application_name", "dst_port"]).size()
    rows = []
    for (s, d), r in rp.iterrows():
        top = svc.loc[(s, d)].sort_values(ascending=False).head(3)
        rows.append([s, d, fint(r.flows), fpct(r.flows, N), fint(r.attack), fint(r.flows - r.attack),
                     fbytes(r.bytes), ", ".join(f"{a}:{int(p)} {fpct(n, r.flows)}" for (a, p), n in top.items())])
    add(table(["Source role", "Destination role", "Flows", "% of all", "Attack", "Benign", "Bytes",
               "Main services (application:dst port)"], rows, "llrrrrrl"))
    add("")
    add("Attack labels are assigned only to flows that start at an attacker host, so attack traffic "
        "appears as attacker → target. Traffic between targets and other hosts is background "
        "activity, and its main services are listed in the table. "
        "Section 5.6 explains the target → attacker flows and the benign attacker → target flows.")
    add("")
    add("### 9.2 Top hosts by flow count")
    add("")
    sc, dc = df.src_ip.value_counts(), df.dst_ip.value_counts()
    sb = df.groupby("src_ip").bidirectional_bytes.sum()
    db = df.groupby("dst_ip").bidirectional_bytes.sum()
    tot = sc.add(dc, fill_value=0).sort_values(ascending=False).head(15)
    rows = []
    for ip, n in tot.items():
        r_ = roles.get(ip, "other")
        name = attacker_ip.get(ip, "") if r_ == "attacker" else " / ".join(sorted(target_platforms.get(ip, [])))
        rows.append([ip, r_ + (f" ({name})" if name else ""), fint(sc.get(ip, 0)), fint(dc.get(ip, 0)),
                     fint(n), fbytes(sb.get(ip, 0) + db.get(ip, 0))])
    add(table(["Host", "Role", "Flows as source", "Flows as destination", "Total flows", "Bytes"], rows, "llrrrr"))
    add("")
    add("### 9.3 Subnet pairs")
    add("")
    subnet = {ip: ("IPv6" if ":" in ip else ip.rsplit(".", 1)[0] + ".0/24") for ip in ips}
    sp = df.assign(ss=df.src_ip.map(subnet), ds=df.dst_ip.map(subnet)).groupby(["ss", "ds"]).agg(
        flows=("attack", "size"), attack=("attack", "sum")).sort_values("flows", ascending=False).head(15)
    add(table(["Source subnet", "Destination subnet", "Flows", "% of all", "Attack", "Benign"], [
        [s, d, fint(r.flows), fpct(r.flows, N), fint(r.attack), fint(r.flows - r.attack)]
        for (s, d), r in sp.iterrows()], "llrrrr"))
    add("")

    # 10. Time --------------------------------------------------------------- #
    add("## 10. Time")
    add("")
    add("### 10.1 Flows per day")
    add("")
    day = df.groupby(["start_date", CAPTURE_COL], observed=True).agg(flows=("attack", "size"), attack=("attack", "sum"))
    top_day = att.groupby(["start_date", LABEL_COL], observed=True).size()
    rows = []
    for (d, cid), r in day.iterrows():
        top = ""
        if r.attack:
            s = top_day.loc[d]
            s = s[s > 0].sort_values(ascending=False)
            top = ", ".join(f"`{l}` ({fint(c)})" for l, c in s.head(2).items())
        rows.append([d, cid, fint(r.flows), fint(r.attack), fint(r.flows - r.attack), fpct(r.attack, r.flows), top])
    add(table(["Date (flow start)", "Capture", "Flows", "Attack", "Benign", "Attack %", "Main attack classes"],
              rows, "llrrrrl"))
    add("")
    add("### 10.2 Hour of day")
    add("")
    hr = df.groupby("start_hour").agg(flows=("attack", "size"), attack=("attack", "sum"))
    add(details("Flows by hour of day (UTC)", table(["Hour (UTC)", "Flows", "Attack", "Benign", "Attack %"], [
        [f"{int(h):02d}:00", fint(r.flows), fint(r.attack), fint(r.flows - r.attack), fpct(r.attack, r.flows)]
        for h, r in hr.iterrows()])))
    add("")
    add("### 10.3 Class timeline")
    add("")
    tl = att.groupby(LABEL_COL, observed=True).agg(first=("bidirectional_first_seen_ms", "min"),
                                                   last=("bidirectional_last_seen_ms", "max"),
                                                   caps=(CAPTURE_COL, lambda s: ", ".join(sorted(s.astype(str).unique()))),
                                                   days=("start_date", "nunique"))
    tl = tl.sort_values("first")
    add(details(f"First and last flow of each of the {len(tl)} attack classes", table(
        ["Label", "Capture(s)", "First flow", "Last flow", "Days with flows"], [
            [f"`{l}`", r.caps, fts(r["first"]), fts(r["last"]), r.days] for l, r in tl.iterrows()], "lllll")))
    add("")

    # 11. Data quality ------------------------------------------------------- #
    add("## 11. Data quality and integrity")
    add("")
    dup_ids = N - df.flow_id.nunique()
    imp = defaultdict(int)
    for c in caps:
        for k, v_ in c["validation"]["impossible_values"].items():
            imp[k] += v_
    rows = [
        ["Duplicate `flow_id`", fint(dup_ids)],
        ["Duplicate (canonical key, first-seen) rows", fint(sum(c["validation"]["duplicates"]["duplicate_key_plus_first_seen_rows"] for c in caps))],
        ["Failed pcap files during extraction", fint(sum(len(c["validation"]["files"]["failed_files"]) for c in caps))],
        ["Packets lost while stitching fragments into flows",
         fint(sum(c["validation"]["packets"]["dataset_vs_fragments_delta"] for c in caps))],
    ] + [[f"Impossible values: {k.replace('_', ' ')}", fint(v_)] for k, v_ in imp.items()] + [
        ["Stitched flows (repaired across 10-min file boundaries)",
         f"{fint((df.n_fragments > 1).sum())} (max {int(df.n_fragments.max())} fragments)"],
        ["Flows re-cut at the active timeout", fint(df.recut_active_timeout.sum())],
        ["Flows possibly cut at the start / end of a capture",
         f"{fint(df.truncated_start.sum())} / {fint(df.truncated_end.sum())}"],
        ["Negative or zero durations", f"{fint((df.dur_ms < 0).sum())} negative, "
                                       f"{fint((df.dur_ms == 0).sum())} zero (single-packet or same-millisecond flows)"],
    ]
    add(table(["Check", "Result"], rows, "ll"))
    add("")
    gaps = [(c["id"], g_) for c in caps for g_ in c["validation"]["capture_gaps_over_30s"]]
    add("Capture gaps longer than 30 s between consecutive packets across pcap files: "
        + ("none." if not gaps else "; ".join(
            f"capture {cid} after {fts(g_['after_ts'] * 1000)} ({g_['gap_seconds']} s)" for cid, g_ in gaps)
           + ". All gaps are shorter than the 120 s idle timeout, so flows were still stitched across them."))
    add("")
    add("### 11.1 Missing values")
    add("")
    nulls = [a for a in audit if a["nulls"] > 0]
    splt = [a for a in nulls if a["name"].startswith("splt_")]
    other = [a for a in nulls if not a["name"].startswith("splt_")]
    rows = [[f"`{a['name']}`", fint(a["nulls"]), fpct(a["nulls"], N)] for a in other]
    if splt:
        lo = min(splt, key=lambda a: a["nulls"])
        hi = max(splt, key=lambda a: a["nulls"])
        rows.append([f"`splt_*_i` ({len(splt)} columns)", f"{fint(lo['nulls'])} – {fint(hi['nulls'])}",
                     f"{fpct(lo['nulls'], N)} – {fpct(hi['nulls'], N)}"])
    add(table(["Column", "Null values", "% of rows"], rows))
    add("")
    add("Nulls are structural, not data loss. `splt_*_i` is empty when the flow has ≤ i packets. "
        "Rates (`*_pps`, `*_bps`) are empty when the duration is 0 ms. Ratios are empty when the "
        "reverse direction carried nothing. Text metadata columns use the empty string instead "
        "of null (section 7.3).")
    add("")

    # 12. Features ----------------------------------------------------------- #
    add("## 12. Features (columns)")
    add("")
    groups = defaultdict(list)
    for c in header:
        groups[col_group(c)].append(c)
    add(table(["Column group", "Columns", "Examples"], [
        [gname, len(cols), ", ".join(f"`{c}`" for c in cols[:4]) + (", …" if len(cols) > 4 else "")]
        for gname, cols in sorted(groups.items(), key=lambda kv: -len(kv[1]))], "lrl"))
    add("")
    add(f"The three list columns `{'`, `'.join(LIST_COLS)}` hold the same SPLT values as the flat "
        "`splt_*_0..19` columns, serialized as JSON arrays. The full meaning, unit and type of "
        "every column is in `flow-extraction/DATA_DICTIONARY.md`.")
    add("")
    const = [a for a in audit if a["distinct"] == 1]
    add("### 12.1 Constant columns")
    add("")
    add("These columns hold a single value across the whole dataset and carry no information "
        "for a model:")
    add("")
    add(table(["Column", "Value"], [[f"`{a['name']}`", "null" if a["value"] is None else repr(a["value"])]
                                    for a in const], "ll") if const else "None.")
    add("")
    add("### 12.2 Identifying columns")
    add("")
    add("These columns identify the flow, host, capture or absolute time rather than describe "
        "behaviour. A model trained on them learns the lab setup (e.g. which IPs were attackers, "
        "or when attacks happened) instead of attack traffic. Exclude them from model inputs "
        "unless that is intended. Keep them for joins, splits and error analysis.")
    add("")
    add(", ".join(f"`{c}`" for c in IDENTIFYING if c in header)
        + ", plus the absolute timestamps `*_first_seen_ms` / `*_last_seen_ms`. "
          "Ports (`src_port`, `dst_port`, `service_port`) are legitimate features, but the "
          "attacker's ephemeral source port is effectively random.")
    add("")

    # 13. Provenance --------------------------------------------------------- #
    add("## 13. Provenance and configuration")
    add("")
    rows = []

    def prov(name, fn):
        vals = [str(fn(c)) for c in caps]
        rows.append([name] + vals)

    prov("Extraction run (UTC)", lambda c: c["run"]["run_utc"][:16].replace("T", " "))
    for k, v_ in caps[0]["run"]["tool_versions"].items():
        prov(f"{k} version", lambda c, k=k: c["run"]["tool_versions"].get(k))
    for k in caps[0]["run"]["extract_config"]["nfstream_config"]:
        prov(f"NFStream `{k}`", lambda c, k=k: c["run"]["extract_config"]["nfstream_config"].get(k))
    prov("Byte accounting", lambda c: c["run"]["accounting_mode_meaning"])
    prov("Stddev convention", lambda c: c["run"]["stddev_convention"])
    prov("Labeling time tolerance", lambda c: f"±{c['labeling']['tolerance_ms']} ms")
    prov("Tuple fallback", lambda c: c["labeling"]["tuple_fallback_enabled"])
    prov("Benign label", lambda c: c["labeling"]["benign_label"])
    prov("Attack logs", lambda c: ", ".join(c["attacklog_files"]))
    prov("Manual overrides (unified dataset only)",
         lambda c: sum(1 for a in applied if a["capture_id"] == c["id"]))
    add(table(["Setting"] + [f"Capture {c}" for c in cap_ids], rows, "l" + "l" * len(cap_ids)))
    add("")
    if anon_info:
        add(f"Anonymization (release only): {anon_info['method']}. "
            f"{anon_info['public_ips_pseudonymized']} public addresses pseudonymized; kept unchanged: "
            f"{', '.join(anon_info['public_ips_kept']) or 'none'}.")
        add("")
    add("Pipeline: `flow-extraction` (NFStream per pcap → stitching across file boundaries → "
        "derived columns → validation → CSV), then `flow-labeling/label_flows.py`, then "
        "`dataset-unification/build_dataset.py` (unifies the captures and applies the overrides), "
        "then `dataset-analysis/analyze_dataset.py` (writes this file).")
    add("")
    return "\n".join(md) + "\n", time.time() - t0


def main():
    ap = argparse.ArgumentParser(description=f"Write {REPORT_NAME} for a dataset release")
    ap.add_argument("release_dir", help="release directory written by build_dataset.py")
    ap.add_argument("--info-dir", help="also copy the report into this directory (e.g. dataset-info/)")
    args = ap.parse_args()
    report, elapsed = build_report(args.release_dir)
    path = os.path.join(args.release_dir, REPORT_NAME)
    with open(path + ".tmp", "w", encoding="utf-8") as fh:
        fh.write(report)
    os.replace(path + ".tmp", path)
    print(f"Wrote {path} ({len(report.splitlines())} lines, {elapsed:.0f}s)")
    if args.info_dir:
        os.makedirs(args.info_dir, exist_ok=True)
        shutil.copy2(path, os.path.join(args.info_dir, REPORT_NAME))
        print(f"Copied to {os.path.join(args.info_dir, REPORT_NAME)}")


if __name__ == "__main__":
    main()
