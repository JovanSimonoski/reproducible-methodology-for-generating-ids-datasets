#!/usr/bin/env python3
"""
build_dataset.py  -  Build a unified, documented flow dataset from several captures.

Inputs follow the standard data layout (see data/README.md); for every capture id
listed in the build config:

  <data_root>/processed/<id>/flows.csv            NFStream flow table (flow-extraction)
  <data_root>/processed/<id>/flows_labeled.csv    same rows + label (flow-labeling)
  <data_root>/processed/<id>/*.json               run metadata, validation, labeling summary
  <data_root>/interim/<id>/manifest.csv           per-pcap extraction manifest
  <data_root>/raw/<id>/attacklog/*.json           attacklog exports used for labeling

Output is a self-contained release directory, <data_root>/release/<name>/:

  <flows_name>      all flows of all captures             + capture_id
  <labeled_name>    same rows in the same order + capture_id + label (label stays last)
  README.md         copy of the dataset card named in the config
  build_summary.json
  provenance/<id>/  the capture's reports, manifest and attacklog exports
  provenance/relabel_overrides.csv

Manual label corrections (relabel_overrides.csv) are applied to the labeled output
only; the per-capture inputs are never modified. An override identifies one flow by
capture_id + src_ip + src_port + dst_ip + dst_port + protocol + first_seen_ms, which
stays stable when a capture is re-extracted (unlike flow_id).

If the config has an "anonymization" block, every public IP address (except those on
its keep list) is replaced by a persistent pseudonym from the documentation ranges, in
the CSVs and in the copied provenance (see anonymize.py). The per-capture inputs keep
the real addresses.

If the config names an info_dir, build_summary.json and the provenance reports
(without attacklog exports) are mirrored there, e.g. into the repository's
dataset-info/ so the dataset's metadata is versioned with the code.

Integrity checks (the build aborts instead of skipping anything):
  - all captures share one header; labeled header == flow header + ["label"]
  - row i of flows_labeled.csv equals row i of flows.csv plus a label
  - flow_id is unique across all captures
  - every override hits exactly one flow, and that flow's current label equals the
    override's old_label (protects against stale overrides after re-labeling upstream)

Pure standard library; no third-party dependencies.
"""

import argparse
import csv
import glob
import json
import os
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone

from anonymize import PublicIpAnonymizer

LABEL_COL = "label"
CAPTURE_COL = "capture_id"
BENIGN_LABEL = "BENIGN"
COL_FLOW_ID = "flow_id"
COL_FIRST = "bidirectional_first_seen_ms"
COL_LAST = "bidirectional_last_seen_ms"
KEY_COLS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", COL_FIRST)
ANON_COLS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "canonical_key",
             "requested_server_name")
OVERRIDE_KEY = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "first_seen_ms")
CAPTURE_REPORTS = ("run_metadata.json", "validation_report.json", "labeling_summary.json")


def resolve(path, base):
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base, path))


def utc(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()


def load_overrides(path):
    """(capture_id, *flow key) -> {old_label, new_label, reason}."""
    overrides = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for n, row in enumerate(csv.DictReader(fh), start=2):
            key = (row["capture_id"].strip(),) + tuple(row[c].strip() for c in OVERRIDE_KEY)
            if key in overrides:
                sys.exit(f"{path}:{n}: duplicate override for {key}")
            overrides[key] = {
                "old_label": row["old_label"].strip(),
                "new_label": row["new_label"].strip(),
                "reason": row["reason"].strip(),
            }
    return overrides


def copy_file(src, dest_dir, anon):
    """Copy a provenance file; with an anonymizer, rewrite IP addresses in JSON values
    and CSV cells on the way."""
    dest = os.path.join(dest_dir, os.path.basename(src))
    if anon is None:
        shutil.copy2(src, dest)
    elif src.endswith(".json"):
        with open(src, encoding="utf-8") as fh:
            data = anon.walk(json.load(fh))
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    else:
        with open(src, newline="", encoding="utf-8") as fin, \
             open(dest, "w", newline="", encoding="utf-8") as fout:
            w = csv.writer(fout)
            for row in csv.reader(fin):
                w.writerow([anon.ip(c) for c in row])


def copy_provenance(cid, data_root, dest, anon):
    """Copy one capture's reports, manifest and attacklog exports into dest."""
    os.makedirs(os.path.join(dest, "attacklog"), exist_ok=True)
    for name in CAPTURE_REPORTS:
        copy_file(os.path.join(data_root, "processed", cid, name), dest, anon)
    copy_file(os.path.join(data_root, "interim", cid, "manifest.csv"), dest, anon)
    logs = sorted(glob.glob(os.path.join(data_root, "raw", cid, "attacklog", "*.json")))
    if not logs:
        sys.exit(f"[{cid}] no attacklog exports in {os.path.join(data_root, 'raw', cid, 'attacklog')}")
    for f in logs:
        copy_file(f, os.path.join(dest, "attacklog"), anon)


def mirror_info(release_dir, info_dir, cids):
    """Mirror the small metadata files (no CSVs, no attacklog exports) into info_dir."""
    os.makedirs(info_dir, exist_ok=True)
    shutil.copy2(os.path.join(release_dir, "build_summary.json"), info_dir)
    for cid in cids:
        dest = os.path.join(info_dir, "provenance", cid)
        os.makedirs(dest, exist_ok=True)
        for name in CAPTURE_REPORTS + ("manifest.csv",):
            shutil.copy2(os.path.join(release_dir, "provenance", cid, name), dest)


def main():
    ap = argparse.ArgumentParser(description="Build a unified flow dataset release from processed captures")
    ap.add_argument("config", help="build config JSON (paths in it are relative to the config file)")
    args = ap.parse_args()

    cfg_dir = os.path.dirname(os.path.abspath(args.config))
    with open(args.config, encoding="utf-8") as fh:
        cfg = json.load(fh)
    data_root = resolve(cfg["data_root"], cfg_dir)
    cids = [str(c) for c in cfg["captures"]]
    if len(set(cids)) != len(cids):
        sys.exit(f"duplicate capture id in config: {cids}")
    release_dir = os.path.join(data_root, "release", cfg["name"])
    out_flows = os.path.join(release_dir, cfg.get("flows_name", "flows.csv"))
    out_labeled = os.path.join(release_dir, cfg.get("labeled_name", "flows_labeled.csv"))
    overrides_path = resolve(cfg["relabel_overrides"], cfg_dir) if cfg.get("relabel_overrides") else None
    overrides = load_overrides(overrides_path) if overrides_path else {}
    unknown = sorted({k[0] for k in overrides} - set(cids))
    if unknown:
        sys.exit(f"overrides reference captures not in config: {unknown}")
    anon_cfg = cfg.get("anonymization")
    anon = (PublicIpAnonymizer(resolve(anon_cfg["ip_map"], cfg_dir), anon_cfg.get("keep_public_ips", []))
            if anon_cfg else None)
    os.makedirs(release_dir, exist_ok=True)

    print(f"Release  : {release_dir}")
    print(f"Captures : {cids}")
    print(f"Overrides: {len(overrides)}" + (f" from {overrides_path}" if overrides_path else ""))
    print("Anonymize: " + (f"public IPs, mapping {anon.map_path} ({anon.loaded} known), "
                           f"keep {sorted(anon.keep)}" if anon else "no"))

    t0 = time.time()
    csv.field_size_limit(10 ** 9)
    header = None
    seen_ids = set()
    applied = []
    cap_stats = []
    total_labels = Counter()

    tmp_flows, tmp_labeled = out_flows + ".tmp", out_labeled + ".tmp"
    with open(tmp_flows, "w", newline="", encoding="utf-8") as f_out, \
         open(tmp_labeled, "w", newline="", encoding="utf-8") as l_out:
        w_flows, w_labeled = csv.writer(f_out), csv.writer(l_out)

        for cid in cids:
            proc = os.path.join(data_root, "processed", cid)
            flows_csv = os.path.join(proc, "flows.csv")
            labeled_csv = os.path.join(proc, "flows_labeled.csv")
            print(f"\n[{cid}] {proc}")
            labels = Counter()
            n = 0
            first_ms = last_ms = None

            with open(flows_csv, newline="", encoding="utf-8") as f_in, \
                 open(labeled_csv, newline="", encoding="utf-8") as l_in:
                r_flows, r_labeled = csv.reader(f_in), csv.reader(l_in)
                h_flows, h_labeled = next(r_flows), next(r_labeled)
                if h_labeled != h_flows + [LABEL_COL]:
                    sys.exit(f"[{cid}] labeled header is not flow header + '{LABEL_COL}'")
                if header is None:
                    header = h_flows
                    for name in (CAPTURE_COL, LABEL_COL):
                        if name in header:
                            sys.exit(f"input already has a '{name}' column")
                    w_flows.writerow(header + [CAPTURE_COL])
                    w_labeled.writerow(header + [CAPTURE_COL, LABEL_COL])
                    i_id = header.index(COL_FLOW_ID)
                    i_first, i_last = header.index(COL_FIRST), header.index(COL_LAST)
                    i_key = [header.index(c) for c in KEY_COLS]
                    anon_cols = {c: header.index(c) for c in ANON_COLS}
                elif h_flows != header:
                    sys.exit(f"[{cid}] header differs from the first capture's header")

                for row in r_flows:
                    lrow = next(r_labeled, None)
                    if lrow is None or lrow[:-1] != row:
                        sys.exit(f"[{cid}] flows/labeled CSVs diverge at data row {n + 1}")
                    n += 1
                    fid = row[i_id]
                    if fid in seen_ids:
                        sys.exit(f"[{cid}] duplicate flow_id {fid}")
                    seen_ids.add(fid)

                    label = lrow[-1]
                    if overrides:
                        key = (cid,) + tuple(row[i] for i in i_key)
                        ov = overrides.get(key)
                        if ov is not None:
                            if label != ov["old_label"]:
                                sys.exit(f"[{cid}] override {key}: expected label "
                                         f"'{ov['old_label']}', found '{label}'")
                            applied.append({"capture_id": cid, "flow_id": fid,
                                            **dict(zip(OVERRIDE_KEY, key[1:])), **ov})
                            label = ov["new_label"]

                    out = anon.flow_row(row, anon_cols) if anon else row
                    w_flows.writerow(out + [cid])
                    w_labeled.writerow(out + [cid, label])
                    labels[label] += 1
                    f_ms, l_ms = int(row[i_first]), int(row[i_last])
                    first_ms = f_ms if first_ms is None else min(first_ms, f_ms)
                    last_ms = l_ms if last_ms is None else max(last_ms, l_ms)
                    if n % 500000 == 0:
                        print(f"     ...{n:,} rows ({time.time() - t0:.0f}s)")

                if next(r_labeled, None) is not None:
                    sys.exit(f"[{cid}] labeled CSV has more rows than the flow CSV")

            print(f"     {n:,} rows, {n - labels[BENIGN_LABEL]:,} attack / "
                  f"{labels[BENIGN_LABEL]:,} {BENIGN_LABEL}")
            total_labels.update(labels)
            cap_stats.append({
                "capture_id": cid,
                "rows": n,
                "attack_rows": n - labels[BENIGN_LABEL],
                "benign_rows": labels[BENIGN_LABEL],
                "first_flow_utc": utc(first_ms) if n else None,
                "last_flow_utc": utc(last_ms) if n else None,
                "label_distribution": dict(labels.most_common()),
            })

    hits = Counter((a["capture_id"],) + tuple(a[c] for c in OVERRIDE_KEY) for a in applied)
    problems = [f"matched no flow: {k}" for k in overrides if hits[k] == 0]
    problems += [f"matched {c} flows: {k}" for k, c in hits.items() if c > 1]
    if problems:
        os.remove(tmp_flows)
        os.remove(tmp_labeled)
        sys.exit("invalid overrides:\n  " + "\n  ".join(problems))
    if anon:
        anon.save()  # before publishing outputs, so no pseudonym is ever lost
    os.replace(tmp_flows, out_flows)
    os.replace(tmp_labeled, out_labeled)

    for cid in cids:
        copy_provenance(cid, data_root, os.path.join(release_dir, "provenance", cid), anon)
    if overrides_path:
        copy_file(overrides_path, os.path.join(release_dir, "provenance"), anon)
        os.replace(os.path.join(release_dir, "provenance", os.path.basename(overrides_path)),
                   os.path.join(release_dir, "provenance", "relabel_overrides.csv"))
    if cfg.get("readme"):
        shutil.copy2(resolve(cfg["readme"], cfg_dir), os.path.join(release_dir, "README.md"))

    total = sum(c["rows"] for c in cap_stats)
    summary = {
        "name": cfg["name"],
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "builder": "dataset-unification/build_dataset.py",
        "flows_csv": os.path.basename(out_flows),
        "labeled_csv": os.path.basename(out_labeled),
        "columns_flows": len(header) + 1,
        "columns_labeled": len(header) + 2,
        "total_rows": total,
        "attack_rows": total - total_labels[BENIGN_LABEL],
        "benign_rows": total_labels[BENIGN_LABEL],
        "label_distribution": dict(total_labels.most_common()),
        "captures": cap_stats,
        "relabels_applied": anon.walk(applied) if anon else applied,
        "anonymization": anon.summary() if anon else None,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    with open(os.path.join(release_dir, "build_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    if cfg.get("info_dir"):
        mirror_info(release_dir, resolve(cfg["info_dir"], cfg_dir), cids)

    print(f"\nDone. {total:,} rows from {len(cap_stats)} captures in {summary['elapsed_seconds']:.0f}s")
    print(f"  attack : {summary['attack_rows']:,}\n  {BENIGN_LABEL} : {summary['benign_rows']:,}")
    if anon:
        a = summary["anonymization"]
        print(f"  public IPs pseudonymized: {a['public_ips_pseudonymized']} "
              f"({a['new_mappings_this_build']} new), kept: {a['public_ips_kept']}, "
              f"flows changed: {a['flows_changed']:,}")
    print(f"  relabels applied: {len(applied)}")
    for a in applied:
        print(f"    [{a['capture_id']}] {a['src_ip']}:{a['src_port']} -> {a['dst_ip']}:{a['dst_port']} "
              f"@{a['first_seen_ms']}  {a['old_label']} -> {a['new_label']}")
    print(f"Release: {release_dir}")


if __name__ == "__main__":
    main()
