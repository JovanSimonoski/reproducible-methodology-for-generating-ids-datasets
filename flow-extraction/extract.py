"""Orchestrate per-pcap flow extraction across the corpus.

- Discovers pcaps under --input-dir (read-only; never written).
- Optionally stages each pcap to the Linux filesystem first (the /mnt/c
  bridge caps NFStream at ~23 MB/s vs ~127 MB/s local; measured 2026-08).
- Runs extract_one.py as an isolated subprocess per file, N workers.
- Resumable: skips inputs whose parquet + meta already exist.
- Failures are recorded in errors.log and the manifest; the run continues.

Outputs under --work-dir:
  intermediate/<mirrored rel path>.parquet / .meta.json
  manifest.csv, errors.log, extract_config.json
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent


def discover(input_dir):
    files = sorted(input_dir.rglob("*.pcap"), key=lambda p: p.name)
    return files


def main():
    ap = argparse.ArgumentParser(description="per-pcap flow extraction")
    ap.add_argument("--input-dir", required=True, type=Path)
    ap.add_argument("--work-dir", required=True, type=Path)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--idle-timeout", type=int, default=120)
    ap.add_argument("--active-timeout", type=int, default=1800)
    ap.add_argument("--accounting-mode", type=int, default=0)
    ap.add_argument("--splt", type=int, default=20)
    ap.add_argument("--n-dissections", type=int, default=20)
    ap.add_argument("--limit", type=int, default=0, help="process only the first N files (pilot)")
    ap.add_argument("--files-list", type=Path, default=None,
                    help="file with one relative pcap path per line (overrides --limit selection)")
    ap.add_argument("--no-stage", action="store_true",
                    help="read pcaps directly from --input-dir instead of staging to the Linux FS")
    ap.add_argument("--stage-dir", type=Path, default=Path.home() / "csad-staged")
    ap.add_argument("--timeout-per-file", type=int, default=1800,
                    help="hard per-file subprocess timeout in seconds")
    args = ap.parse_args()

    input_dir = args.input_dir.resolve()
    work = args.work_dir
    inter = work / "intermediate"
    inter.mkdir(parents=True, exist_ok=True)

    all_files = discover(input_dir)
    if args.files_list:
        wanted = {line.strip() for line in args.files_list.read_text().splitlines() if line.strip()}
        files = [f for f in all_files if str(f.relative_to(input_dir)).replace(os.sep, "/") in wanted]
        missing = wanted - {str(f.relative_to(input_dir)).replace(os.sep, "/") for f in files}
        if missing:
            raise SystemExit(f"--files-list entries not found under input dir: {sorted(missing)}")
    else:
        files = all_files[: args.limit] if args.limit else all_files

    config = {
        "nfstream_config": {
            "decode_tunnels": True,
            "promiscuous_mode": False,
            "statistical_analysis": True,
            "splt_analysis": args.splt,
            "n_dissections": args.n_dissections,
            "accounting_mode": args.accounting_mode,
            "idle_timeout": args.idle_timeout,
            "active_timeout": args.active_timeout,
        },
        "input_dir": str(input_dir),
        "staged": not args.no_stage,
        "workers": args.workers,
        "files_discovered": len(all_files),
        "files_selected": len(files),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(work / "extract_config.json", "w") as fh:
        json.dump(config, fh, indent=2)

    errors_log = open(work / "errors.log", "a", buffering=1)
    log_lock = threading.Lock()
    progress = {"done": 0, "flows": 0, "failed": 0, "skipped": 0}
    t_start = time.time()

    def process(pcap_path):
        rel = str(pcap_path.relative_to(input_dir)).replace(os.sep, "/")
        out_parquet = inter / (rel[:-len(".pcap")] + ".parquet")
        out_meta = inter / (rel[:-len(".pcap")] + ".meta.json")
        out_parquet.parent.mkdir(parents=True, exist_ok=True)

        if out_parquet.exists() and out_meta.exists():
            with open(out_meta) as fh:
                meta = json.load(fh)
            return rel, "skipped", meta, None

        read_path = pcap_path
        if not args.no_stage:
            staged = args.stage_dir / rel
            staged.parent.mkdir(parents=True, exist_ok=True)
            if not (staged.exists() and staged.stat().st_size == pcap_path.stat().st_size):
                tmp = staged.with_suffix(".tmp")
                shutil.copyfile(pcap_path, tmp)
                os.replace(tmp, staged)
            read_path = staged

        cmd = [
            sys.executable, str(HERE / "extract_one.py"),
            "--pcap", str(read_path),
            "--rel", rel,
            "--out", str(out_parquet),
            "--meta", str(out_meta),
            "--idle-timeout", str(args.idle_timeout),
            "--active-timeout", str(args.active_timeout),
            "--accounting-mode", str(args.accounting_mode),
            "--splt", str(args.splt),
            "--n-dissections", str(args.n_dissections),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=args.timeout_per_file)
        if proc.returncode != 0:
            return rel, "failed", None, (
                f"exit {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            )
        with open(out_meta) as fh:
            meta = json.load(fh)
        return rel, "ok", meta, None

    manifest_rows = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(process, f): f for f in files}
        for fut in as_completed(futures):
            pcap_path = futures[fut]
            rel = str(pcap_path.relative_to(input_dir)).replace(os.sep, "/")
            try:
                rel, status, meta, err = fut.result()
            except Exception as exc:  # subprocess timeout, staging IO error, ...
                status, meta, err = "failed", None, f"{type(exc).__name__}: {exc}"
            row = {
                "source_pcap": rel,
                "size_bytes": pcap_path.stat().st_size,
                "status": status,
                "packet_count": "",
                "first_packet_ts": "",
                "last_packet_ts": "",
                "truncated_frames": "",
                "n_flows": "",
                "flow_packets_total": "",
                "extract_seconds": "",
                "error": "",
            }
            with log_lock:
                if status == "failed":
                    progress["failed"] += 1
                    row["error"] = (err or "").splitlines()[0][:300] if err else "unknown"
                    errors_log.write(f"=== {rel} ===\n{err}\n")
                else:
                    if status == "skipped":
                        progress["skipped"] += 1
                    scan = meta["scan"]
                    row.update({
                        "packet_count": scan["n_packets"],
                        "first_packet_ts": scan["first_ts"],
                        "last_packet_ts": scan["last_ts"],
                        "truncated_frames": scan["truncated_frames"],
                        "n_flows": meta["n_flows"],
                        "flow_packets_total": meta["flow_packets_total"],
                        "extract_seconds": meta["extract_seconds"],
                    })
                    progress["flows"] += meta["n_flows"]
                progress["done"] += 1
                manifest_rows[rel] = row
                elapsed = time.time() - t_start
                rate = progress["done"] / elapsed if elapsed else 0
                print(
                    f"[{progress['done']}/{len(files)}] {status:7s} {rel} "
                    f"| flows so far {progress['flows']} | failed {progress['failed']} "
                    f"| {elapsed:.0f}s elapsed, {rate:.1f} files/s",
                    flush=True,
                )

    errors_log.close()

    manifest_path = work / "manifest.csv"
    fieldnames = ["source_pcap", "size_bytes", "status", "packet_count",
                  "first_packet_ts", "last_packet_ts", "truncated_frames",
                  "n_flows", "flow_packets_total", "extract_seconds", "error"]
    with open(manifest_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for rel in sorted(manifest_rows):
            writer.writerow(manifest_rows[rel])

    ok = sum(1 for r in manifest_rows.values() if r["status"] in ("ok", "skipped"))
    print(
        f"\nDone: {ok} ok ({progress['skipped']} resumed), {progress['failed']} failed, "
        f"{progress['flows']} new flow fragments, {time.time() - t_start:.0f}s total."
    )
    print(f"Manifest: {manifest_path}")
    if progress["failed"]:
        print(f"FAILURES logged in {work / 'errors.log'}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
