#!/usr/bin/env python3
"""CLI tool for tracking cybersecurity attack attempts"""

import argparse
import csv
import ipaddress
import json
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = Path.home() / ".attacklog"
CONFIG_PATH = CONFIG_DIR / "config.json"
DB_PATH = CONFIG_DIR / "attacks.db"

VALID_PROTOCOLS = {"tcp", "udp", "icmp"}
VALID_STATUSES = {"success", "ran", "error"}


def now_iso() -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        print(
            "Error: attacklog has not been initialized on this machine.\n"
            "Run: attacklog init --attacker-id <id> --src-ip <ip>",
            file=sys.stderr,
        )
        sys.exit(1)
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_db() -> sqlite3.Connection:
    ensure_config_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attacks (
            attack_id   TEXT PRIMARY KEY,
            attacker_id TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            dst_port    TEXT,
            protocol    TEXT,
            attack_name TEXT,
            attack_type TEXT,
            t_start     TEXT,
            t_end       TEXT,
            status      TEXT,
            notes       TEXT
        )
        """
    )
    # Migration: add attack_type column to databases created before this field existed.
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(attacks)")}
    if "attack_type" not in existing_cols:
        conn.execute("ALTER TABLE attacks ADD COLUMN attack_type TEXT")
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_dst_ip(value: str) -> tuple[str, str]:
    """Validate and normalise a destination IP specifier.

    Returns (normalised_value, kind) where kind is one of:
      'single' – a single host address (e.g. 192.168.1.5)
      'cidr'   – a network in CIDR notation (e.g. 192.168.1.0/24)
      'range'  – an inclusive address range (e.g. 192.168.1.1-192.168.1.254)
    """
    v = value.strip()

    # IP range: x.x.x.x-x.x.x.x
    m = re.fullmatch(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", v
    )
    if m:
        try:
            start = ipaddress.ip_address(m.group(1))
            end = ipaddress.ip_address(m.group(2))
        except ValueError as exc:
            raise ValueError(f"Invalid IP range: {exc}") from exc
        if int(start) > int(end):
            raise ValueError(f"IP range start {start} is after end {end}")
        return f"{start}-{end}", "range"

    # CIDR block or single address — ip_network handles both gracefully.
    try:
        net = ipaddress.ip_network(v, strict=False)
        if net.num_addresses == 1:
            return str(net.network_address), "single"
        return str(net), "cidr"
    except ValueError:
        pass

    raise ValueError(
        f"Invalid --dst-ip: {value!r}. "
        "Expected a single IP (192.168.1.5), CIDR block (192.168.1.0/24), "
        "or range (192.168.1.1-192.168.1.254)."
    )


def _validate_dst_port(value: str) -> tuple[str, str]:
    """Validate and normalise a destination port specifier.

    Returns (normalised_value, kind) where kind is one of:
      'single' – one port number (e.g. 80)
      'range'  – a contiguous range (e.g. 1-1024)
      'list'   – a comma-separated set (e.g. 22,80,443)
    """
    v = value.strip()

    def _check(p: int, label: str = "Port") -> None:
        if not (0 <= p <= 65535):
            raise ValueError(f"{label} {p} is outside the valid range 0-65535")

    # Single port
    if re.fullmatch(r"\d+", v):
        p = int(v)
        _check(p)
        return str(p), "single"

    # Contiguous range: start-end
    m = re.fullmatch(r"(\d+)-(\d+)", v)
    if m:
        s, e = int(m.group(1)), int(m.group(2))
        _check(s, "Start port")
        _check(e, "End port")
        if s > e:
            raise ValueError(f"Port range {s}-{e}: start is greater than end")
        return f"{s}-{e}", "range"

    # Comma-separated list
    if "," in v:
        parts = [p.strip() for p in v.split(",") if p.strip()]
        normalised: list[str] = []
        for p in parts:
            if not re.fullmatch(r"\d+", p):
                raise ValueError(f"Invalid port in list: {p!r}")
            pn = int(p)
            _check(pn)
            normalised.append(str(pn))
        return ",".join(normalised), "list"

    raise ValueError(
        f"Invalid --dst-port: {value!r}. "
        "Expected a single port (80), a range (1-1024), or a list (22,80,443)."
    )


def _infer_attack_type(ip_kind: str, port_kind: str) -> str:
    """Derive a human-readable attack type label from the IP and port kinds."""
    if ip_kind == "single" and port_kind == "single":
        return "targeted"
    if ip_kind == "single":
        return "port_scan"
    return "network_scan"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    ensure_config_dir()
    config = {"attacker_id": args.attacker_id, "src_ip": args.src_ip}
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    get_db().close()
    print("attacklog initialized.")
    print(f"  config       : {CONFIG_PATH}")
    print(f"  database     : {DB_PATH}")
    print(f"  attacker_id  : {args.attacker_id}")
    print(f"  src_ip       : {args.src_ip}")


def cmd_start(args: argparse.Namespace) -> None:
    config = load_config()
    protocol = args.protocol.lower()
    if protocol not in VALID_PROTOCOLS:
        print(
            f"Error: --protocol must be one of {sorted(VALID_PROTOCOLS)}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        dst_ip, ip_kind = _validate_dst_ip(args.dst_ip)
        dst_port, port_kind = _validate_dst_port(args.dst_port)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    attack_type = _infer_attack_type(ip_kind, port_kind)

    conn = get_db()
    open_row = conn.execute(
        "SELECT attack_id, attack_name, t_start FROM attacks "
        "WHERE t_end IS NULL ORDER BY t_start DESC LIMIT 1"
    ).fetchone()
    if open_row is not None:
        print(
            "Refusing to start: there is already an open attack.\n"
            f"  attack_id   : {open_row['attack_id']}\n"
            f"  attack_name : {open_row['attack_name']}\n"
            f"  t_start     : {open_row['t_start']}\n"
            "Run `attacklog end --status <success|ran|error>` first.",
            file=sys.stderr,
        )
        conn.close()
        sys.exit(1)

    attack_id = str(uuid.uuid4())
    t_start = now_iso()
    conn.execute(
        "INSERT INTO attacks "
        "(attack_id, attacker_id, src_ip, dst_ip, dst_port, protocol, "
        "attack_name, attack_type, t_start, t_end, status, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
        (
            attack_id,
            config["attacker_id"],
            config["src_ip"],
            dst_ip,
            dst_port,
            protocol,
            args.name,
            attack_type,
            t_start,
        ),
    )
    conn.commit()
    conn.close()

    print(f"Attack started  [{attack_type}].")
    print(f"  attack_id   : {attack_id}")
    print(f"  attack_name : {args.name}")
    print(f"  attacker_id : {config['attacker_id']}")
    print(f"  src_ip      : {config['src_ip']}")
    print(f"  dst         : {dst_ip}:{dst_port}/{protocol}")
    print(f"  t_start     : {t_start}")


def cmd_end(args: argparse.Namespace) -> None:
    load_config()
    if args.status not in VALID_STATUSES:
        print(
            f"Error: --status must be one of {sorted(VALID_STATUSES)}",
            file=sys.stderr,
        )
        sys.exit(1)

    conn = get_db()
    row = conn.execute(
        "SELECT attack_id, attack_name, t_start FROM attacks "
        "WHERE t_end IS NULL ORDER BY t_start DESC LIMIT 1"
    ).fetchone()
    if row is None:
        print(
            "Error: no open attack to end. Start one with `attacklog start ...`.",
            file=sys.stderr,
        )
        conn.close()
        sys.exit(1)

    t_end = now_iso()
    conn.execute(
        "UPDATE attacks SET t_end = ?, status = ?, notes = ? WHERE attack_id = ?",
        (t_end, args.status, args.notes, row["attack_id"]),
    )
    conn.commit()
    conn.close()

    print("Attack ended.")
    print(f"  attack_id   : {row['attack_id']}")
    print(f"  attack_name : {row['attack_name']}")
    print(f"  t_start     : {row['t_start']}")
    print(f"  t_end       : {t_end}")
    print(f"  status      : {args.status}")
    if args.notes:
        print(f"  notes       : {args.notes}")


def cmd_list(args: argparse.Namespace) -> None:
    load_config()
    conn = get_db()
    query = "SELECT * FROM attacks ORDER BY t_start DESC"
    params: tuple = ()
    if args.limit is not None:
        query += " LIMIT ?"
        params = (args.limit,)
    rows = conn.execute(query, params).fetchall()
    conn.close()

    if not rows:
        print("No attacks recorded.")
        return

    headers = [
        "attack_id",
        "attack_name",
        "attack_type",
        "dst",
        "proto",
        "t_start",
        "t_end",
        "status",
    ]
    table = []
    for r in rows:
        dst = f"{r['dst_ip']}:{r['dst_port']}"
        table.append(
            [
                r["attack_id"],
                r["attack_name"] or "",
                r["attack_type"] or "targeted",
                dst,
                r["protocol"] or "",
                r["t_start"] or "",
                r["t_end"] or "(open)",
                r["status"] or "",
            ]
        )

    widths = [
        max(len(h), max(len(str(row[i])) for row in table))
        for i, h in enumerate(headers)
    ]
    sep = "  "
    print(sep.join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print(sep.join("-" * w for w in widths))
    for row in table:
        print(sep.join(str(row[i]).ljust(widths[i]) for i in range(len(headers))))


def cmd_export(args: argparse.Namespace) -> None:
    load_config()
    fmt = args.format.lower()
    if fmt not in {"json", "csv"}:
        print("Error: --format must be json or csv", file=sys.stderr)
        sys.exit(1)

    conn = get_db()
    rows = conn.execute("SELECT * FROM attacks ORDER BY t_start ASC").fetchall()
    conn.close()
    records = [dict(r) for r in rows]

    if fmt == "json":
        text = json.dumps(records, indent=2)
    else:
        from io import StringIO

        buf = StringIO()
        fieldnames = [
            "attack_id",
            "attacker_id",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "attack_name",
            "attack_type",
            "t_start",
            "t_end",
            "status",
            "notes",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for rec in records:
            writer.writerow({k: ("" if rec.get(k) is None else rec[k]) for k in fieldnames})
        text = buf.getvalue()

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(text, encoding="utf-8")
        print(f"Exported {len(records)} record(s) to {out_path} ({fmt}).")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attacklog",
        description="Track cybersecurity attack attempts in a controlled research environment.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize attacklog on this machine.")
    p_init.add_argument("--attacker-id", required=True)
    p_init.add_argument("--src-ip", required=True)
    p_init.set_defaults(func=cmd_init)

    p_start = sub.add_parser("start", help="Start a new attack.")
    p_start.add_argument("--name", required=True)
    p_start.add_argument("--dst-ip", required=True,
                         help="Target IP, CIDR block (192.168.1.0/24), or range (192.168.1.1-192.168.1.254)")
    p_start.add_argument("--dst-port", required=True,
                         help="Target port, range (1-1024), or comma-separated list (22,80,443)")
    p_start.add_argument("--protocol", default="tcp")
    p_start.set_defaults(func=cmd_start)

    p_end = sub.add_parser("end", help="End the most recently started open attack.")
    p_end.add_argument("--status", required=True, choices=sorted(VALID_STATUSES))
    p_end.add_argument("--notes", default=None)
    p_end.set_defaults(func=cmd_end)

    p_list = sub.add_parser("list", help="List recorded attacks.")
    p_list.add_argument("--limit", type=int, default=None)
    p_list.set_defaults(func=cmd_list)

    p_export = sub.add_parser("export", help="Export records to JSON or CSV.")
    p_export.add_argument("--format", default="json")
    p_export.add_argument("--output", default=None)
    p_export.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
