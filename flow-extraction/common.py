"""Shared helpers for the flow-extraction pipeline.

Runs under WSL (Linux) Python. All timestamps are UTC; NFStream emits
millisecond epoch timestamps and the pcap directory layout is UTC-bucketed
(verified during corpus investigation, 2026-08).
"""

import ipaddress
import json
import struct
from datetime import datetime, timezone

import pyarrow as pa

# ---------------------------------------------------------------------------
# Flow keying
# ---------------------------------------------------------------------------

WELL_KNOWN_PORT_MAX = 1024


def canonical_key(src_ip, src_port, dst_ip, dst_port, protocol):
    """Direction-independent 5-tuple key: endpoints sorted lexicographically."""
    a = f"{src_ip}:{src_port}"
    b = f"{dst_ip}:{dst_port}"
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{lo}|{hi}|{protocol}"


# ---------------------------------------------------------------------------
# Address classification (for derived columns)
# ---------------------------------------------------------------------------

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_ULA_V6 = ipaddress.ip_network("fc00::/7")


def ip_flags(ip_str):
    """Return (is_private, is_multicast, is_broadcast) for an IP string.

    is_private: RFC1918 for IPv4, ULA fc00::/7 for IPv6.
    is_broadcast: limited broadcast 255.255.255.255 only (subnet broadcasts
    are not identifiable without knowing the subnet plan).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, False, False
    if addr.version == 4:
        private = any(addr in n for n in _RFC1918)
        broadcast = str(addr) == "255.255.255.255"
    else:
        private = addr in _ULA_V6
        broadcast = False
    return private, addr.is_multicast, broadcast


# ---------------------------------------------------------------------------
# Pure-python pcap scan (ground-truth packet counts, independent of NFStream)
# ---------------------------------------------------------------------------


def scan_pcap(path):
    """Scan a classic libpcap file; return packet-level ground truth.

    Returns dict with n_packets, first_ts / last_ts (float epoch seconds),
    truncated_frames (incl_len < orig_len), max_orig_len, snaplen.
    Raises on malformed files — caller decides how to record the failure.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise ValueError(f"pcap too short ({len(data)} bytes)")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_div = "<", 1e6  # little-endian, microseconds
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_div = ">", 1e6
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_div = "<", 1e9  # nanosecond variant
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_div = ">", 1e9
    else:
        raise ValueError(f"unknown pcap magic {magic.hex()}")
    snaplen = struct.unpack(endian + "I", data[16:20])[0]
    rec = struct.Struct(endian + "IIII")
    off = 24
    n = 0
    first_ts = last_ts = None
    truncated = 0
    max_orig = 0
    total_len = len(data)
    while off + 16 <= total_len:
        ts_sec, ts_sub, incl_len, orig_len = rec.unpack_from(data, off)
        if off + 16 + incl_len > total_len:
            raise ValueError(
                f"truncated record at offset {off}: incl_len {incl_len} "
                f"exceeds file size {total_len}"
            )
        ts = ts_sec + ts_sub / ts_div
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        if incl_len < orig_len:
            truncated += 1
        if orig_len > max_orig:
            max_orig = orig_len
        n += 1
        off += 16 + incl_len
    if off != total_len:
        raise ValueError(f"trailing garbage: {total_len - off} bytes after last record")
    return {
        "n_packets": n,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "truncated_frames": truncated,
        "max_orig_len": max_orig,
        "snaplen": snaplen,
    }


# ---------------------------------------------------------------------------
# Arrow schema for NFStream fragment output
# ---------------------------------------------------------------------------

# Every field NFStream 6.6.0 emits (NFlow.keys() with statistical_analysis=True,
# splt_analysis>0, n_dissections>0), with explicit types so per-file parquets
# are schema-identical even when a column is entirely null in one file.
NFLOW_TYPES = {
    "id": pa.int64(),
    "expiration_id": pa.int64(),
    "src_ip": pa.string(),
    "src_mac": pa.string(),
    "src_oui": pa.string(),
    "src_port": pa.int64(),
    "dst_ip": pa.string(),
    "dst_mac": pa.string(),
    "dst_oui": pa.string(),
    "dst_port": pa.int64(),
    "protocol": pa.int64(),
    "ip_version": pa.int64(),
    "vlan_id": pa.int64(),
    "tunnel_id": pa.int64(),
    "bidirectional_first_seen_ms": pa.int64(),
    "bidirectional_last_seen_ms": pa.int64(),
    "bidirectional_duration_ms": pa.int64(),
    "bidirectional_packets": pa.int64(),
    "bidirectional_bytes": pa.int64(),
    "src2dst_first_seen_ms": pa.int64(),
    "src2dst_last_seen_ms": pa.int64(),
    "src2dst_duration_ms": pa.int64(),
    "src2dst_packets": pa.int64(),
    "src2dst_bytes": pa.int64(),
    "dst2src_first_seen_ms": pa.int64(),
    "dst2src_last_seen_ms": pa.int64(),
    "dst2src_duration_ms": pa.int64(),
    "dst2src_packets": pa.int64(),
    "dst2src_bytes": pa.int64(),
    "bidirectional_min_ps": pa.float64(),
    "bidirectional_mean_ps": pa.float64(),
    "bidirectional_stddev_ps": pa.float64(),
    "bidirectional_max_ps": pa.float64(),
    "src2dst_min_ps": pa.float64(),
    "src2dst_mean_ps": pa.float64(),
    "src2dst_stddev_ps": pa.float64(),
    "src2dst_max_ps": pa.float64(),
    "dst2src_min_ps": pa.float64(),
    "dst2src_mean_ps": pa.float64(),
    "dst2src_stddev_ps": pa.float64(),
    "dst2src_max_ps": pa.float64(),
    "bidirectional_min_piat_ms": pa.float64(),
    "bidirectional_mean_piat_ms": pa.float64(),
    "bidirectional_stddev_piat_ms": pa.float64(),
    "bidirectional_max_piat_ms": pa.float64(),
    "src2dst_min_piat_ms": pa.float64(),
    "src2dst_mean_piat_ms": pa.float64(),
    "src2dst_stddev_piat_ms": pa.float64(),
    "src2dst_max_piat_ms": pa.float64(),
    "dst2src_min_piat_ms": pa.float64(),
    "dst2src_mean_piat_ms": pa.float64(),
    "dst2src_stddev_piat_ms": pa.float64(),
    "dst2src_max_piat_ms": pa.float64(),
    "bidirectional_syn_packets": pa.int64(),
    "bidirectional_cwr_packets": pa.int64(),
    "bidirectional_ece_packets": pa.int64(),
    "bidirectional_urg_packets": pa.int64(),
    "bidirectional_ack_packets": pa.int64(),
    "bidirectional_psh_packets": pa.int64(),
    "bidirectional_rst_packets": pa.int64(),
    "bidirectional_fin_packets": pa.int64(),
    "src2dst_syn_packets": pa.int64(),
    "src2dst_cwr_packets": pa.int64(),
    "src2dst_ece_packets": pa.int64(),
    "src2dst_urg_packets": pa.int64(),
    "src2dst_ack_packets": pa.int64(),
    "src2dst_psh_packets": pa.int64(),
    "src2dst_rst_packets": pa.int64(),
    "src2dst_fin_packets": pa.int64(),
    "dst2src_syn_packets": pa.int64(),
    "dst2src_cwr_packets": pa.int64(),
    "dst2src_ece_packets": pa.int64(),
    "dst2src_urg_packets": pa.int64(),
    "dst2src_ack_packets": pa.int64(),
    "dst2src_psh_packets": pa.int64(),
    "dst2src_rst_packets": pa.int64(),
    "dst2src_fin_packets": pa.int64(),
    "splt_direction": pa.list_(pa.int64()),
    "splt_ps": pa.list_(pa.int64()),
    "splt_piat_ms": pa.list_(pa.float64()),
    "application_name": pa.string(),
    "application_category_name": pa.string(),
    "application_is_guessed": pa.int64(),
    "application_confidence": pa.int64(),
    "requested_server_name": pa.string(),
    "client_fingerprint": pa.string(),
    "server_fingerprint": pa.string(),
    "user_agent": pa.string(),
    "content_type": pa.string(),
}

# Fragment-level bookkeeping columns added by extract_one.py.
FRAGMENT_EXTRA_TYPES = {
    "fragment_id": pa.string(),
    "source_pcap": pa.string(),
    "canonical_key": pa.string(),
}


def records_to_table(records, type_map):
    """Build a pyarrow Table from row dicts with an explicit schema."""
    fields = list(type_map.items())
    arrays = []
    for name, typ in fields:
        arrays.append(pa.array([r.get(name) for r in records], type=typ))
    return pa.Table.from_arrays(arrays, names=[n for n, _ in fields])


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def utc_from_ms(ms):
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


def write_json(path, obj):
    tmp = str(path) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2, default=str)
    import os

    os.replace(tmp, path)
