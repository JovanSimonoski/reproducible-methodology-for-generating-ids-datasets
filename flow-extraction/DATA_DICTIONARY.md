# Flow Dataset — Data Dictionary

One row = **one bidirectional network flow**, extracted with NFStream 6.6.0
(nDPI-based) by [flow-extraction](README.md). Flow fragments split by the
capture appliance's file rotation are stitched back together during
consolidation (`n_fragments` > 1 marks stitched rows).

A processed capture has **186 columns**. Read hive-style, the Parquet dataset
adds the partition keys `date` / `hour` (from flow start, UTC) as virtual
columns. Later stages append columns: `label` ([flow-labeling](../flow-labeling/README.md))
and `capture_id` ([dataset-unification](../dataset-unification/README.md)).

Conventions that apply throughout:

- **Timestamps** are absolute Unix epoch **milliseconds, UTC**.
- **Direction**: `src2dst` ("up") is the direction of the first packet NFStream
  saw for the flow; `dst2src` ("down") is the reverse. For stitched flows the
  orientation of the *first* fragment wins.
- **Bytes** are counted in accounting mode 0 = **full link-layer (L2) frame
  bytes**. Byte columns are only comparable to other datasets using the same
  mode.
- **Statistics convention**: `stddev` columns are *sample* standard deviation
  (ddof=1, verified empirically). Directional statistic columns are **0, not
  null, when that direction has no packets** (NFStream convention); always
  check `*_packets > 0` before interpreting a directional statistic.
- **Strings**: nDPI metadata columns use the empty string `""` (not null) when
  nothing was extracted, matching NFStream's own output.

## Identity and join keys

| column | type | meaning |
|---|---|---|
| `flow_id` | string | Unique id within a capture: `<source-file-epoch>-<per-file NFStream id>` of the flow's first fragment. Deterministic across re-extractions when extraction runs with one NFStream meter (the default); to refer to a flow independently of extraction, use the 5-tuple plus `bidirectional_first_seen_ms`. |
| `canonical_key` | string | Direction-independent 5-tuple: the two `ip:port` endpoints sorted lexicographically, joined with the IP protocol number, `ip:port\|ip:port\|proto`. Use this (plus time) for joins so A→B and B→A meet. |
| `src_ip`, `dst_ip` | string | Endpoint IPs as seen in the flow's first packet (the label join keys). Real addresses in the per-capture datasets; in a release built with anonymization, public addresses are replaced by documentation-range pseudonyms (see dataset-unification). |
| `src_port`, `dst_port` | int64 | Transport ports (0 for port-less protocols such as ICMP/IGMP). |
| `protocol` | int64 | IP protocol number (6 TCP, 17 UDP, 1 ICMP, 2 IGMP, …). |
| `ip_version` | int64 | 4 or 6. |
| `id` | int64 | NFStream's per-file flow counter (not unique across files; use `flow_id`). |
| `expiration_id` | int64 | NFStream's expiration trigger of the *last* fragment: 0 idle timeout, 1 active timeout, −1 custom expiration. When each pcap is shorter than the active timeout (10-minute files vs 1800 s), only idle and end-of-file expiry occur, both reported as 0, so the column is constant; use `truncated_*` / `recut_active_timeout` for lifecycle reasoning. Kept per the keep-everything policy. |
| `vlan_id` | int64 | 802.1Q VLAN id (0 when untagged). |
| `tunnel_id` | int64 | NFStream tunnel decoder id (0 when no tunneling). |
| `src_mac`, `dst_mac` | string | Endpoint MAC addresses. On routed or virtualized captures they reflect the capture point's L2 neighbourhood (e.g. a hypervisor vSwitch), not necessarily the end hosts. |
| `src_oui`, `dst_oui` | string | First three MAC octets (vendor prefix). |

## Provenance and stitching

| column | type | meaning |
|---|---|---|
| `source_pcap` | string | Path of the pcap containing the flow's **first** fragment, relative to the extraction input directory and prefixed with the capture id (`--capture-id`). |
| `source_pcaps` | string | Comma-joined paths of **all** files the flow spans (equals `source_pcap` for unstitched rows). |
| `fragment_id` | string | Id of the first fragment (equals `flow_id`). |
| `fragment_ids` | string | Comma-joined ids of all merged fragments, in time order. |
| `n_fragments` | int64 | Number of NFStream fragments merged into this row (1 = untouched by stitching). |
| `truncated_start` | bool | Flow starts within `idle_timeout` of its file's first packet **and** no repaired boundary precedes it (the capture's first file or a failed/missing neighbour), so its true start may predate the capture. |
| `truncated_end` | bool | Mirror image at the flow's tail (the capture's last file or a failed/missing next file): its true end may postdate the capture. |
| `recut_active_timeout` | bool | This row begins a continuation chain that was deliberately cut at `active_timeout` during stitching, mimicking NFStream's own behaviour on an unsplit capture. |

## Timing

| column | type | meaning |
|---|---|---|
| `bidirectional_first_seen_ms` | int64 | Epoch ms UTC of the flow's first packet. |
| `bidirectional_last_seen_ms` | int64 | Epoch ms UTC of the flow's last packet. |
| `bidirectional_duration_ms` | int64 | last − first, ms. |
| `src2dst_first_seen_ms`, `src2dst_last_seen_ms`, `src2dst_duration_ms` | int64 | Same, restricted to the up direction (0 if that direction has no packets). |
| `dst2src_first_seen_ms`, `dst2src_last_seen_ms`, `dst2src_duration_ms` | int64 | Same, down direction. |

## Volume counters

| column | type | meaning |
|---|---|---|
| `bidirectional_packets`, `bidirectional_bytes` | int64 | Total packets / L2 bytes both directions. |
| `src2dst_packets`, `src2dst_bytes` | int64 | Up direction. |
| `dst2src_packets`, `dst2src_bytes` | int64 | Down direction. |

## Packet-size and inter-arrival statistics (24 columns)

For each family `F` ∈ {`bidirectional`, `src2dst`, `dst2src`}:

| column | type | meaning |
|---|---|---|
| `F_min_ps`, `F_mean_ps`, `F_stddev_ps`, `F_max_ps` | float64 | Packet size (L2 bytes) min / mean / sample-stddev / max. |
| `F_min_piat_ms`, `F_mean_piat_ms`, `F_stddev_piat_ms`, `F_max_piat_ms` | float64 | Packet inter-arrival time (ms) statistics; defined when the family has ≥ 2 packets, else 0. For stitched flows these are exact pooled values including the known inter-fragment gap. |

## TCP flag counters (24 columns)

`F_{syn,cwr,ece,urg,ack,psh,rst,fin}_packets` (int64) for the same three
families: number of packets with that TCP flag set. Always 0 for non-TCP flows.

## SPLT — sequence of the first 20 packets

Per-packet direction, size and inter-arrival time of the flow's first 20
packets; the most valuable features for encrypted/behavioural classification.
For stitched flows the sequence continues seamlessly across the file boundary
(the appended packet's inter-arrival is the true seam gap).

| column | type | meaning |
|---|---|---|
| `splt_direction` | list<int64> | Per-packet direction: 0 = src2dst, 1 = dst2src; padded with −1 past the flow's packet count. |
| `splt_ps` | list<int64> | Per-packet L2 size in bytes; −1 padding. |
| `splt_piat_ms` | list<float64> | Per-packet inter-arrival ms (first entry 0); −1 padding. |
| `splt_direction_0` … `splt_direction_19` | int64 | Flattened copies of the lists for tooling that cannot read list types. **Null (not −1) past the flow's packet count.** |
| `splt_ps_0` … `splt_ps_19` | int64 | ditto |
| `splt_piat_ms_0` … `splt_piat_ms_19` | float64 | ditto |

In the CSV export the three list columns are serialized as JSON arrays.

## nDPI application-layer metadata

| column | type | meaning |
|---|---|---|
| `application_name` | string | nDPI protocol/application (e.g. `HTTP`, `DNS`, `TLS`, `NTP`, `NetBIOS.SMBv1`); `Unknown` when undetected. In scan-heavy traffic most flows are `Unknown`: 1–2 packet probes carry no classifiable payload. |
| `application_category_name` | string | nDPI category (e.g. `Web`, `Network`, `System`). |
| `application_is_guessed` | int64 | 1 if nDPI fell back to a port/IP guess rather than payload dissection. |
| `application_confidence` | int64 | nDPI confidence enum (6 = DPI match; lower = weaker inference). |
| `requested_server_name` | string | TLS SNI, HTTP Host, or DNS query name. |
| `client_fingerprint` | string | TLS client fingerprint, **JA4 format** in this nDPI version (e.g. `t13i1515h2_8daaf…`; the legacy-looking `D41D8CD9…` value is the MD5-of-empty degenerate). Only present for completed client hellos. |
| `server_fingerprint` | string | TLS server (JA3S-style) fingerprint. |
| `user_agent` | string | HTTP User-Agent (attack tools often identify themselves, e.g. `sqlmap/…`). |
| `content_type` | string | HTTP Content-Type of the response. |

## Derived columns (computed at consolidation)

| column | type | meaning |
|---|---|---|
| `duration_s` | float64 | `bidirectional_duration_ms` / 1000. |
| `bidirectional_pps`, `bidirectional_bps` | float64 | Packets/sec and L2 bytes/sec over the flow's own duration; **null when duration is 0** (e.g. single-packet flows). |
| `src2dst_pps`, `src2dst_bps`, `dst2src_pps`, `dst2src_bps` | float64 | Same per direction, over that direction's duration; null when 0/undefined. |
| `bytes_ratio_updown` | float64 | `src2dst_bytes / dst2src_bytes`; null when the down direction has 0 bytes. |
| `packets_ratio_updown` | float64 | Same for packets. |
| `is_ipv4`, `is_ipv6` | bool | From `ip_version`. |
| `is_tcp`, `is_udp`, `is_other_protocol` | bool | From `protocol`. |
| `src_is_private`, `dst_is_private` | bool | RFC1918 for IPv4; ULA fc00::/7 for IPv6. |
| `src_is_multicast`, `dst_is_multicast` | bool | IP multicast ranges. |
| `src_is_broadcast`, `dst_is_broadcast` | bool | Limited broadcast 255.255.255.255 only (subnet-directed broadcasts are not identifiable without the subnet plan). |
| `src_port_wellknown`, `dst_port_wellknown` | bool | Port < 1024. |
| `service_port` | int64 | The well-known port if exactly one side has one, else min(src_port, dst_port). |
| `start_date` | string | `YYYY-MM-DD` (UTC) of flow start. |
| `start_hour`, `start_minute` | int64 | UTC clock fields of flow start. |
| `start_day_of_week` | int64 | Monday = 0 … Sunday = 6 (UTC). |

## Columns added by later stages

| column | added by | meaning |
|---|---|---|
| `label` | flow-labeling | Canonical `attack_name` of the matched attacklog record, or `BENIGN`. Always the last column. |
| `capture_id` | dataset-unification | Capture the flow came from (its folder name under `data/raw/`). Placed just before `label`. |

## Known limitations / columns to use with care

- `expiration_id`: constant when pcaps are shorter than the active timeout (see above).
- `id`: per-file counter, duplicated across files; use `flow_id`.
- `src_mac`/`dst_mac`/OUIs: reflect the capture point's L2 neighbourhood, not
  necessarily end hosts.
- `client_fingerprint`/`server_fingerprint`: empty without completed TLS
  handshakes; retained so the schema is future-proof.
- Columns that are constant within a capture (e.g. `vlan_id` on a single
  VLAN) are findings about the capture, not errors. The dataset statistics
  report lists them.
- Byte counts include L2 headers (mode 0): re-extract under a different
  accounting mode if payload-byte semantics are needed.
