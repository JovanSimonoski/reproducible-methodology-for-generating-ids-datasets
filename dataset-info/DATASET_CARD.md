# cyber-attacks-dataset

Labeled network-flow dataset for training and evaluating intrusion detection
systems. It was produced with the methodology of the master thesis
**A Reproducible Methodology for Generating Modern Intrusion Detection Datasets**
(Jovan Simonoski). Volunteer attackers ran a documented catalog of attacks
against intentionally vulnerable hosts (Metasploitable 2, Metasploitable 3,
VulHub containers) in an isolated, monitored lab. They logged every attack
with `attacklog`, and the captured traffic was turned into flows and labeled
automatically from those logs.

Code, methodology and documentation:
<https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets>

## Files

| File | Content |
|---|---|
| `cyber_attacks_flows.csv` | All flows, unlabeled: 186 flow columns + `capture_id` (187 columns). |
| `cyber_attacks_flows_labeled.csv` | Same rows in the same order + `label` (188 columns, `label` last). |
| `DATASET_STATISTICS.md` | Full statistics: class distribution and balance, per-class traffic profiles, attackers and targets, labeling method and limitations, protocols, ports, hosts, time, data quality, feature audit. |
| `build_summary.json` | Build record: per-capture counts and label distributions, every manual relabel. |
| `provenance/` | Per capture: extraction run metadata, validation report, labeling summary, pcap manifest and the attackers' attacklog exports; plus `relabel_overrides.csv`. |

## Captures

| capture_id | Traffic window (UTC) | Flows | Attack | BENIGN | Attackers |
|---|---|---:|---:|---:|---|
| `07` | 2026-07-14 07:45 → 07-17 08:43 | 1,796,455 | 1,413,666 | 382,789 | 4 |
| `10` | 2026-10-01 00:00 → 10-13 08:41 | 466,966 | 385,099 | 81,867 | 2 |
| **total** | 15.4 days | **2,263,421** | **1,798,765** | **464,656** | 6 |

Rows are ordered capture by capture.

## Columns

- **186 flow columns.** NFStream 6.6.0 bidirectional flow features: identity
  and timing, volume, packet-size and inter-arrival statistics, TCP flags, the
  first 20 packets' sizes, directions and timings, nDPI application metadata,
  and derived rates and flags. Timestamps are epoch milliseconds (UTC). See the
  [data dictionary](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets/blob/main/flow-extraction/DATA_DICTIONARY.md).
- **`capture_id`.** Capture the flow came from (`07`, `10`); read it as a
  string if the leading zero matters. Use it to split train/test by capture.
- **`label`.** Canonical attack name, or `BENIGN`. There are 54 classes: 53
  attacks and BENIGN. Prefixes give the target platform (`ms2-`
  Metasploitable 2, `ms3-` Metasploitable 3, `vulnhub-` VulHub). Names ending
  in `-portscan` are the single-port reconnaissance run right before the
  matching exploit. `nmap-full-portscan` is the full TCP port scan of a target.

Several columns identify the flow, host, capture or absolute time (IPs, MACs,
`flow_id`, timestamps, `source_pcap`, …). Keep them out of model inputs unless
you intend the model to learn the lab setup; section 12 of
`DATASET_STATISTICS.md` lists them.

## How labels were assigned

1. **Automatically, from the attack logs.** A flow from an attacker gets an
   attack's label when its src IP, dst IP, dst port and protocol match that
   attack's record and its time overlaps the record's window (±1 s). Flows that
   match a record's addresses and port but no window go to the nearest such
   record (tuple fallback). Everything else is `BENIGN`.
2. **Manual corrections, reviewed flow by flow (16).** Exploit side channels on
   unlogged ports get their exploit's label, and administrative SSH sessions
   from an attacker host become `BENIGN`. Each correction and the evidence
   behind it is in `provenance/relabel_overrides.csv`. Four of them are
   inferred from traffic fingerprints rather than an attack record, and their
   reason says so.

## Anonymization

Public IP addresses are pseudonymized: 92 addresses, all destinations of the
lab's outbound background traffic (e.g. DNS resolvers, CDNs, OS update
mirrors), in 8,115 flows, all `BENIGN`. Each is replaced by a pseudonym from
the IPv4 documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and
`203.0.113.0/24`; `canonical_key` is recomputed accordingly.

- The same real address always maps to the same pseudonym, so flows to one
  server stay grouped. Pseudonyms carry no network structure, though: two
  addresses of one provider do not share a pseudonym subnet.
- The lab's time server, `194.149.136.252` (`ntp.finki.ukim.mk`), is
  deliberately left unchanged.
- Private lab addresses (`192.168.x.x`), link-local and multicast addresses
  are unchanged, so attacker and target hosts keep their real lab addresses.

## Caveats

- **Strong class imbalance.** `nmap-full-portscan` is 76% of all rows (one
  flow per probed port), and most exploit classes have fewer than 300 flows.
  Use class weights or re-sampling, and report macro-averaged metrics.
- **Target → attacker traffic is BENIGN.** attacklog records attacker-initiated
  traffic only, so reverse-shell callbacks and payload downloads from the
  attacker (551 flows) are labeled `BENIGN`.
- **Fallback labels.** About 15% of attack flows were labeled by the tuple
  fallback, mostly a full port scan that one attacker repeated without logging.
- `BENIGN` means "matched no attack record"; the lab is isolated, so this is
  the lab's own background traffic (DNS, NTP, logging, …).

## Reproducing

From the repository, with the raw captures and attack logs in `data/raw/`:

```bash
export PYTHON=~/ids-venv/bin/python
bash scripts/process_capture.sh 07
bash scripts/process_capture.sh 10
bash scripts/build_release.sh
```

This regenerates the release (the same flows, flow ids and labels) together
with `DATASET_STATISTICS.md`.
