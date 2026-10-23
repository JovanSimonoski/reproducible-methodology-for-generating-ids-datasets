# Dataset Unification

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Combines the labeled flows of several captures into one documented dataset
release. It also applies reviewed, flow-level label corrections, optionally
pseudonymizes public IP addresses, and copies each capture's provenance into
the release.

| File | Purpose |
|---|---|
| `build_dataset.py` | The release builder. |
| `anonymize.py` | Public-IP pseudonymization used by the builder (see [Anonymization](#anonymization)). |

## Requirements and inputs

Python 3.8 or later; only standard-library modules are used. Each capture must
already be processed ([flow-extraction](../flow-extraction/README.md) and
[flow-labeling](../flow-labeling/README.md), e.g. with
`scripts/process_capture.sh`) in the [standard data layout](../data/README.md):

```
data/processed/<capture>/flows.csv, flows_labeled.csv,
                         run_metadata.json, validation_report.json, labeling_summary.json
data/interim/<capture>/manifest.csv
data/raw/<capture>/attacklog/*.json
```

## Running

```bash
python3 dataset-unification/build_dataset.py dataset-info/build-config.json
```

`scripts/build_release.sh` runs this and then [dataset-analysis](../dataset-analysis/README.md).
A build of ~2.3 M flows takes about 6 minutes.

## Build config

Paths are relative to the config file.

```json
{
  "name": "cyber-attacks-dataset",
  "data_root": "../data",
  "captures": ["07", "10"],
  "flows_name": "cyber_attacks_flows.csv",
  "labeled_name": "cyber_attacks_flows_labeled.csv",
  "readme": "DATASET_CARD.md",
  "relabel_overrides": "relabel_overrides.csv",
  "anonymization": {
    "ip_map": "../data/anonymization/public_ip_map.csv",
    "keep_public_ips": ["194.149.136.252"]
  },
  "info_dir": "."
}
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Release name; output goes to `<data_root>/release/<name>/`. |
| `data_root` | yes | Root of the standard data layout. |
| `captures` | yes | Capture ids, in output order. |
| `flows_name`, `labeled_name` | no | Output CSV names (default `flows.csv`, `flows_labeled.csv`). |
| `readme` | no | Dataset card copied into the release as `README.md`. |
| `relabel_overrides` | no | Manual label corrections (see below). |
| `anonymization` | no | Pseudonymize public IPs (see below): `ip_map` is the private mapping file, `keep_public_ips` lists public addresses to leave unchanged. |
| `info_dir` | no | Directory that receives a copy of `build_summary.json` and the provenance reports (no CSVs, no attacklog exports), so the release metadata can be versioned. |

The thesis release is configured in [dataset-info/build-config.json](../dataset-info/build-config.json).

## Output

```
data/release/<name>/
  <flows_name>       all flows of all captures, original 186 columns + capture_id
  <labeled_name>     same rows in the same order + capture_id + label (label is the last column)
  README.md          dataset card
  build_summary.json counts per capture and label, applied relabels
  provenance/
    relabel_overrides.csv
    <capture>/run_metadata.json, validation_report.json, labeling_summary.json,
              manifest.csv, attacklog/*.json
```

`capture_id` is the capture's folder name under `data/raw/`. Outputs are
written atomically (temp file + rename), so a failed build never leaves
half-written CSVs behind.

## Integrity checks

The build aborts (it never skips rows) if:

- the captures' headers differ, or a labeled header is not the flow header + `label`;
- any row of `flows_labeled.csv` differs from the same row of `flows.csv`;
- a `flow_id` occurs twice across captures;
- an override matches no flow or several flows, or the matched flow's current
  label is not the override's `old_label`. This catches overrides that went
  stale after upstream re-labeling.

## Relabel overrides

The automatic labeler matches flows to attack records by src IP, dst IP, dst
port and protocol, using the time window first and a tuple fallback second.
Some flows fall through those rules and get a wrong label. The attacker's
full-range port-scan record (ports 1–65535) usually absorbs them, because it
covers every port:

- **Exploit side channels on a port the attacker did not log**, e.g. an
  exploit's connection to a dynamic RMI port or a payload trigger on another
  HTTP port. Relabel them to the exploit whose logged window contains them.
- **Non-attack traffic from an attacker host**, e.g. administrative SSH
  sessions to a target's host system. Relabel them `BENIGN`.

`relabel_overrides.csv` has one row per corrected flow:

| Column | Meaning |
|---|---|
| `capture_id` | Capture of the flow. |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `first_seen_ms` | Identify the flow (`first_seen_ms` = `bidirectional_first_seen_ms`). Unlike `flow_id`, this key does not depend on how the capture was extracted. |
| `old_label` | Label the flow must currently have; the build fails otherwise. |
| `new_label` | Corrected label. |
| `reason` | Why: the evidence that was reviewed. Say so when a label is inferred rather than backed by an attacklog record. |

Overrides apply only to the release; the per-capture datasets keep their
automatic labels.

## Anonymization

With an `anonymization` block in the config, every **public** IP address
(globally routable unicast) is replaced by a pseudonym from the documentation
ranges: RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` for IPv4
(762 addresses) and RFC 3849 `2001:db8::/32` for IPv6. Addresses in
`keep_public_ips` stay as they are.

- **Unchanged:** private (RFC 1918 / ULA), link-local, multicast, loopback
  and other special-purpose addresses, so the lab topology, attacker/target
  roles and labels are untouched. The derived address flags (`dst_is_private`,
  …) remain correct, because a pseudonym is never private either.
- **Rewritten:** `src_ip`, `dst_ip`, `canonical_key` (recomputed from the new
  addresses), IP literals in `requested_server_name`, and every IP-valued
  string in the copied provenance (e.g. the validation reports' top talkers).
  Free text such as user agents is left alone; its dotted numbers are
  version strings (`Chrome/121.0.0.0`), not addresses.
- **Consistent:** the same address always gets the same pseudonym, in both
  CSVs, all captures and every later build. Pseudonyms are drawn at random the
  first time an address is seen and stored in `ip_map`
  (`real_ip,pseudonym`); later builds reuse and extend that file.
- **Private:** `ip_map` is the key that undoes the anonymization. Keep it
  under the git-ignored `data/` root, never copy it into a release, and back
  it up: without it, a rebuild assigns new pseudonyms.

The per-capture datasets in `data/processed/` keep the real addresses; only
the release is anonymized. A build stops if its input already contains
documentation-range addresses, which pseudonyms could collide with.

## Adding a capture

1. Put its pcaps in `data/raw/<id>/pcap/` and its attackers' exports in
   `data/raw/<id>/attacklog/`.
2. `bash scripts/process_capture.sh <id>`
3. Add `<id>` to `captures` in the build config and run `bash scripts/build_release.sh`.
