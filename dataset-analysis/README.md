# Dataset Analysis

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Writes `DATASET_STATISTICS.md`, a statistics report for a dataset release
built by [dataset-unification](../dataset-unification/README.md). Every
number in the report is computed from the release itself, so the report can be
regenerated after every rebuild and never drifts from the data.

## Requirements

Python 3.8+ with pandas and pyarrow (`pip install -r dataset-analysis/requirements.txt`;
the flow-extraction virtual environment already has both). Analysing ~2.3 M
flows peaks at about 8.5 GB of RAM and takes under a minute.

## Running

```bash
python3 dataset-analysis/analyze_dataset.py data/release/cyber-attacks-dataset --info-dir dataset-info
```

The report is written into the release directory. `--info-dir` also copies it
into a second directory, e.g. the repository's `dataset-info/`.
`scripts/build_release.sh` runs the build and this analysis in one go.

The script reads only the release: the labeled CSV, `build_summary.json` and
`provenance/<capture>/` (run metadata, validation report, labeling summary,
pcap manifest, attacklog exports).

## Report contents

| Section | Content |
|---|---|
| 1. At a glance | Flows, attack/benign split, classes, captures, time covered, packets, bytes, hosts, attack records, raw capture size, files. |
| 2. Captures | Per-capture and total: traffic window, pcaps, frames vs. packets in flows, flows, attack share, attackers, targets, stitching. |
| 3. Labels and class balance | Attack vs. benign per capture; classes grouped by technique and by target platform; every class with per-capture counts; class-size bins, imbalance ratio and effective number of classes. |
| 4. Traffic profile per class | Median packets, bytes and duration, p95 duration, share of unanswered flows, TCP accept rate. |
| 5. Attack records, attackers and targets | How each label was assigned (time window, fallback, overrides), per-attacker and per-target tables, records per class, records that matched no flow (with the attackers' notes), known labeling limitations. |
| 6. Flow characteristics | Duration/packet/byte distributions; direction and TCP behaviour per technique. |
| 7. Protocols and applications | Transport protocols, nDPI applications and categories, metadata availability. |
| 8. Ports | Destination ports of attack flows, service ports of benign flows. |
| 9. Hosts and network | Flows between attackers, targets and other hosts; top hosts; subnet pairs. |
| 10. Time | Flows per day and hour; first/last flow of every attack class. |
| 11. Data quality and integrity | Duplicates, impossible values, stitching, capture gaps, missing values. |
| 12. Features (columns) | Column groups, constant columns, identifying columns to keep out of model inputs. |
| 13. Provenance and configuration | Tool versions, extraction and labeling settings per capture, overrides. |

## Label taxonomy

Technique and platform columns are derived from the canonical attack names
of the methodology's attack catalog:

- **Platform** comes from the name prefix: `ms2-` Metasploitable 2, `ms3-`
  Metasploitable 3, `vulnhub-` VulHub. Names without a known prefix (e.g.
  `nmap-full-portscan`) count as *All targets*.
- **Technique** comes from keywords: `-portscan` suffix (pre-exploit service
  scan), `-revshell`, `sqlmap`/`sqli`, `xss`, `cmdinject`, `lfi`, `ssti`,
  `wordlist`, `-dos`, `-enum`, `cve-`/`cnvd-`.

Attack names outside these conventions are reported under *Other*; extend
`TECHNIQUE_RULES` and `PLATFORMS` at the top of the script for a new catalog.
