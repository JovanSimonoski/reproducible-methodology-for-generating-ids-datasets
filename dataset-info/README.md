# Dataset Info

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Metadata of the thesis dataset, **cyber-attacks-dataset**, versioned
together with the code that produced it. The data itself (pcaps, CSVs) is
too large for git and lives in the local [data root](../data/README.md) under
`data/release/cyber-attacks-dataset/`.

| File | Kind | Content |
|---|---|---|
| [DATASET_CARD.md](DATASET_CARD.md) | written by hand | What the dataset is, files, captures, columns, labels, caveats. Copied into the release as its `README.md`. |
| [DATASET_STATISTICS.md](DATASET_STATISTICS.md) | generated | Full statistics report (13 sections) by [dataset-analysis](../dataset-analysis/README.md). |
| [build-config.json](build-config.json) | written by hand | Release definition for [dataset-unification](../dataset-unification/README.md): captures, file names, overrides, public-IP anonymization (keeping the NTP server `194.149.136.252`). |
| [relabel_overrides.csv](relabel_overrides.csv) | written by hand | The 16 reviewed, flow-level label corrections with their evidence. |
| [build_summary.json](build_summary.json) | generated | Per-capture and per-label counts, applied relabels. |
| [provenance/](provenance) | generated | Per capture: extraction run metadata, validation report, labeling summary, pcap manifest. |

Generated files are overwritten by every build; edit the hand-written ones.
Everything here comes from the anonymized release: public IPs appear as
documentation-range pseudonyms. The private mapping lives only in
`data/anonymization/public_ip_map.csv`, never here.
The attackers' attacklog exports are part of the release (`provenance/<capture>/attacklog/`)
but are not mirrored here, like the other execution exports and raw data.

## Rebuilding

```bash
export PYTHON=~/ids-venv/bin/python
bash scripts/build_release.sh          # uses dataset-info/build-config.json
```

This needs both captures processed (`bash scripts/process_capture.sh 07` and
`... 10`, see [scripts](../scripts/README.md)).
