# A Reproducible Methodology for Generating Modern Intrusion Detection Datasets

Implementation components accompanying the master thesis by **Jovan Simonoski**. This repository brings methodology documentation, laboratory automation, attack execution recording, flow extraction, flow labelling, dataset assembly and dataset analysis into one place, together with the metadata of the resulting dataset.

## Components

| Directory | Purpose |
| --- | --- |
| [methodology](methodology/README.md) | Document the experimental methodology, attack scenarios, participant instructions, and infrastructure. |
| [ansible-playbook](ansible-playbook/README.md) | Configure laboratory networking, hostnames, time synchronisation, and centralised log shipping. |
| [attacklog](attacklog/README.md) | Record attack execution metadata and export it as JSON or CSV. |
| [flow-extraction](flow-extraction/README.md) | Extract and consolidate bidirectional flows from the packet captures of one capture, validate the output, and export CSV. Includes the [data dictionary](flow-extraction/DATA_DICTIONARY.md). |
| [flow-labeling](flow-labeling/README.md) | Attribute flow records to documented executions and produce a labelled CSV and summary. |
| [dataset-unification](dataset-unification/README.md) | Combine the labelled flows of several captures into one release, apply reviewed label corrections, pseudonymize public IP addresses, and collect provenance. |
| [dataset-analysis](dataset-analysis/README.md) | Generate the statistics report of a release. |
| [ml-evaluation](ml-evaluation/README.md) | Baseline machine-learning and graph-ML experiments on a release (Jupyter notebooks with results). |
| [scripts](scripts/README.md) | Run the whole pipeline for a capture, or build a release, with one command. |
| [dataset-info](dataset-info/README.md) | Metadata of the thesis dataset: dataset card, statistics, build configuration, label corrections, provenance. |
| [data](data/README.md) | Local data root with a fixed layout (raw → interim → processed → release). Not versioned except for its README. |

## Pipeline

```
data/raw/<capture>/pcap/  ──► flow-extraction ──► data/processed/<capture>/flows.csv
                                                              │
data/raw/<capture>/attacklog/ ───────────────► flow-labeling ─┴─► flows_labeled.csv
                                                                        │ (every capture)
dataset-info/build-config.json ──► dataset-unification ◄────────────────┘
                                          │
                                          ▼
                       data/release/<name>/  ──► dataset-analysis ──► DATASET_STATISTICS.md
                                │
                                └──────────────► ml-evaluation ────► baseline ML / graph-ML results
```

## Getting started

```bash
git clone https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets.git
cd reproducible-methodology-for-generating-ids-datasets

# Linux or WSL2: one virtual environment serves every Python component
python3 -m venv ~/ids-venv
~/ids-venv/bin/pip install -r flow-extraction/requirements.txt
export PYTHON=~/ids-venv/bin/python
```

Place each capture's pcaps in `data/raw/<capture>/pcap/` and its attackers' JSON exports in `data/raw/<capture>/attacklog/` (see [data/README.md](data/README.md)), then:

```bash
bash scripts/process_capture.sh 07        # pcaps -> labelled flows of one capture
bash scripts/process_capture.sh 10
bash scripts/build_release.sh             # captures in dataset-info/build-config.json -> release + statistics
```

All commands run from the repository root. Each component's README documents its options for running the steps individually.

## Workflow

1. Prepare the laboratory and observation services using the Ansible playbooks.
2. Record the start and end of each attack with attacklog while network traffic is captured by the laboratory observation infrastructure.
3. Export the execution records as JSON and collect the packet captures; store them per capture under `data/raw/`.
4. Process each capture: extract, consolidate, and validate the flows, export them to CSV, and label them with that capture's execution records (`scripts/process_capture.sh`).
5. Review the labelling summary and record any necessary flow-level corrections in the release's relabel overrides.
6. Build the release from all processed captures and generate its statistics (`scripts/build_release.sh`); the release metadata is mirrored into `dataset-info/`.
7. Evaluate the release with baseline machine-learning and graph-ML models (`ml-evaluation/` notebooks).

Packet capture is performed by the laboratory infrastructure; the extraction component consumes existing captures. Raw traffic, execution exports, virtual-machine images, and generated datasets are supplied separately. Laboratory addresses must be adapted to the deployment environment.

## Repository organisation

The components are ordinary directories in a single Git repository; no submodule initialisation is required. This repository starts from a snapshot of the component repositories. Their earlier Git histories remain in the original repositories.
