# A Reproducible Methodology for Generating Modern Intrusion Detection Datasets

Implementation components accompanying the master thesis by **Jovan Simonoski**. This repository brings laboratory automation, attack execution recording, flow extraction, and flow labelling into one place.

## Components

| Directory | Purpose |
| --- | --- |
| [ansible-playbook](ansible-playbook/README.md) | Configure laboratory networking, hostnames, time synchronisation, and centralised log shipping. |
| [attacklog](attacklog/README.md) | Record attack execution metadata and export it as JSON or CSV. |
| [flow-extraction](flow-extraction/README.md) | Extract and consolidate bidirectional flows from packet captures, validate the output, and export CSV. |
| [flow-labeling](flow-labeling/README.md) | Attribute flow records to documented executions and produce a labelled CSV and summary. |

## Getting started

```bash
git clone https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets.git
cd reproducible-methodology-for-generating-ids-datasets
```

Follow each component's README for its requirements and commands. Commands in the Ansible and extraction READMEs run from their component directories.

## Workflow

1. Prepare the laboratory and observation services using the Ansible playbooks.
2. Record the start and end of each attack with attacklog while network traffic is captured by the laboratory observation infrastructure.
3. Export the execution records as JSON and collect the packet captures.
4. Extract, consolidate, and validate the flows, then export the consolidated dataset to CSV.
5. Run flow labelling with the flow CSV and JSON execution records, retaining the resulting dataset and summary alongside their inputs.

Packet capture is performed by the laboratory infrastructure; the extraction component consumes existing captures. Raw traffic, execution exports, virtual-machine images, and generated datasets are supplied separately. Laboratory addresses and paths must be adapted to the deployment environment.

## Repository organisation

The four components are ordinary directories in a single Git repository; no submodule initialisation is required. This repository starts from a snapshot of the component repositories. Their earlier Git histories remain in the original repositories.