# ML Evaluation

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Baseline machine-learning and graph-ML experiments on a dataset release. The three Jupyter notebooks are an adaptation of the author's earlier GraphML pipeline for CIC-IDS2017. They keep its models, hyperparameters and experiments, so the results can be set against that dataset. They are committed together with their outputs from the full run on **cyber-attacks-dataset**.

| Notebook | What it does | Output |
|---|---|---|
| `01_data_preparation.ipynb` | Load the release CSV, clean, explore, engineer and select features | `prepared_data/ml_prepared.parquet`, `tl_prepared.parquet`, `metadata.json` |
| `02_standard_ml.ipynb` | Logistic Regression, Random Forest and XGBoost under seven split strategies | Reports, plots, `prepared_data/xgb_baseline_results.npz` |
| `03_graph_ml.ipynb` | GCN edge classifier and label propagation on the IP graph; comparison and majority-vote ensemble with XGBoost | Reports, plots |

## Running

Linux or WSL2, from this directory:

```bash
python3 -m venv ~/graphml-venv
~/graphml-venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu   # or a CUDA build
~/graphml-venv/bin/pip install -r requirements.txt
~/graphml-venv/bin/python -m ipykernel install --user --name graphml
```

Open the notebooks in Jupyter or VS Code with the `graphml` kernel and run them in order. Each notebook starts with a Pydantic configuration cell.

- `01` reads the release from the [data root](../data/README.md), `../data/release/cyber-attacks-dataset/cyber_attacks_flows_labeled.csv`. Override this with the `CYBER_ATTACKS_CSV` environment variable or `DataPathsConfig.dataset_csv`.
- For a quick trial run, set `DataPrepConfig.sample_rows` (e.g. `200_000`). `02` and `03` then run on that stratified sample.
- `prepared_data/` is generated and not versioned.

## Adaptations to this dataset

| Topic | CIC-IDS2017 notebooks | Here |
|---|---|---|
| Input | Two CSV folders (MachineLearningCVE, TrafficLabelling) | One release CSV. `ml_prepared` = features + labels, deduplicated; `tl_prepared` = every flow + `src_ip`, `dst_ip`, `src_port`, `bidirectional_first_seen_ms`, `capture_id` |
| Features | 79 CICFlowMeter columns | NFStream statistics, TCP flags, integer-coded nDPI application/category, derived rates and ratios, address-class flags, first-20-packet sequence (`splt_*`). **Excluded:** identifiers (flow ids, IPs, MACs, `src_port`), absolute times, `capture_id`, stitching provenance, free text (SNI, user agent, TLS fingerprints). See the [data dictionary](../flow-extraction/DATA_DICTIONARY.md) |
| Missing values | Rows dropped | Values NFStream leaves undefined by design (`splt_*` past the packet count, rates of 0 ms flows, ratios with an empty reverse direction) are filled with −1 |
| Constant / redundant columns | Hand-written lists | Detected from the data (zero variance; \|r\| = 1) |
| Multi-class target | 15 labels | Attack technique (13 classes, default) or attack name (54); classes with fewer than 10 flows are left out of the stratified split |
| Correlation selection | Spearman vs. label code, threshold 0.3 | Spearman vs. the binary attack indicator, threshold 0.3 (keeps 90 of 132 features) |
| Day-based splits | Mon–Thu / Fri, per day | Cross-capture (train 07 / test 10), per capture |
| Balancing | Undersample BENIGN | Undersample the majority class (here ATTACK, ~80 % of flows) |
| Graph comparison | XGBoost and graph models evaluated on different test sets | Both notebooks build the identical per-label chronological split, so the error analysis and ensemble run on the same flows |
| Hardware | cuML on a large GPU | scikit-learn on the CPU when cuML is absent; XGBoost on CUDA if available (CPU fallback); GCN edge tensors stay in RAM when they do not fit the GPU |

## Results (cyber-attacks-dataset, full run)

2,263,421 flows; 629,679 after removing duplicate feature vectors. 90 correlation-selected features in `02`, all 132 features in `03`. Macro F1 on the test sets:

| Experiment (`02`) | Logistic Regression | Random Forest | XGBoost |
|---|---|---|---|
| Multi-class (attack technique, 10 classes with ≥ 10 flows) | 0.652 | 0.827 | 0.839 |
| Binary, random 70/30 | 0.968 | 0.972 | 0.973 |
| Balanced binary, random 70/30 | 0.948 | 0.953 | 0.953 |
| Cross-capture (train 07, test 10) | 0.991 | 0.999 | 0.999 |
| Capture-stratified 70/30 | 0.967 | 0.965 | 0.972 |
| Chronological 70/15/15 per capture | 0.992 | 0.999 | 0.999 |
| Per-label chronological 70/15/15 | 0.996 | 0.999 | 0.999 |

| Per-label chronological test set (`03`, 94,460 flows) | Macro F1 |
|---|---|
| XGBoost (from `02`) | 0.9993 |
| GCN edge classifier | 0.9993 |
| Label propagation | 0.1295 |
| Majority vote of the three | 0.9995 |

Observations:

- **Easy separation.** The full-range port scan (`nmap-full-portscan`) makes up 78 % of the deduplicated flows, and the benign traffic is laboratory background. Both are easy to tell apart. Even the cross-capture split stays at 0.999. The difficult classes are the rare ones, e.g. single-port service scans (F1 0.49) and OS command injection (4 test flows).
- **Unlogged scan labelled BENIGN.** On 2026-07-16 (06:53–08:28 UTC), `192.168.71.202` probed 6,973 ports of `192.168.77.226` (7,136 flows). Neither host appears in any attacklog record, so the flows carry the BENIGN label. The models classify them as attacks, and they account for 1,847 of the 1,849 benign test flows predicted as attacks in the random binary split (benign recall ≈ 0.91 on random splits, ≈ 1.0 on time-ordered ones).
- **Label propagation needs known IPs.** It labels flows from the reputation of their endpoints in the training set. The per-label chronological test set is 97 % capture-10 attacks, whose attackers (`.12`, `.205`) barely occur in training and whose targets were mostly benign there. Label propagation therefore predicts BENIGN for almost all of them. XGBoost and the GCN use the flow features and are unaffected.
- **Runtime.** On an i7-11370H with 32 GB RAM and a GeForce MX450 under WSL2 (scikit-learn on the CPU, XGBoost on the GPU, CPU PyTorch): 1.0, 12.0 and 3.0 min for the three notebooks. Two-thirds of `02` is the CPU Logistic Regression; `ModelHyperparamsConfig.run_models` can leave it out.
- **Reproducibility.** The GCN training is not seeded, so its scores vary in the last digits between runs; all other results are reproducible.
