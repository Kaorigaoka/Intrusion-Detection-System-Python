# `data/` — datasets, models & runtime artifacts

Everything in this folder is **gitignored** — it's either too large for GitHub
(multi-GB datasets) or machine-generated (trained model, database, logs). Only
this README and the `.gitkeep` placeholders are tracked, so the layout survives a
fresh clone.

```
data/
├── datasets/   # raw training CSVs  (CIC-IDS2017 / CIC-UNSW-NB15)  — ~3 GB
├── models/     # isolation_forest.model  +  cic_normal_features.npy
├── runtime/    # ids_data.db  +  ids_alerts.log  (created when the IDS runs)
└── backups/    # *.bak pre-retrain snapshots
```

## How to rebuild the model from scratch

1. **Download a dataset** into `data/datasets/`:
   - **CIC-IDS2017** — https://www.unb.ca/cic/datasets/ids-2017.html
     (the `*.pcap_ISCX.csv` files), or
   - **CIC-UNSW-NB15** CICFlowMeter output as `CICFlowMeter_out.csv`.

2. **Build the benign baseline** (`cic_normal_features.npy`):
   ```bash
   nids_env/bin/python preprocess_cic_ids2017.py
   ```
   It streams the big CSVs in chunks, keeps only `BENIGN` flows, extracts the
   6 features, and writes `data/models/cic_normal_features.npy`.

3. **Train the Isolation Forest** — just run anything that builds a
   `DetectionEngine` (e.g. `sudo python main.py`). If the model file is missing
   but the `.npy` exists, it auto-trains and saves
   `data/models/isolation_forest.model`.

   To force a retrain, delete `data/models/isolation_forest.model` first.
