"""
preprocess_cic_ids2017.py — Build the normal-traffic baseline (.npy) for the
IsolationForest from CIC flow CSVs.

Supports two CSV layouts:
  • CIC-IDS2017  (*.pcap_ISCX.csv)      — label column " Label", "BENIGN"
  • CIC-UNSW-NB15 via CICFlowMeter      — label column "Label",  "Benign"

Only the 6 features used by the live pipeline are read (via usecols), and big
files are streamed in chunks so the 1.9 GB CICFlowMeter_out.csv doesn't have to
fit in RAM all at once.
"""

import os
import logging
import numpy as np
import pandas as pd

from config import NORMAL_DATA_PATH

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

CHUNK_SIZE = 250_000

# Canonical 6 features, in the order the rest of the pipeline expects
# (traffic_analyzer + detection_engine + intel_factory).
#   Packet Length Mean     → packet_size
#   Flow Packets/s         → packet_rate
#   Flow Bytes/s           → byte_rate
#   Init_Win_bytes_forward → window_size
#   Flow Duration          → flow_duration
#   Fwd Packets/s          → fwd_packet_rate
SELECTED_FEATURES = [
    "Packet Length Mean",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Init_Win_bytes_forward",
    "Flow Duration",
    "Fwd Packets/s",
]

# Alternative column names seen across CICFlowMeter / dataset versions.
# The first match (against whitespace-stripped headers) wins.
FEATURE_ALIASES = {
    "Init_Win_bytes_forward": [
        "Init_Win_bytes_forward",   # CIC-IDS2017
        "FWD Init Win Bytes",       # CIC-UNSW CICFlowMeter
        "Init Fwd Win Bytes",
    ],
    "Fwd Packets/s": ["Fwd Packets/s", "Fwd Packet/s"],
}

# Raw datasets live under data/datasets/ (gitignored — too large for GitHub).
DATASETS_DIR = "data/datasets"

# Default inputs. The large CIC-UNSW file is preferred if present.
CIC_UNSW_FILE = os.path.join(DATASETS_DIR, "CICFlowMeter_out.csv")
CIC_IDS2017_FILES = [
    os.path.join(DATASETS_DIR, f) for f in [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv",
    ]
]


def _resolve_columns(path: str):
    """Read just the header and map each desired feature to the actual column
    name present in this file. Returns (resolved, label_col, wanted_set)."""
    header = pd.read_csv(path, nrows=0)
    cols = [c.strip() for c in header.columns]

    label_col = next((c for c in cols if c.lower() == "label"), None)
    if label_col is None:
        raise KeyError(f"{path}: no 'Label' column found.")

    resolved = {}
    for feat in SELECTED_FEATURES:
        candidates = FEATURE_ALIASES.get(feat, [feat])
        match = next((c for c in candidates if c in cols), None)
        if match is None:
            raise KeyError(f"{path}: feature '{feat}' not found (tried {candidates}).")
        resolved[feat] = match

    wanted = {resolved[f] for f in SELECTED_FEATURES} | {label_col}
    return resolved, label_col, wanted


def _extract_benign_features(path: str) -> np.ndarray:
    """Stream one CSV in chunks, keeping only BENIGN flows and the 6 features."""
    resolved, label_col, wanted = _resolve_columns(path)
    logger.info("%s → feature columns: %s", os.path.basename(path),
                {f: resolved[f] for f in SELECTED_FEATURES})

    ordered_cols = [resolved[f] for f in SELECTED_FEATURES]
    arrays = []
    total_benign = 0

    reader = pd.read_csv(
        path,
        usecols=lambda c: c.strip() in wanted,   # strip handles " Label" etc.
        chunksize=CHUNK_SIZE,
        low_memory=False,
    )
    for chunk in reader:
        chunk.columns = chunk.columns.str.strip()
        benign = chunk[chunk[label_col].astype(str).str.strip().str.upper() == "BENIGN"]
        if benign.empty:
            continue
        total_benign += len(benign)

        feats = benign[ordered_cols].apply(pd.to_numeric, errors="coerce")
        # CICFlowMeter / CIC-IDS2017 store Flow Duration in microseconds, but the
        # live traffic_analyzer measures flow_duration in seconds. Convert here so
        # the model trains on the same units it sees at inference time. (The /s
        # rate features are already per-second, so they need no scaling.)
        fd_src = resolved["Flow Duration"]
        feats[fd_src] = feats[fd_src] / 1_000_000.0
        feats = feats.replace([np.inf, -np.inf], np.nan).dropna().drop_duplicates()
        if not feats.empty:
            arrays.append(feats.values.astype(np.float32))

    logger.info("%s → %d BENIGN flows, %d clean feature rows",
                os.path.basename(path), total_benign,
                sum(a.shape[0] for a in arrays))

    if not arrays:
        return np.empty((0, len(SELECTED_FEATURES)), dtype=np.float32)
    return np.concatenate(arrays, axis=0)


def preprocess(csv_files: list[str], output_file: str = NORMAL_DATA_PATH) -> np.ndarray:
    logger.info("Building normal baseline from %d file(s)...", len(csv_files))

    parts = []
    for path in csv_files:
        if not os.path.exists(path):
            logger.warning("File not found, skipping: %s", path)
            continue
        logger.info("Processing %s ...", path)
        parts.append(_extract_benign_features(path))

    parts = [p for p in parts if p.shape[0] > 0]
    if not parts:
        raise ValueError("No BENIGN samples extracted from any input file!")

    X_normal = np.concatenate(parts, axis=0)
    np.save(output_file, X_normal)
    logger.info("✅ Saved %d normal samples to %s (shape: %s)",
                X_normal.shape[0], output_file, X_normal.shape)
    return X_normal


# Backwards-compatible alias (older callers / docs use this name).
preprocess_cic_ids2017 = preprocess


if __name__ == "__main__":
    if os.path.exists(CIC_UNSW_FILE):
        inputs = [CIC_UNSW_FILE]
        logger.info("Using CIC-UNSW dataset: %s", CIC_UNSW_FILE)
    else:
        inputs = [f for f in CIC_IDS2017_FILES if os.path.exists(f)]
        logger.info("CIC-UNSW file not found; using %d CIC-IDS2017 file(s).", len(inputs))

    if not inputs:
        logger.error("No input CSVs found. Place CICFlowMeter_out.csv (or the "
                     "CIC-IDS2017 *.pcap_ISCX.csv files) in this directory.")
    else:
        try:
            preprocess(inputs)
            logger.info("Preprocessing completed successfully!")
        except Exception as e:
            logger.error("Preprocessing failed: %s", e)
