# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

Hybrid Network Intrusion Detection System (NIDS) — final year project.
Live TCP/IP packet capture → feature extraction → dual detection
(signature rules + ML anomaly) → alerts (SQLite + JSON log + Telegram).
Plus a Streamlit dashboard for viewing alerts. Snort alerts ingested in parallel.

## Run

```bash
# Capture needs root (raw sockets)
sudo python main.py          # or: ./run_ids.sh

# Dashboard (separate terminal, no root)
streamlit run dashboard.py
```

All config from `.env` (copy `.env.example` → `.env`). No hardcoded tokens/IPs.
Virtualenv lives in `nids_env/`. Install deps: `pip install -r requirements.txt`.

> The venv is **not relocatable** — its shebangs/activate scripts hardcode the
> absolute project path. If the project folder is moved/renamed, either run via
> `nids_env/bin/python` (resolves site-packages by location) or recreate the venv.
> `run_ids.sh` calls `sudo nids_env/bin/python main.py` so it survives this.

## Deployment

The dashboard is exposed publicly via a **Cloudflare Tunnel** — not traditional
hosting. There is no cloud server and no port forwarding; the whole system stays
local. Streamlit runs on `localhost:8501` and the tunnel proxies it.

- Public URL: <https://ids-dha-dashboard.app>
- Tunnel name: `my-tunnel`
- Tunnel config: `/home/kali/.cloudflared/config.yml`

To run with public access (two terminals):

```bash
# Terminal 1 — dashboard (binds localhost:8501)
streamlit run dashboard.py

# Terminal 2 — expose it via Cloudflare
cloudflared tunnel run my-tunnel
```

Because the machine must stay local, the IDS capture (`main.py`) and the tunnel
both run on this host. The tunnel only fronts the dashboard, not the packet
capture.

## Architecture

Pipeline orchestrated by `ids.py` (`IntrusionDetectionSystem`):

```
PacketCapture   → packet_queue (Scapy sniff, daemon thread, bounded 10k queue)
TrafficAnalyzer → feature dict  (per-flow stats, 5s flow timeout)
DetectionEngine → threat list   (signature rules + IsolationForest anomaly)
IntelFactory    → reason string (XAI: which feature deviated from baseline)
AlertSystem     → SQLite + JSON log + Telegram (whitelist filtering)

SnortParser runs independent daemon thread → tails alert.fast → AlertSystem
```

| File | Role |
|------|------|
| `main.py` | Entry point. Builds IDS, handles Ctrl-C. |
| `ids.py` | Top-level coordinator + main packet loop. |
| `config.py` | Central `.env` loader. All modules import config, never `os.getenv` directly. |
| `packet_capture.py` | Scapy sniffer in background thread → queue. TCP/IP only. |
| `traffic_analyzer.py` | Per-flow stats → 10-key feature dict. Flow key = sorted (ip,port) pair. |
| `detection_engine.py` | Signature rules (dict of lambdas) + IsolationForest. 8s per-flow cooldown. |
| `intel_factory.py` | XAI explanations + AbuseIPDB lookup. Baseline = mean of normal data. |
| `alert_system.py` | Persist + notify. Filters sensor IPs and whitelisted IPs. |
| `snort_parser.py` | Regex parser for Snort 3 alert.fast, with fallback parser. |
| `dashboard.py` | Streamlit UI: alert tables, charts, login + sign-up, Snort simulator. |
| `preprocess_cic_ids2017.py` | Build `cic_normal_features.npy` from BENIGN flows (CIC-UNSW CICFlowMeter or CIC-IDS2017). |
| `check_sample.py` | Debug: print shape of saved feature array. |

## ML model

- **IsolationForest**, trained on BENIGN flows. Current baseline =
  **CIC-UNSW-NB15** via `CICFlowMeter_out.csv` (~1.64M normal samples).
- Auto-trains on first run if `isolation_forest.model` absent but
  `cic_normal_features.npy` present (`DetectionEngine._auto_train`).
- `ANOMALY_THRESHOLD = -0.55` in `detection_engine.py` (lower = more sensitive).
  Tuned against an older baseline — re-check if the training data changes.
- To retrain: delete `isolation_forest.model` and run anything that builds a
  `DetectionEngine`, or `nids_env/bin/python preprocess_cic_ids2017.py` first to
  rebuild the `.npy`.

### Feature order — keep in sync across 3 places

`traffic_analyzer.py`, `detection_engine.py` (`_run_anomaly_check` vector),
and `intel_factory.py` (`FEATURE_NAMES`) must agree on the 6-feature order:

```
packet_size, packet_rate, byte_rate, window_size, flow_duration, fwd_packet_rate
```

`preprocess_cic_ids2017.py` maps CSV columns to these (handles both CIC-UNSW
CICFlowMeter and CIC-IDS2017 layouts via `FEATURE_ALIASES`; e.g. window_size =
`FWD Init Win Bytes` or `Init_Win_bytes_forward`). It streams big files in
chunks reading only the needed columns, filters BENIGN case-insensitively, and
**converts `Flow Duration` from microseconds → seconds** to match the live
`traffic_analyzer` (which measures seconds). The /s rate features are already
per-second and need no scaling.
All 3 inference files + the preprocessor now agree on all 6 keys.
If adding/removing a feature, update all 4 AND retrain the model.

## Signature rules

Defined in `DetectionEngine._build_signature_rules` as lambdas over the feature dict:
`ssh_brute_force` (port 22 + high pkt rate), `high_rate_flood`, `port_scan`.

## Conventions

- Config only via `config.py` / `.env`. Never hardcode tokens or IPs.
- Long-running work runs in daemon threads; stop via `threading.Event`.
- Alerts dedup'd by per-flow cooldown (8s in engine, flow timeout 5s in analyzer).
- DB schema (`alerts` table) duplicated in `alert_system.py` and `dashboard.py` —
  change both if altering columns. The `features` column (JSON of the 6-feature
  vector) is added via `alert_system.ensure_features_column()` (migration for
  older DBs); `ids.py` attaches it to anomaly threats so the XAI tab shows real
  per-anomaly deviations (older/Snort alerts have no vector → graceful fallback).
- Dashboard auth is **DB-backed** (`users` table in the same SQLite DB), seeded
  with admin/analyst/viewer on first run. Sign-up creates `viewer` accounts.
- Whitelist: `false_positive_ips.txt` (one IP per line) + `SENSOR_IPS` from `.env`.

## Data / artifacts (not source)

All non-source data lives under `data/` (gitignored — see `data/README.md`):

```
data/datasets/   *.pcap_ISCX.csv (CIC-IDS2017), CICFlowMeter_out.csv (CIC-UNSW, ~1.9GB)
data/models/     cic_normal_features.npy, isolation_forest.model
data/runtime/    ids_data.db, ids_alerts.log*  (generated at run time)
data/backups/    *.bak pre-retrain backups
```

Paths are set in `config.py` (overridable via `.env`): `MODEL_PATH`,
`NORMAL_DATA_PATH`, `DB_PATH`, `LOG_FILE` all default into `data/`. The
preprocessor reads CSVs from `data/datasets/` (`DATASETS_DIR`). Don't edit these
by hand. Only `.py` source, `requirements.txt`, `.env.example`, README, and the
`data/**/.gitkeep` placeholders are tracked in Git.
