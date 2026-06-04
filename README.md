# 🛡️ Hybrid Network Intrusion Detection System (NIDS)

A real-time **Hybrid Network Intrusion Detection System** that captures live TCP/IP
traffic and flags malicious activity using **two complementary detection methods**:

1. **Signature-based detection** — fast, rule-based matching for known attack patterns
   (SSH brute-force, port scans, high-rate floods).
2. **ML anomaly detection** — an **Isolation Forest** trained on ~1.6M benign network
   flows that catches *unknown* / zero-day behaviour by spotting deviations from normal.

Every alert is **explained** (which feature deviated and by how much — Explainable AI),
**persisted** (SQLite + JSON log), and **pushed in real time** to Telegram. A
**Streamlit dashboard** visualises alerts, trends, and the ML baseline. Snort alerts are
ingested in parallel so the system works alongside an industry-standard IDS.

> Final-year project. Built in Python with Scapy, scikit-learn, and Streamlit.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔴 **Live capture** | Scapy sniffer on a background thread → bounded packet queue. |
| 🧮 **Per-flow features** | 6 numeric features per flow (size, rates, window, duration). |
| ⚡ **Signature engine** | Rule lambdas for SSH brute-force, port scan, high-rate flood. |
| 🤖 **ML anomaly engine** | Isolation Forest, auto-trains from the benign baseline. |
| 💡 **Explainable AI** | Each anomaly says *which* feature deviated from the baseline. |
| 🌐 **Threat intel** | Optional AbuseIPDB reputation lookup per source IP. |
| 🔔 **Real-time alerts** | SQLite + JSON log + Telegram, with IP whitelisting. |
| 📊 **Dashboard** | Streamlit UI: alert tables, charts, login/sign-up, Snort simulator. |
| 🐍 **Snort ingestion** | Parses Snort 3 `alert.fast` in a parallel thread. |

---

## 🏗️ Architecture

```
                       ┌────────────────────────────────────────────┐
                       │                main.py / ids.py             │
                       │        (IntrusionDetectionSystem)           │
                       └────────────────────────────────────────────┘
                                          │
  ┌────────────────┐   packets   ┌────────────────┐  features  ┌──────────────────┐
  │ PacketCapture  │ ──────────▶ │ TrafficAnalyzer │ ─────────▶ │  DetectionEngine  │
  │ (Scapy sniff)  │   queue     │ (per-flow stats)│            │ signatures + ML   │
  └────────────────┘             └────────────────┘            └──────────────────┘
                                                                          │ threats
                                                                          ▼
  ┌────────────────┐                                            ┌──────────────────┐
  │  SnortParser   │ ── alert.fast ───────────────┐             │   IntelFactory    │
  │ (daemon thread)│                              │             │ (XAI + AbuseIPDB) │
  └────────────────┘                              ▼             └──────────────────┘
                                          ┌──────────────────┐           │ reason
                                          │   AlertSystem    │◀──────────┘
                                          │ SQLite + JSON +  │
                                          │ Telegram + WL    │
                                          └──────────────────┘
                                                   │
                                                   ▼
                                          ┌──────────────────┐
                                          │   dashboard.py   │
                                          │  (Streamlit UI)  │
                                          └──────────────────┘
```

---

## 📁 Project Structure

```
NIDS_PROJECT/
├── main.py                     # Entry point — builds the IDS, handles Ctrl-C
├── ids.py                      # Top-level coordinator + main packet loop
├── config.py                   # Central .env loader (all modules import this)
├── packet_capture.py           # Scapy sniffer → queue (background thread)
├── traffic_analyzer.py         # Per-flow stats → 6-feature dict
├── detection_engine.py         # Signature rules + Isolation Forest
├── intel_factory.py            # Explainable-AI reasons + AbuseIPDB lookup
├── alert_system.py             # Persist + notify (SQLite / JSON / Telegram)
├── snort_parser.py             # Snort 3 alert.fast parser (parallel thread)
├── dashboard.py                # Streamlit dashboard
├── preprocess_cic_ids2017.py   # Build the benign ML baseline (.npy)
├── check_sample.py             # Debug helper (prints baseline shape)
│
├── requirements.txt            # Python dependencies
├── .env.example                # Config template (copy → .env)
├── run_ids.sh                  # Convenience launcher (sudo + venv)
├── false_positive_ips.txt      # IP whitelist (one per line)
│
├── data/                       # ⚠️ gitignored — not on GitHub (see data/README.md)
│   ├── datasets/               #   raw CIC-IDS2017 / CIC-UNSW CSVs (~3 GB)
│   ├── models/                 #   isolation_forest.model, cic_normal_features.npy
│   ├── runtime/                #   ids_data.db, ids_alerts.log (generated)
│   └── backups/                #   pre-retrain .bak files
│
└── docs/
    └── screenshots/            # presentation screenshots
```

---

## 🚀 Quick Start

### 1. Clone & set up

```bash
git clone https://github.com/<your-username>/<repo>.git
cd <repo>

python3 -m venv nids_env
source nids_env/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — add your Telegram bot token / chat id, capture interface, etc.
```

### 3. Provide the ML baseline

The trained model and benign baseline are **not** in the repo (too large).
See [`data/README.md`](data/README.md) to download the dataset and rebuild them:

```bash
nids_env/bin/python preprocess_cic_ids2017.py   # builds data/models/cic_normal_features.npy
# the Isolation Forest auto-trains on first run if the model is absent
```

### 4. Run the IDS (needs root for raw sockets)

```bash
sudo python main.py          # or:  ./run_ids.sh
```

### 5. Run the dashboard (separate terminal, no root)

```bash
streamlit run dashboard.py
```

Default dashboard logins are seeded on first run: `admin`, `analyst`, `viewer`.

---

## 🧠 The ML Model

- **Algorithm:** Isolation Forest (unsupervised anomaly detection).
- **Training data:** ~1.64M **benign** flows from **CIC-UNSW-NB15** (CICFlowMeter output),
  with **CIC-IDS2017** supported as an alternative.
- **Features (order matters — kept in sync across 3 files):**
  `packet_size, packet_rate, byte_rate, window_size, flow_duration, fwd_packet_rate`
- **Threshold:** `ANOMALY_THRESHOLD = -0.55` in `detection_engine.py` (lower = more sensitive).
- **Auto-train:** if `isolation_forest.model` is missing but the `.npy` baseline exists,
  the engine trains a fresh model on first run.

---

## ☁️ Deployment Notes

> **Important:** the *live capture engine cannot run on serverless platforms* (Vercel,
> Netlify, Lambda) — it needs **root + raw sockets + a long-running process**. Those
> hosts run short-lived functions with no privileged network access.

| Component | Where it runs |
|-----------|---------------|
| **IDS capture engine** (`main.py`) | A real machine / VM with root (laptop for the demo, or a VPS). |
| **Streamlit dashboard** (`dashboard.py`) | Locally, **or** publish read-only to **Streamlit Community Cloud**. |

### Publishing the dashboard to Streamlit Community Cloud

1. Push this repo to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) → **New app** → pick this repo,
   main file `dashboard.py`.
3. Add secrets (Telegram token, etc.) in the app's **Secrets** settings (it reads the
   same env var names as `.env`).
4. The dashboard needs a database to display. Either upload a small **demo**
   `ids_data.db` and `cic_normal_features.npy`, or point it at a hosted DB. (The full
   datasets are never needed by the dashboard.)

---

## 🧰 Tech Stack

Python · Scapy · scikit-learn · NumPy · Pandas · SQLite · Streamlit · python-telegram-bot · Snort 3

---

## 📜 License & Disclaimer

Educational / academic project. Run packet capture **only on networks you own or are
authorised to monitor**.
