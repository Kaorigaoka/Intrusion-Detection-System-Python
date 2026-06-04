"""
intel_factory.py — Updated XAI for new feature set
"""

import logging
import numpy as np
import requests
from typing import Optional

from config import ABUSE_IP_KEY, NORMAL_DATA_PATH

logger = logging.getLogger(__name__)

# Must match the order in traffic_analyzer + preprocess
FEATURE_NAMES = [
    "packet_size", "packet_rate", "byte_rate", 
    "window_size", "flow_duration", "fwd_packet_rate"
]
FEATURE_LABELS = [
    "Packet Size", "Pkt Rate", "Byte Rate", 
    "Win Size", "Flow Duration", "Fwd Pkt Rate"
]


class IntelFactory:
    def __init__(self, abuse_ip_key=ABUSE_IP_KEY, normal_data_path=NORMAL_DATA_PATH):
        self.abuse_ip_key = abuse_ip_key
        self.normal_data_path = normal_data_path
        self._baseline_means = None
        self._load_baseline()

    def get_ip_reputation(self, ip: str):
        if not self.abuse_ip_key:
            return "No API key"
        # ... (keep your existing AbuseIPDB code)
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": self.abuse_ip_key}
            resp = requests.get(url, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=4)
            if resp.ok:
                return resp.json()["data"]["abuseConfidenceScore"]
        except:
            pass
        return 0

    def explain_anomaly(self, features: dict) -> str:
        if self._baseline_means is None:
            return "Anomaly detected"
        current = [features.get(k, 0) for k in FEATURE_NAMES]
        devs = self._compute_deviations(current)
        idx = int(np.argmax(np.abs(devs)))
        return f"High {FEATURE_LABELS[idx]} ({abs(devs[idx]):.1f}% above baseline)"

    def get_feature_deviations(self, features: dict):
        if self._baseline_means is None:
            return []
        current = [features.get(k, 0) for k in FEATURE_NAMES]
        devs = self._compute_deviations(current)
        return [
            {
                "label": FEATURE_LABELS[i],
                "current": float(current[i]),
                "baseline": float(self._baseline_means[i]),
                "deviation_pct": float(devs[i])
            }
            for i in range(len(FEATURE_NAMES))
        ]

    def _load_baseline(self):
        try:
            data = np.load(self.normal_data_path)
            self._baseline_means = np.mean(data, axis=0)
            logger.info("Baseline loaded (%d samples)", data.shape[0])
        except Exception as e:
            logger.warning("Failed to load baseline: %s", e)

    def _compute_deviations(self, current_vals):
        return ((np.array(current_vals) - self._baseline_means) 
                / (self._baseline_means + 1e-6)) * 100
