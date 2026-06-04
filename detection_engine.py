"""
detection_engine.py — Tuned for faster response and less repeated alerts
"""

import logging
import os
from typing import Optional
import time

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from config import MODEL_PATH, NORMAL_DATA_PATH

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = -0.55   # Slightly less sensitive

class DetectionEngine:
    def __init__(self, model_path: str = MODEL_PATH, normal_data_path: str = NORMAL_DATA_PATH):
        self.model_path = model_path
        self.normal_data_path = normal_data_path
        self.model_loaded = False
        self.last_alert_time = {}   # Per flow cooldown

        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
        self.signature_rules = self._build_signature_rules()

        if os.path.exists(self.model_path):
            self._load_model()
        elif os.path.exists(self.normal_data_path):
            self._auto_train()

    def _build_signature_rules(self):
        return {
            "ssh_brute_force": {
                "condition": lambda f: f.get("dst_port") == 22 and f.get("packet_rate", 0) > 60
            },
            "high_rate_flood": {
                "condition": lambda f: f.get("packet_rate", 0) > 450 and f.get("flow_duration", 0) < 4
            },
            "port_scan": {
                "condition": lambda f: f.get("packet_size", 0) < 100 and f.get("packet_rate", 0) > 200
            },
        }

    def detect_threats(self, features: dict) -> list[dict]:
        flow_key = (features.get("src_ip"), features.get("dst_ip"), features.get("dst_port"))
        current_time = time.time()

        # Cooldown: max 1 alert per flow every 8 seconds
        if flow_key in self.last_alert_time and current_time - self.last_alert_time[flow_key] < 8:
            return []

        threats = []
        threats.extend(self._run_signature_checks(features))
        threats.extend(self._run_anomaly_check(features))

        if threats:
            self.last_alert_time[flow_key] = current_time

        return threats

    def _run_signature_checks(self, features: dict) -> list[dict]:
        threats = []
        for name, rule in self.signature_rules.items():
            try:
                if rule["condition"](features):
                    threats.append({
                        "type": "signature",
                        "source": "engine",
                        "rule": name,
                        "confidence": 0.95,
                    })
            except:
                pass
        return threats

    def _run_anomaly_check(self, features: dict) -> list[dict]:
        if not self.model_loaded:
            return []

        try:
            vec = np.array([[
                features.get("packet_size", 0),
                features.get("packet_rate", 0),
                features.get("byte_rate", 0),
                features.get("window_size", 0),
                features.get("flow_duration", 1),
                features.get("fwd_packet_rate", 0),
            ]])

            score = float(self.anomaly_detector.score_samples(vec)[0])

            if score < ANOMALY_THRESHOLD:
                return [{
                    "type": "anomaly",
                    "source": "engine",
                    "rule": "isolation_forest",
                    "score": score,
                    "confidence": min(0.98, abs(score) * 1.3),
                }]
        except Exception as e:
            logger.warning("Anomaly detection error: %s", e)
        return []

    def _load_model(self):
        try:
            self.anomaly_detector = joblib.load(self.model_path)
            self.model_loaded = True
            logger.info("✅ IsolationForest model loaded")
        except Exception as e:
            logger.error("Failed to load model: %s", e)

    def _auto_train(self):
        try:
            X = np.load(self.normal_data_path)
            logger.info("Training on %d normal samples...", X.shape[0])
            self.anomaly_detector.fit(X)
            joblib.dump(self.anomaly_detector, self.model_path)
            self.model_loaded = True
            logger.info("✅ New model trained and saved!")
            return True
        except Exception as e:
            logger.error("Training failed: %s", e)
            return False
