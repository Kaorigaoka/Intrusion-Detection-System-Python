"""
alert_system.py — Updated with Source + Destination IP Whitelist
"""

import json
import logging
import sqlite3
import threading
import os
from datetime import datetime

import requests

from config import (
    DB_PATH,
    LOG_FILE,
    SENSOR_IPS,
    TELEGRAM_CHAT_ID,
    TELEGRAM_TOKEN,
)

logger = logging.getLogger(__name__)

FP_IPS_FILE = "false_positive_ips.txt"

# ====================== WHITELIST HELPER ======================
def load_false_positive_ips() -> set:
    """Load whitelisted IPs"""
    try:
        if not os.path.exists(FP_IPS_FILE):
            return set()
        with open(FP_IPS_FILE, "r") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        logger.warning("Failed to load false_positive_ips.txt: %s", e)
        return set()


_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'engine',
    rule        TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    confidence  REAL,
    reason      TEXT,
    features    TEXT
)
"""


def ensure_features_column(conn) -> None:
    """Add the `features` column to pre-existing alerts tables (migration).

    CREATE TABLE IF NOT EXISTS won't add columns to a table that already
    exists, so older ids_data.db files need this one-off ALTER. Kept module
    level so dashboard.py can reuse the exact same migration.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    if "features" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN features TEXT")
        conn.commit()

class AlertSystem:
    def __init__(
        self,
        db_path: str           = DB_PATH,
        log_file: str          = LOG_FILE,
        telegram_token: str    = TELEGRAM_TOKEN,
        telegram_chat_id: str  = TELEGRAM_CHAT_ID,
        sensor_ips: list       = None,
    ):
        self.log_file         = log_file
        self.telegram_token   = telegram_token.strip() if telegram_token else ""
        self.telegram_chat_id = telegram_chat_id.strip() if telegram_chat_id else ""

        if sensor_ips is not None:
            self.sensor_ips = set(sensor_ips)
        else:
            self.sensor_ips = set(SENSOR_IPS)

        # Load whitelist
        self.false_positive_ips = load_false_positive_ips()

        # SQLite setup. The connection is shared across the main detection
        # loop and the SnortParser daemon thread, so every write must be
        # serialized with this lock and use its own short-lived cursor —
        # sharing one cursor across threads raises "Recursive use of cursors"
        # and can segfault the process under concurrent inserts.
        self._db_lock = threading.Lock()
        self.conn     = sqlite3.connect(db_path, check_same_thread=False)
        with self._db_lock:
            cur = self.conn.cursor()
            cur.execute(_CREATE_TABLE_SQL)
            self.conn.commit()
            cur.close()
            ensure_features_column(self.conn)

        # Backup logger
        self._file_logger = logging.getLogger("IDS.AlertFile")
        self._file_logger.setLevel(logging.INFO)
        if not self._file_logger.handlers:
            handler = logging.FileHandler(log_file + ".backup.log")
            handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
            self._file_logger.addHandler(handler)

        logger.info(f"AlertSystem initialized. Whitelisted IPs: {len(self.false_positive_ips)}")

    def generate_alert(self, threat: dict, packet_info: dict) -> None:
        """
        Main entry point - Now filters Source AND Destination IP
        """
        src_ip = packet_info.get("source_ip")
        dst_ip = packet_info.get("destination_ip")

        # Skip sensor IPs
        if src_ip in self.sensor_ips or dst_ip in self.sensor_ips:
            logger.debug("Skipped - sensor IP involved")
            return

        # Skip whitelisted IPs (Source OR Destination)
        if src_ip in self.false_positive_ips or dst_ip in self.false_positive_ips:
            logger.debug(f"Skipped - whitelisted IP: {src_ip} <-> {dst_ip}")
            return

        # If not skipped → generate alert
        self._save_to_db(threat, packet_info)
        self._write_to_json_log(threat, packet_info)

        msg = self._build_telegram_message(threat, packet_info)
        self.send_telegram(msg)

    # ====================== Original Methods (unchanged) ======================
    def _save_to_db(self, threat: dict, packet_info: dict) -> None:
        try:
            with self._db_lock:
                cur = self.conn.cursor()
                feats = threat.get("features")
                cur.execute(
                    """INSERT INTO alerts
                       (timestamp, type, source, rule, src_ip, dst_ip,
                        src_port, dst_port, confidence, reason, features)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        datetime.now().isoformat(),
                        threat.get("type", "unknown"),
                        threat.get("source", "engine"),
                        threat.get("rule", "unknown"),
                        packet_info.get("source_ip"),
                        packet_info.get("destination_ip"),
                        packet_info.get("source_port"),
                        packet_info.get("destination_port"),
                        float(threat.get("confidence", 0.0)),
                        threat.get("reason", "N/A"),
                        json.dumps(feats) if feats is not None else None,
                    ),
                )
                self.conn.commit()
                cur.close()
        except sqlite3.Error as exc:
            logger.error("Database insert failed: %s", exc)

    def _write_to_json_log(self, threat: dict, packet_info: dict) -> None:
        record = {
            "timestamp":        datetime.now().isoformat(),
            "type":             threat.get("type"),
            "source":           threat.get("source", "engine"),
            "rule":             threat.get("rule", "unknown"),
            "source_ip":        packet_info.get("source_ip"),
            "destination_ip":   packet_info.get("destination_ip"),
            "source_port":      packet_info.get("source_port"),
            "destination_port": packet_info.get("destination_port"),
            "confidence":       float(threat.get("confidence", 0.0)),
            "reason":           threat.get("reason", "N/A"),
            "features":         threat.get("features"),
        }
        try:
            with open(self.log_file, "a") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            logger.error("JSON log write failed: %s", exc)

    def _build_telegram_message(self, threat: dict, packet_info: dict) -> str:
        src_ip   = packet_info.get("source_ip", "N/A")
        dst_ip   = packet_info.get("destination_ip", "N/A")
        src_port = packet_info.get("source_port", "N/A")
        dst_port = packet_info.get("destination_port", "N/A")

        alert_type  = threat.get("type", "unknown").upper()
        rule        = threat.get("rule", "Unknown")
        source      = threat.get("source", "engine").upper()
        confidence  = float(threat.get("confidence", 0.0))
        reason      = threat.get("reason", "N/A")

        score_line = f"\n<b>IF Score:</b> {threat['score']:.3f}" if threat.get("type") == "anomaly" and "score" in threat else ""

        return (
            f"🚨 <b>IDS ALERT</b>\n\n"
            f"<b>Type:</b> {alert_type}\n"
            f"<b>Source:</b> {source}\n"
            f"<b>Rule:</b> {rule}\n"
            f"<b>Reason:</b> {reason}{score_line}\n\n"
            f"<b>Src:</b> {src_ip}:{src_port}\n"
            f"<b>Dst:</b> {dst_ip}:{dst_port}\n"
            f"<b>Confidence:</b> {confidence:.2f}"
        )

    def send_telegram(self, message: str) -> None:
        if not self.telegram_token or not self.telegram_chat_id:
            return
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        try:
            requests.post(
                url,
                json={"chat_id": self.telegram_chat_id, "text": message, "parse_mode": "HTML"},
                timeout=5
            )
        except Exception as exc:
            logger.warning("Telegram send failed: %s", exc)
