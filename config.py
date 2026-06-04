"""
config.py — Central configuration loader.
All modules import from here instead of reading os.getenv() individually.
"""
import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN       = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID     = os.getenv("TELEGRAM_CHAT_ID", "")
SENSOR_IP            = os.getenv("SENSOR_IP", "192.168.8.8")
SENSOR_IPS = [ip.strip() for ip in os.getenv("SENSOR_IPS", "192.168.8.8,192.168.8.21").split(",")]
CAPTURE_INTERFACE    = os.getenv("CAPTURE_INTERFACE", "eth0")
MODEL_PATH           = os.getenv("MODEL_PATH", "data/models/isolation_forest.model")
NORMAL_DATA_PATH     = os.getenv("NORMAL_DATA_PATH", "data/models/cic_normal_features.npy")
ABUSE_IP_KEY         = os.getenv("ABUSE_IP_KEY", "")
SNORT_ALERT_FILE     = os.getenv("SNORT_ALERT_FILE", "/var/log/snort/alert_fast.txt")
DB_PATH              = os.getenv("DB_PATH", "data/runtime/ids_data.db")
LOG_FILE             = os.getenv("LOG_FILE", "data/runtime/ids_alerts.log")
