"""
snort_parser.py — Tails a Snort alert.fast log file and forwards
parsed alerts to the AlertSystem.

Supports the Snort 3 alert.fast format with a regex-based primary
parser and a lightweight fallback for non-standard lines.
"""
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Optional

from config import SNORT_ALERT_FILE

logger = logging.getLogger(__name__)

# Regex for the standard Snort 3 alert.fast line
_SNORT_PATTERN = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"        # timestamp
    r"\[\*\*\]\s+"                                       # [**]
    r"\[(\d+):(\d+):(\d+)\]\s+"                         # [gid:sid:rev]
    r'"(.*?)"\s+'                                        # message
    r"\[\*\*\]\s+"                                       # [**]
    r"(?:\[Classification:\s*(.*?)\]\s+)?"               # classification (optional)
    r"(?:\[Priority:\s*(\d+)\]\s+)?"                     # priority (optional)
    r"\{(\w+)\}\s+"                                      # protocol
    r"(\d{1,3}(?:\.\d{1,3}){3}):?(\d*)\s+->\s+"        # src ip : port
    r"(\d{1,3}(?:\.\d{1,3}){3}):?(\d*)"                # dst ip : port
)

_IP_PATTERN  = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?")
_DST_PATTERN = re.compile(r"->\s*(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?")

# Snort builtin decoder / inspector alerts prefix their message with a
# parenthesised subsystem tag, e.g. "(ipv4) IPv4 datagram length > captured
# length", "(tcp) bad checksum", "(decode) ...". Real text/community signature
# rules (GID 1) never use this prefix, so it cleanly identifies low-value
# decoder noise we don't want flooding the alert DB.
_DECODER_MSG_PATTERN = re.compile(r"^\(\w+\)\s")

# The packet decoder uses GID 116; builtin decoder events also surface here.
_DECODER_GIDS = {116}


class SnortParser:
    """
    Watches a Snort alert.fast file, parses each new line,
    and calls alert_system.generate_alert() for valid alerts.
    """

    def __init__(
        self,
        alert_file: str = SNORT_ALERT_FILE,
        alert_system=None,
        poll_interval: float = 0.5,
        filter_decoder_events: bool = True,
    ):
        self.alert_file    = alert_file
        self.alert_system  = alert_system
        self.poll_interval = poll_interval
        # Drop builtin decoder/inspector noise (e.g. malformed-packet events)
        # so only real signature matches reach the alert DB. Set False to keep.
        self.filter_decoder_events = filter_decoder_events

        self._stop_event      = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the tail thread (idempotent — safe to call multiple times)."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._tail_alerts,
            daemon=True,
            name="SnortParserThread",
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the tail thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_line(self, line: str) -> Optional[dict]:
        """
        Parse one line from alert.fast.
        Returns a structured dict or None if the line is not a valid alert.
        """
        line = line.strip()
        if not line or "[**]" not in line:
            return None

        match = _SNORT_PATTERN.search(line)
        if match:
            alert = self._parse_full_match(match, line)
        else:
            alert = self._parse_fallback(line)

        if alert is not None and self.filter_decoder_events and self._is_decoder_event(alert):
            logger.debug("Skipped decoder/inspector event: %s", alert.get("msg"))
            return None

        return alert

    @staticmethod
    def _is_decoder_event(alert: dict) -> bool:
        """True for Snort builtin decoder/inspector alerts (low-value noise)."""
        if alert.get("gid") in _DECODER_GIDS:
            return True
        msg = alert.get("msg") or ""
        return bool(_DECODER_MSG_PATTERN.match(msg))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_full_match(self, match: re.Match, raw: str) -> dict:
        ts, gid, sid, rev, msg, classification, priority, proto, \
            src_ip, src_port, dst_ip, dst_port = match.groups()

        return {
            "timestamp":      datetime.now().isoformat(),
            "source":         "snort",
            "msg":            msg.strip(),
            "classification": classification.strip() if classification else None,
            "priority":       int(priority) if priority else 3,
            "protocol":       proto,
            "src_ip":         src_ip,
            "src_port":       int(src_port) if src_port else None,
            "dst_ip":         dst_ip,
            "dst_port":       int(dst_port) if dst_port else None,
            "gid":            int(gid),
            "sid":            int(sid),
            "rev":            int(rev),
            "raw":            raw,
        }

    def _parse_fallback(self, line: str) -> Optional[dict]:
        """Minimal fallback for non-standard Snort lines."""
        try:
            src_m  = _IP_PATTERN.search(line)
            dst_m  = _DST_PATTERN.search(line)
            msg_s  = line.find('"')
            msg_e  = line.rfind('"')
            msg    = line[msg_s + 1:msg_e] if msg_s != -1 else "Unknown Snort Alert"

            return {
                "timestamp": datetime.now().isoformat(),
                "source":    "snort",
                "msg":       msg.strip(),
                "src_ip":    src_m.group(1) if src_m else None,
                "src_port":  int(src_m.group(2)) if src_m and src_m.group(2) else None,
                "dst_ip":    dst_m.group(1) if dst_m else None,
                "dst_port":  int(dst_m.group(2)) if dst_m and dst_m.group(2) else None,
                "priority":  3,
                "sid":       None,
                "raw":       line,
            }
        except Exception as exc:
            logger.debug("Fallback parse failed: %s", exc)
            return None

    def _alert_to_threat(self, alert: dict) -> dict:
        """Convert a parsed Snort alert into the standard threat dict."""
        sid        = alert.get("sid")
        priority   = alert.get("priority", 3)
        confidence = 0.95 if priority <= 2 else 0.80

        return {
            "type":       "signature",
            "source":     "snort",
            "rule":       f"Snort_{sid}" if sid else "Snort_unknown",
            "confidence": confidence,
            "reason":     "Signature Match (Snort)",
            "details":    alert,
        }

    def _alert_to_packet_info(self, alert: dict) -> dict:
        return {
            "source_ip":        alert.get("src_ip"),
            "destination_ip":   alert.get("dst_ip"),
            "source_port":      alert.get("src_port"),
            "destination_port": alert.get("dst_port"),
        }

    # ------------------------------------------------------------------
    # File tailing
    # ------------------------------------------------------------------

    def _tail_alerts(self) -> None:
        """
        Seek to the end of the alert file and poll for new lines.
        Reconnects automatically if the file is rotated.
        """
        if not os.path.exists(self.alert_file):
            logger.warning(
                "Snort alert file not found: %s\n"
                "Make sure Snort is running with -A alert_fast.",
                self.alert_file,
            )
            return

        logger.info("SnortParser tailing: %s", self.alert_file)

        with open(self.alert_file, "r") as fh:
            fh.seek(0, os.SEEK_END)

            while not self._stop_event.is_set():
                try:
                    lines = fh.readlines()
                    for line in lines:
                        alert = self.parse_line(line)
                        if not alert:
                            continue

                        threat      = self._alert_to_threat(alert)
                        packet_info = self._alert_to_packet_info(alert)

                        if self.alert_system:
                            self.alert_system.generate_alert(threat, packet_info)

                        logger.info(
                            "[SNORT] %s | SID: %s | %s -> %s",
                            alert.get("msg", "Alert"),
                            alert.get("sid"),
                            alert.get("src_ip"),
                            alert.get("dst_ip"),
                        )

                    time.sleep(self.poll_interval)

                except Exception as exc:
                    logger.error("SnortParser tail error: %s", exc)
                    time.sleep(1)
