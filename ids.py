"""
ids.py — Orchestrates all IDS components into a single run-loop.

Architecture:
  PacketCapture  →  packet_queue
  TrafficAnalyzer  →  feature dict
  DetectionEngine  →  threat list
  IntelFactory     →  reason string (XAI)
  AlertSystem      →  SQLite + JSON log + Telegram

  SnortParser runs independently in its own daemon thread,
  forwarding alerts directly to AlertSystem.
"""
import logging
import queue
import sys

from config import (
    CAPTURE_INTERFACE,
    TELEGRAM_CHAT_ID,
    TELEGRAM_TOKEN,
)
from alert_system import AlertSystem
from detection_engine import DetectionEngine
from intel_factory import IntelFactory, FEATURE_NAMES
from packet_capture import PacketCapture
from snort_parser import SnortParser
from traffic_analyzer import TrafficAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


class IntrusionDetectionSystem:
    """
    Top-level coordinator.

    Usage:
        ids = IntrusionDetectionSystem()
        ids.start()   # blocks until KeyboardInterrupt or ids.stop()
    """

    def __init__(
        self,
        interface: str       = CAPTURE_INTERFACE,
        telegram_token: str  = TELEGRAM_TOKEN,
        telegram_chat_id: str = TELEGRAM_CHAT_ID,
    ):
        self.interface = interface
        self.running   = False

        self.packet_capture   = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.intel_factory    = IntelFactory()
        self.alert_system     = AlertSystem(
            telegram_token=telegram_token,
            telegram_chat_id=telegram_chat_id,
        )
        self.snort_parser = SnortParser(alert_system=self.alert_system)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start all subsystems and enter the main packet-processing loop.
        Blocks until stopped by KeyboardInterrupt or self.stop().
        """
        logger.info("Starting Hybrid IDS on interface: %s", self.interface)
        self.running = True

        self.packet_capture.start_capture(self.interface)
        self.snort_parser.start()

        logger.info("IDS is running. Press Ctrl-C to stop.")

        try:
            self._run_loop()
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully shut down all subsystems."""
        self.running = False
        self.packet_capture.stop()
        self.snort_parser.stop()
        logger.info("Hybrid IDS stopped.")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """
        Dequeue packets, analyse them, detect threats,
        attach XAI reasons, and forward to AlertSystem.
        """
        while self.running:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                break

            try:
                self._process_packet(packet)
            except Exception as exc:
                logger.error("Unhandled error processing packet: %s", exc)

    def _process_packet(self, packet) -> None:
        features = self.traffic_analyzer.analyze_packet(packet)
        if not features:
            return

        threats = self.detection_engine.detect_threats(features)
        if not threats:
            return

        packet_info = {
            "source_ip":        features.get("src_ip"),
            "destination_ip":   features.get("dst_ip"),
            "source_port":      features.get("src_port"),
            "destination_port": features.get("dst_port"),
        }

        for threat in threats:
            # Attach XAI reason
            if threat["type"] == "anomaly":
                threat["reason"] = self.intel_factory.explain_anomaly(features)
                # Persist the exact feature vector so the dashboard can show
                # real per-anomaly deviations instead of placeholder values.
                threat["features"] = {k: float(features.get(k, 0)) for k in FEATURE_NAMES}
            else:
                threat["reason"] = "Signature Match"

            self.alert_system.generate_alert(threat, packet_info)

            logger.info(
                "[%s] %s | %s -> %s | Reason: %s | Confidence: %.2f",
                threat["type"].upper(),
                threat.get("rule", "N/A"),
                packet_info["source_ip"],
                packet_info["destination_ip"],
                threat.get("reason"),
                threat.get("confidence", 0.0),
            )
