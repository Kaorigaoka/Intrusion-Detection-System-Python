"""
packet_capture.py — Captures live TCP/IP packets using Scapy.

Runs the sniffer in a background daemon thread and places
packets into a bounded queue for the main IDS loop to consume.
"""
import queue
import threading
import logging

from scapy.all import sniff, IP, TCP

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Captures live TCP/IP packets on a given network interface.

    Packets are placed onto self.packet_queue (maxsize=10 000).
    When the queue is full, incoming packets are silently dropped
    to prevent memory exhaustion under high traffic.
    """

    def __init__(self, maxqueue: int = 10_000):
        self.packet_queue = queue.Queue(maxsize=maxqueue)
        self._stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start_capture(self, interface: str = "eth0") -> None:
        """Start packet capture in a background daemon thread."""
        if self._capture_thread and self._capture_thread.is_alive():
            logger.warning("Capture already running on %s — ignoring start request.", interface)
            return

        self._stop_event.clear()
        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface,),
            daemon=True,
            name="PacketCaptureThread",
        )
        self._capture_thread.start()
        logger.info("Packet capture started on interface: %s", interface)

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the capture thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=timeout)
        logger.info("Packet capture stopped.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _capture_worker(self, interface: str) -> None:
        """Worker function that runs inside the background thread."""
        sniff(
            iface=interface,
            prn=self._packet_callback,
            store=0,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _packet_callback(self, packet) -> None:
        """Called by Scapy for every captured packet."""
        if IP not in packet or TCP not in packet:
            return

        logger.debug(
            "TCP packet: %s:%s -> %s:%s",
            packet[IP].src, packet[TCP].sport,
            packet[IP].dst, packet[TCP].dport,
        )

        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            logger.debug("Packet queue full — dropping packet.")
