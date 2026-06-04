"""
traffic_analyzer.py — Improved with Flow Timeout for Real-Time Detection
"""

import time
import logging
from collections import defaultdict
from typing import Optional

from scapy.all import IP, TCP

logger = logging.getLogger(__name__)

FLOW_TIMEOUT = 5.0          # Reset flow after 5 seconds of inactivity
CLEANUP_INTERVAL = 3.0

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats: defaultdict = defaultdict(self._empty_flow_stats)
        self.last_cleanup = time.time()
        self.flow_last_alert = {}  # To reduce repeated alerts

    def _empty_flow_stats(self) -> dict:
        return {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": None,
            "last_time": None,
            "fwd_packet_count": 0,
            "bwd_packet_count": 0,
            "fwd_byte_count": 0,
            "bwd_byte_count": 0,
        }

    def analyze_packet(self, packet) -> Optional[dict]:
        if IP not in packet or TCP not in packet:
            return None

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport

        flow_key = tuple(sorted([(ip_src, port_src), (ip_dst, port_dst)]))
        stats = self.flow_stats[flow_key]
        current_time = float(packet.time) if hasattr(packet, "time") else time.time()

        # Flow Timeout - Reset old flows
        if stats["last_time"] is not None:
            if current_time - stats["last_time"] > FLOW_TIMEOUT:
                self.flow_stats[flow_key] = self._empty_flow_stats()
                stats = self.flow_stats[flow_key]
                if flow_key in self.flow_last_alert:
                    del self.flow_last_alert[flow_key]

        # Update statistics
        pkt_len = len(packet)
        stats["packet_count"] += 1
        stats["byte_count"] += pkt_len

        if stats["start_time"] is None:
            stats["start_time"] = current_time
        stats["last_time"] = current_time

        # Direction
        if (ip_src, port_src) == flow_key[0]:
            stats["fwd_packet_count"] += 1
            stats["fwd_byte_count"] += pkt_len
        else:
            stats["bwd_packet_count"] += 1
            stats["bwd_byte_count"] += pkt_len

        # Periodic cleanup
        if current_time - self.last_cleanup > CLEANUP_INTERVAL:
            self._cleanup_old_flows(current_time)
            self.last_cleanup = current_time

        return self._extract_features(packet, stats, flow_key)

    def _cleanup_old_flows(self, current_time):
        to_delete = [key for key, stats in self.flow_stats.items() 
                    if stats["last_time"] and current_time - stats["last_time"] > FLOW_TIMEOUT * 3]
        for key in to_delete:
            self.flow_stats.pop(key, None)
            self.flow_last_alert.pop(key, None)

    def _extract_features(self, packet, stats: dict, flow_key) -> dict:
        duration = max(stats["last_time"] - stats["start_time"], 1e-6)

        features = {
            "packet_size": len(packet),
            "packet_rate": stats["packet_count"] / duration,
            "byte_rate": stats["byte_count"] / duration,
            "window_size": packet[TCP].window,
            "flow_duration": duration,
            "fwd_packet_rate": stats["fwd_packet_count"] / duration,
            "tcp_flags": int(packet[TCP].flags),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
        }
        return features
