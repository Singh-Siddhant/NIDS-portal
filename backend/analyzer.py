from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress


COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 587, 993, 995, 1433, 1521, 1723,
    1883, 2049, 2375, 2376, 3306, 3389, 5060, 5432, 5900, 6379, 8080, 8443,
}


class RuleBasedAnalyzer:
    def __init__(self, packet_threshold: int = 12, window_seconds: int = 10) -> None:
        self.packet_threshold = packet_threshold
        self.window_seconds = window_seconds
        self.source_activity = defaultdict(deque)
        self.packet_id = 1

    def analyze(self, features: dict) -> dict:
        reasons = []
        timestamp = datetime.now(timezone.utc)
        src_ip = features["source_ip"]
        dst_port = features.get("destination_port")
        src_is_private = self._is_private_ip(src_ip)

        events = self.source_activity[src_ip]
        events.append(timestamp)
        while events and (timestamp - events[0]).total_seconds() > self.window_seconds:
            events.popleft()

        if len(events) > self.packet_threshold:
            reasons.append(
                f"High traffic from {src_ip}: {len(events)} packets in {self.window_seconds}s"
            )

        if dst_port is not None and dst_port not in COMMON_PORTS and not src_is_private:
            reasons.append(f"Unknown destination port {dst_port}")

        status = "Suspicious" if reasons else "Safe"
        packet_record = {
            "id": self.packet_id,
            "timestamp": timestamp.isoformat(),
            "source_ip": src_ip,
            "destination_ip": features["destination_ip"],
            "protocol": features["protocol"],
            "packet_size": features["packet_size"],
            "flags": features["flags"],
            "source_port": features.get("source_port"),
            "destination_port": dst_port,
            "status": status,
            "reasons": reasons,
        }
        self.packet_id += 1
        return packet_record

    def reset(self) -> None:
        self.packet_id = 1
        self.source_activity.clear()

    @staticmethod
    def _is_private_ip(ip_text: str) -> bool:
        try:
            return ipaddress.ip_address(ip_text).is_private
        except ValueError:
            return False
