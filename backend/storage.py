from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path
from typing import Deque


class PacketStore:
    def __init__(
        self,
        output_path: Path,
        max_packets: int = 50,
        max_suspicious_packets: int = 50,
    ) -> None:
        self.output_path = output_path
        self.max_packets = max_packets
        self.max_suspicious_packets = max_suspicious_packets
        self._lock = threading.RLock()
        self._packets: Deque[dict] = deque(maxlen=max_packets)
        self._suspicious_packets: Deque[dict] = deque(maxlen=max_suspicious_packets)
        self._counts = {"total": 0, "safe": 0, "suspicious": 0}

    def add_packet(self, packet: dict) -> dict:
        status = packet["status"].lower()
        with self._lock:
            self._packets.appendleft(packet)
            if status == "suspicious":
                self._suspicious_packets.appendleft(packet)
            self._counts["total"] += 1
            self._counts[status] += 1
            self._write_snapshot()
            return {
                "summary": dict(self._counts),
                "packets": list(self._packets),
                "suspicious_packets": list(self._suspicious_packets),
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "summary": dict(self._counts),
                "packets": list(self._packets),
                "suspicious_packets": list(self._suspicious_packets),
            }

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._suspicious_packets.clear()
            self._counts = {"total": 0, "safe": 0, "suspicious": 0}
            self._write_snapshot()

    def _write_snapshot(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "summary": self._counts,
            "packets": list(self._packets),
            "suspicious_packets": list(self._suspicious_packets),
        }
        self.output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
