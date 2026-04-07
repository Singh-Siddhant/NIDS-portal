from __future__ import annotations

import re
import random
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

try:
    from scapy.all import ICMP, IP, TCP, UDP, get_if_list, sniff
    from scapy.arch.windows import get_windows_if_list
except Exception:  # pragma: no cover - keeps sample mode usable without scapy
    ICMP = IP = TCP = UDP = None
    get_if_list = None
    get_windows_if_list = None
    sniff = None


PacketHandler = Callable[[dict], None]


class PacketSnifferService:
    def __init__(self, packet_handler: PacketHandler) -> None:
        self.packet_handler = packet_handler
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._mode = "idle"
        self._iface: Optional[str] = None
        self._packet_limit: Optional[int] = None

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, mode: str = "sample", iface: Optional[str] = None, packet_limit: Optional[int] = None) -> None:
        if self.running:
            raise RuntimeError("Capture is already running.")

        self._mode = mode
        self._iface = iface
        self._packet_limit = packet_limit
        self._stop_event.clear()
        target = self._run_live_capture if mode == "live" else self._run_sample_capture
        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def list_interfaces(self) -> list[dict]:
        if get_windows_if_list is not None:
            try:
                interfaces = []
                for item in get_windows_if_list():
                    guid = str(item.get("guid", "")).strip("{}")
                    device_name = f"\\Device\\NPF_{{{guid}}}" if guid else str(item.get("name", ""))
                    ip_list = item.get("ips") or []
                    description = str(item.get("description") or "").strip()
                    friendly_name = self._friendly_interface_name(
                        str(item.get("name") or ""),
                        description,
                        ip_list,
                    )
                    label_parts = [friendly_name]
                    if description:
                        label_parts.append(description)
                    ipv4s = [ip for ip in ip_list if "." in ip]
                    if ipv4s:
                        label_parts.append(", ".join(ipv4s[:2]))
                    interfaces.append({
                        "id": device_name,
                        "label": " | ".join(label_parts),
                        "friendly_name": friendly_name,
                        "description": description,
                    })
                return interfaces
            except Exception:
                pass

        if get_if_list is None:
            return []
        try:
            return [
                {
                    "id": str(name),
                    "label": self._friendly_interface_name(str(name), "", []),
                    "friendly_name": self._friendly_interface_name(str(name), "", []),
                    "description": "",
                }
                for name in sorted(get_if_list())
            ]
        except Exception:
            return []

    @staticmethod
    def _friendly_interface_name(name: str, description: str, ips: list[str]) -> str:
        text = f"{name} {description}".lower()
        ipv4s = [ip for ip in ips if "." in ip]

        if "loopback" in text:
            return "Loopback Adapter"
        if "wi-fi direct" in text:
            suffix = PacketSnifferService._extract_suffix(name)
            return f"Wi-Fi Direct Virtual Adapter{suffix}"
        if "wireless" in text or "wi-fi" in text or "wifi" in text or "wlan" in text:
            return "Wi-Fi Adapter"
        if "ethernet" in text:
            return "Ethernet Adapter"
        if "tap-windows" in text or "openvpn" in text or "tunnel" in text or "vpn" in text:
            return "VPN / Tunnel Adapter"
        if "virtual" in text:
            suffix = PacketSnifferService._extract_suffix(name)
            return f"Virtual Adapter{suffix}"
        if ipv4s:
            return f"Network Adapter ({ipv4s[0]})"
        return "Network Adapter"

    @staticmethod
    def _extract_suffix(name: str) -> str:
        match = re.search(r"(\d+)$", name.strip())
        return f" #{match.group(1)}" if match else ""

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        self._mode = "idle"

    def _run_live_capture(self) -> None:
        if sniff is None:
            raise RuntimeError("Scapy is not installed. Install dependencies or use sample mode.")

        captured = 0
        while not self._stop_event.is_set():
            sniff(
                iface=self._iface,
                count=1,
                timeout=1,
                store=False,
                prn=lambda packet: self._handle_live_packet(packet),
            )
            if self._packet_limit:
                captured += 1
                if captured >= self._packet_limit:
                    break
        self._mode = "idle"

    def _handle_live_packet(self, packet) -> None:
        if IP is None or not packet.haslayer(IP):
            return

        protocol = "OTHER"
        flags = "-"
        source_port = None
        destination_port = None

        if TCP is not None and packet.haslayer(TCP):
            protocol = "TCP"
            flags = str(packet[TCP].flags)
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
        elif UDP is not None and packet.haslayer(UDP):
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)
        elif ICMP is not None and packet.haslayer(ICMP):
            protocol = "ICMP"

        self.packet_handler(
            {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "source_ip": packet[IP].src,
                "destination_ip": packet[IP].dst,
                "protocol": protocol,
                "packet_size": len(packet),
                "flags": flags,
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )

    def _run_sample_capture(self) -> None:
        samples_sent = 0
        safe_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
        suspicious_ips = ["203.0.113.10", "198.51.100.77", "45.33.32.156"]
        common_ports = [22, 53, 80, 123, 443, 3306, 5432, 8080]
        uncommon_ports = [31337, 4444, 5555, 9001, 9999]

        while not self._stop_event.is_set():
            # Force regular suspicious samples so short demos show both labels.
            use_suspicious = samples_sent % 3 == 2 or random.random() < 0.25
            dst_port = random.choice(uncommon_ports if use_suspicious else common_ports)
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            flags = random.choice(["S", "SA", "A", "PA", "-"]) if protocol == "TCP" else "-"
            self.packet_handler(
                {
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "source_ip": random.choice(suspicious_ips if use_suspicious else safe_ips),
                    "destination_ip": "192.168.1.100",
                    "protocol": protocol,
                    "packet_size": random.randint(60, 1500),
                    "flags": flags,
                    "source_port": random.randint(1024, 65535),
                    "destination_port": None if protocol == "ICMP" else dst_port,
                }
            )
            samples_sent += 1
            if self._packet_limit and samples_sent >= self._packet_limit:
                break
            time.sleep(0.75)

        self._mode = "idle"
