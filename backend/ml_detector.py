from __future__ import annotations

from collections import defaultdict
import ipaddress
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd


class FlowFeatureBuilder:
    def __init__(self) -> None:
        self.flow_state = defaultdict(
            lambda: {
                "count": 0,
                "bytes_sent": 0.0,
                "bytes_received": 0.0,
                "first_seen": None,
            }
        )

    def build(self, packet: dict) -> dict:
        flow_key = (
            packet["source_ip"],
            packet["destination_ip"],
            packet["protocol"],
            packet.get("destination_port") or 0,
        )
        state = self.flow_state[flow_key]
        captured_at = pd.Timestamp(packet["captured_at"])
        if state["first_seen"] is None:
            state["first_seen"] = captured_at

        state["count"] += 1
        packet_size = float(packet["packet_size"])
        state["bytes_sent"] += packet_size
        duration = max((captured_at - state["first_seen"]).total_seconds(), 1e-3)
        inbound = 0 if self._is_private_ip(packet["source_ip"]) else 1
        if inbound:
            state["bytes_received"] += packet_size

        flags = packet.get("flags") or ""
        protocol = packet["protocol"].upper()
        source_port = float(packet.get("source_port") or 0)
        destination_port = float(packet.get("destination_port") or 0)

        return {
            "Packet_Length": packet_size,
            "Duration": duration,
            "Source_Port": source_port,
            "Destination_Port": destination_port,
            "Bytes_Sent": state["bytes_sent"],
            "Bytes_Received": state["bytes_received"],
            "Flow_Packets/s": state["count"] / duration,
            "Flow_Bytes/s": state["bytes_sent"] / duration,
            "Avg_Packet_Size": state["bytes_sent"] / state["count"],
            "Total_Fwd_Packets": float(state["count"]),
            "Total_Bwd_Packets": float(1 if inbound else 0),
            "Fwd_Header_Length": 20.0,
            "Bwd_Header_Length": 20.0 if inbound else 0.0,
            "Sub_Flow_Fwd_Bytes": state["bytes_sent"],
            "Sub_Flow_Bwd_Bytes": state["bytes_received"],
            "Inbound": float(inbound),
            "Protocol_TCP": float(protocol == "TCP"),
            "Protocol_UDP": float(protocol == "UDP"),
            "Flags_FIN": float("F" in flags),
            "Flags_PSH": float("P" in flags),
            "Flags_SYN": float("S" in flags),
        }

    def reset(self) -> None:
        self.flow_state.clear()

    @staticmethod
    def _is_private_ip(ip_text: str) -> bool:
        try:
            return ipaddress.ip_address(ip_text).is_private
        except ValueError:
            return False


class TrainedModelDetector:
    def __init__(self, model_dir: Path, suspicious_threshold: float = 0.8) -> None:
        self.model_dir = model_dir
        self.suspicious_threshold = suspicious_threshold
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.expected_features = []
        self.ready = False
        self.flow_builder = FlowFeatureBuilder()
        self._load()

    def _load(self) -> None:
        model_path = self.model_dir / "nids_model_hgb.pkl"
        scaler_path = self.model_dir / "scaler.pkl"
        features_path = self.model_dir / "model_features.pkl"
        encoder_path = self.model_dir / "label_encoder.pkl"

        if not all(path.exists() for path in [model_path, scaler_path, features_path, encoder_path]):
            return

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.expected_features = list(joblib.load(features_path))
        self.label_encoder = joblib.load(encoder_path)
        self.ready = True

    def predict(self, packet: dict) -> Optional[dict]:
        if not self.ready:
            return None

        raw_features = self.flow_builder.build(packet)
        feature_frame = pd.DataFrame([{name: raw_features.get(name, 0.0) for name in self.expected_features}])
        scaled_values = self.scaler.transform(feature_frame)
        scaled_array = np.asarray(scaled_values)
        encoded_prediction = int(self.model.predict(scaled_array)[0])
        label = str(self.label_encoder.inverse_transform([encoded_prediction])[0])
        confidence = self._get_confidence(scaled_array, encoded_prediction)
        is_suspicious = label.lower() != "normal" and confidence is not None and confidence >= self.suspicious_threshold
        return {
            "label": label,
            "is_suspicious": is_suspicious,
            "confidence": confidence,
            "features": raw_features,
        }

    def _get_confidence(self, scaled_array: np.ndarray, encoded_prediction: int) -> Optional[float]:
        if self.model is None or not hasattr(self.model, "predict_proba"):
            return None
        probabilities = self.model.predict_proba(scaled_array)[0]
        if encoded_prediction >= len(probabilities):
            return None
        return round(float(probabilities[encoded_prediction]), 4)

    def reset(self) -> None:
        self.flow_builder.reset()
