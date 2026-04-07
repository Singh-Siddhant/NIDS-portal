from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score


BASE_DIR = Path(__file__).resolve().parents[1]
MODELS_DIR = BASE_DIR / "models"
NIDS_DIR = BASE_DIR.parent / "nids"

FEATURE_COLUMNS = list(joblib.load(MODELS_DIR / "model_features.pkl"))
MODEL = joblib.load(MODELS_DIR / "nids_model_hgb.pkl")
SCALER = joblib.load(MODELS_DIR / "scaler.pkl")
ENCODER = joblib.load(MODELS_DIR / "label_encoder.pkl")


def clean_frame(df: pd.DataFrame) -> pd.DataFrame:
    return df.replace([np.inf, -np.inf], np.nan).dropna()


def evaluate_frame(frame: pd.DataFrame, name: str) -> dict:
    frame = clean_frame(frame)
    X = frame[FEATURE_COLUMNS]
    y_true = ENCODER.transform(frame["Target"])
    y_pred = MODEL.predict(SCALER.transform(X))
    return {
        "dataset": name,
        "rows": int(len(frame)),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
    }


def cyberfed_frame() -> pd.DataFrame:
    df = pd.read_csv(NIDS_DIR / "cyber-threat-detection" / "cyberfeddefender_dataset.csv")
    return pd.DataFrame(
        {
            "Packet_Length": df["Packet_Length"],
            "Duration": df["Duration"],
            "Destination_Port": df["Destination_Port"],
            "Bytes_Sent": df["Bytes_Sent"],
            "Bytes_Received": df["Bytes_Received"],
            "Flow_Packets/s": df["Flow_Packets/s"],
            "Flow_Bytes/s": df["Flow_Bytes/s"],
            "Avg_Packet_Size": df["Avg_Packet_Size"],
            "Total_Fwd_Packets": df["Total_Fwd_Packets"],
            "Total_Bwd_Packets": df["Total_Bwd_Packets"],
            "Fwd_Header_Length": df["Fwd_Header_Length"],
            "Bwd_Header_Length": df["Bwd_Header_Length"],
            "Sub_Flow_Fwd_Bytes": df["Sub_Flow_Fwd_Bytes"],
            "Sub_Flow_Bwd_Bytes": df["Sub_Flow_Bwd_Bytes"],
            "Target": np.where(df["Attack_Type"].astype(str).str.lower() == "normal", "Normal", "Suspicious"),
        }
    )


def cic_frame(file_name: str, attack_labels: set[str]) -> pd.DataFrame:
    df = pd.read_csv(NIDS_DIR / "network-intrusion-dataset" / file_name, low_memory=False)
    labels = df[" Label"].astype(str).str.strip()
    return pd.DataFrame(
        {
            "Packet_Length": pd.to_numeric(df[" Packet Length Mean"], errors="coerce"),
            "Duration": pd.to_numeric(df[" Flow Duration"], errors="coerce"),
            "Destination_Port": pd.to_numeric(df[" Destination Port"], errors="coerce"),
            "Bytes_Sent": pd.to_numeric(df["Total Length of Fwd Packets"], errors="coerce"),
            "Bytes_Received": pd.to_numeric(df[" Total Length of Bwd Packets"], errors="coerce"),
            "Flow_Packets/s": pd.to_numeric(df[" Flow Packets/s"], errors="coerce"),
            "Flow_Bytes/s": pd.to_numeric(df["Flow Bytes/s"], errors="coerce"),
            "Avg_Packet_Size": pd.to_numeric(df[" Average Packet Size"], errors="coerce"),
            "Total_Fwd_Packets": pd.to_numeric(df[" Total Fwd Packets"], errors="coerce"),
            "Total_Bwd_Packets": pd.to_numeric(df[" Total Backward Packets"], errors="coerce"),
            "Fwd_Header_Length": pd.to_numeric(df[" Fwd Header Length"], errors="coerce"),
            "Bwd_Header_Length": pd.to_numeric(df[" Bwd Header Length"], errors="coerce"),
            "Sub_Flow_Fwd_Bytes": pd.to_numeric(df[" Subflow Fwd Bytes"], errors="coerce"),
            "Sub_Flow_Bwd_Bytes": pd.to_numeric(df[" Subflow Bwd Bytes"], errors="coerce"),
            "Target": np.where(labels.isin(attack_labels), "Suspicious", "Normal"),
        }
    )


def main() -> None:
    results = [
        evaluate_frame(cyberfed_frame(), "cyberfed"),
        evaluate_frame(cic_frame("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", {"DDoS"}), "cic-ddos"),
        evaluate_frame(cic_frame("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", {"PortScan"}), "cic-portscan"),
        evaluate_frame(cic_frame("Tuesday-WorkingHours.pcap_ISCX.csv", {"FTP-Patator", "SSH-Patator"}), "cic-tuesday"),
        evaluate_frame(
            cic_frame(
                "Wednesday-workingHours.pcap_ISCX.csv",
                {"DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "Heartbleed"},
            ),
            "cic-wednesday",
        ),
    ]
    payload = {"results": results}
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
