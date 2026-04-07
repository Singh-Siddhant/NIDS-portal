from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


BASE_DIR = Path(__file__).resolve().parents[1]
NIDS_DIR = BASE_DIR.parent / "nids"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

FEATURE_COLUMNS = [
    "Packet_Length",
    "Duration",
    "Destination_Port",
    "Bytes_Sent",
    "Bytes_Received",
    "Flow_Packets/s",
    "Flow_Bytes/s",
    "Avg_Packet_Size",
    "Total_Fwd_Packets",
    "Total_Bwd_Packets",
    "Fwd_Header_Length",
    "Bwd_Header_Length",
    "Sub_Flow_Fwd_Bytes",
    "Sub_Flow_Bwd_Bytes",
]


def clean_frame(df: pd.DataFrame) -> pd.DataFrame:
    return df.replace([np.inf, -np.inf], np.nan).dropna()


def load_cyberfed() -> pd.DataFrame:
    df = pd.read_csv(NIDS_DIR / "cyber-threat-detection" / "cyberfeddefender_dataset.csv")
    mapped = pd.DataFrame(
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
            "Dataset": "cyberfed",
        }
    )
    return clean_frame(mapped)


def load_cic(file_name: str, attack_labels: set[str], sample_size: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(NIDS_DIR / "network-intrusion-dataset" / file_name, low_memory=False)
    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)

    labels = df[" Label"].astype(str).str.strip()
    mapped = pd.DataFrame(
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
            "Dataset": Path(file_name).stem,
        }
    )
    return clean_frame(mapped)


def build_training_frame() -> pd.DataFrame:
    frames = [
        load_cyberfed(),
        load_cic("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", {"DDoS"}, sample_size=25000),
        load_cic("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", {"PortScan"}, sample_size=25000),
        load_cic("Tuesday-WorkingHours.pcap_ISCX.csv", {"FTP-Patator", "SSH-Patator"}, sample_size=25000),
        load_cic(
            "Wednesday-workingHours.pcap_ISCX.csv",
            {"DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "Heartbleed"},
            sample_size=25000,
        ),
    ]
    return pd.concat(frames, ignore_index=True)


def train() -> dict:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    df = build_training_frame()
    X = df[FEATURE_COLUMNS]
    y_text = df["Target"]
    dataset_names = df["Dataset"]

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_text)

    X_train, X_test, y_train, y_test, ds_train, ds_test = train_test_split(
        X,
        y,
        dataset_names,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = ExtraTreesClassifier(
        n_estimators=400,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train_scaled, y_train)
    predictions = model.predict(X_test_scaled)

    overall_accuracy = accuracy_score(y_test, predictions)
    per_dataset = {}
    for dataset_name in sorted(pd.Series(ds_test).unique()):
        mask = ds_test == dataset_name
        per_dataset[dataset_name] = round(float(accuracy_score(y_test[mask], predictions[mask])), 4)

    report = {
        "overall_accuracy": round(float(overall_accuracy), 4),
        "per_dataset_accuracy": per_dataset,
        "feature_columns": FEATURE_COLUMNS,
        "label_classes": list(map(str, encoder.classes_)),
        "classification_report": classification_report(
            y_test,
            predictions,
            target_names=list(map(str, encoder.classes_)),
            output_dict=True,
            zero_division=0,
        ),
    }

    joblib.dump(model, MODELS_DIR / "nids_model_hgb.pkl")
    joblib.dump(model, MODELS_DIR / "nids_model_mlp.pkl")
    joblib.dump(model, MODELS_DIR / "nids_model_rf.pkl")
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    joblib.dump(FEATURE_COLUMNS, MODELS_DIR / "model_features.pkl")
    joblib.dump(encoder, MODELS_DIR / "label_encoder.pkl")
    (REPORTS_DIR / "main_model_eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    train()
