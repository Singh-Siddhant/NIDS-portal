from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from backend.analyzer import RuleBasedAnalyzer
from backend.ml_detector import TrainedModelDetector
from backend.sniffer import PacketSnifferService
from backend.storage import PacketStore


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
LOCAL_MODEL_DIR = BASE_DIR / "models"
REFERENCE_MODEL_DIR = BASE_DIR.parent / "nids"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

store = PacketStore(DATA_DIR / "packets.json")
analyzer = RuleBasedAnalyzer()
ml_detector = TrainedModelDetector(LOCAL_MODEL_DIR if (LOCAL_MODEL_DIR / "nids_model_hgb.pkl").exists() else REFERENCE_MODEL_DIR)


def process_packet(features: dict) -> None:
    packet_record = analyzer.analyze(features)
    ml_result = ml_detector.predict(features)

    reasons = list(packet_record["reasons"])
    if ml_result:
        packet_record["ml_label"] = ml_result["label"]
        packet_record["ml_confidence"] = ml_result["confidence"]
        if ml_result["is_suspicious"]:
            reasons.append(f"ML model predicted {ml_result['label']} with confidence {ml_result['confidence']}")
    else:
        packet_record["ml_label"] = "Unavailable"
        packet_record["ml_confidence"] = None

    packet_record["reasons"] = reasons
    packet_record["status"] = "Suspicious" if reasons else "Safe"
    store.add_packet(packet_record)


sniffer_service = PacketSnifferService(process_packet)


@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/api/summary")
def get_summary():
    return jsonify(store.snapshot()["summary"])


@app.get("/api/packets")
def get_packets():
    limit = request.args.get("limit", default=50, type=int)
    packets = store.snapshot()["packets"][: max(limit, 1)]
    return jsonify(packets)


@app.get("/api/suspicious")
def get_suspicious_packets():
    limit = request.args.get("limit", default=50, type=int)
    packets = store.snapshot()["suspicious_packets"][: max(limit, 1)]
    return jsonify(packets)


@app.get("/api/status")
def get_status():
    return jsonify(
        {
            "running": sniffer_service.running,
            "mode": sniffer_service.mode,
            "message": "Live capture requires Scapy and admin/root privileges.",
            "ml_model_ready": ml_detector.ready,
            "ml_model_source": str(
                (LOCAL_MODEL_DIR if (LOCAL_MODEL_DIR / "nids_model_hgb.pkl").exists() else REFERENCE_MODEL_DIR)
                / "nids_model_hgb.pkl"
            ),
        }
    )


@app.get("/api/interfaces")
def get_interfaces():
    return jsonify(
        {
            "interfaces": sniffer_service.list_interfaces(),
            "message": "Select the adapter that carries your real traffic. Avoid loopback and unused virtual adapters unless that is what you want to inspect.",
        }
    )


@app.post("/api/capture/start")
def start_capture():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode", "live")
    iface = payload.get("interface")
    packet_limit = payload.get("packet_limit")

    if mode not in {"sample", "live"}:
        return jsonify({"error": "mode must be 'sample' or 'live'"}), 400
    if mode == "live" and not iface:
        return jsonify({"error": "A network interface is required for live capture."}), 400

    try:
        sniffer_service.start(mode=mode, iface=iface, packet_limit=packet_limit)
        return jsonify({"status": "started", "mode": mode})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/capture/stop")
def stop_capture():
    sniffer_service.stop()
    return jsonify({"status": "stopped"})


@app.post("/api/reset")
def reset_data():
    if sniffer_service.running:
        sniffer_service.stop()
    store.clear()
    analyzer.reset()
    ml_detector.reset()
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)
