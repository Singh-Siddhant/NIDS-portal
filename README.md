# NIDS Final

<p align="center">
  <img src="./screenshots/dashboard-overview.png" alt="NIDS Dashboard Overview" width="100%">
</p>

<p align="center">
  <strong>Real-Time Network Intrusion Detection System</strong><br>
  Live packet capture, rule-based analysis, ML-assisted prediction, and an interactive dashboard.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.x-1f6feb?style=for-the-badge">
  <img alt="Flask" src="https://img.shields.io/badge/Flask-Backend-111827?style=for-the-badge">
  <img alt="Scapy" src="https://img.shields.io/badge/Scapy-Live%20Capture-0f766e?style=for-the-badge">
  <img alt="ML" src="https://img.shields.io/badge/ML-ExtraTrees-orange?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/Status-Complete-166534?style=for-the-badge">
</p>

## Overview

`NIDS Final` is a cybersecurity project focused on building a practical **Network Intrusion Detection System** for live traffic monitoring.

This project was completed as a **Cybersecurity project task given by Dr. V. Kumar sir, CSE branch, Madan Mohan Malaviya University of Technology, Gorakhpur**.

The system combines:

- live packet capture from real network interfaces
- rule-based suspicious activity detection
- machine learning based `Normal` vs `Suspicious` prediction
- a rolling dashboard with the latest packet entries
- a separate suspicious packet cache panel

## Quick Links

- [Project Report](./PROJECT_REPORT.md)
- [Main Model Report](./reports/MAIN_MODEL_REPORT.md)
- [Evaluation JSON](./reports/main_model_eval.json)
- [App Entry Point](./app.py)

## Screenshots

### Dashboard Overview

![Dashboard Overview](./screenshots/dashboard-overview.png)

### Packet Logs

![Packet Logs](./screenshots/dashboard-packets.png)

### Suspicious Packet Cache

![Suspicious Packet Cache](./screenshots/dashboard-suspicious-panel.png)

## Highlights

- Real-time packet capture using `Scapy`
- Friendly network adapter selection for Windows
- Rolling latest `50` packet entries on the dashboard
- Temporary suspicious-only packet cache
- Hybrid detection using rules + machine learning
- Binary classification optimized for live monitoring
- Local training and evaluation scripts included

## Architecture

### Backend

- `Flask` serves the UI and API endpoints
- `Scapy` captures packets from a selected network interface
- feature engineering adapts live packets into model-compatible inputs
- rule checks and ML outputs are combined into final decisions
- recent activity is stored in rolling JSON-backed structures

### Frontend

- dashboard cards for total, safe, and suspicious traffic
- live packet logs table
- suspicious packet panel
- lightweight interactive controls
- hidden UI easter egg

## Credits

- Frontend design, layout styling, and visual presentation were made with the help of AI.
- Backend development, APIs, packet capture flow, ML integration, feature engineering, logic, and project functionality were self-made.

## Tech Stack

```text
Backend   : Flask, Scapy, Python
Frontend  : HTML, CSS, JavaScript
ML        : scikit-learn, pandas, joblib
Storage   : Rolling JSON snapshot
Platform  : Windows-compatible live capture workflow
```

## Project Structure

```text
nids-final/
|-- app.py
|-- backend/
|   |-- analyzer.py
|   |-- ml_detector.py
|   |-- sniffer.py
|   `-- storage.py
|-- data/
|-- models/
|-- reports/
|-- screenshots/
|-- scripts/
|-- static/
|   |-- app.js
|   |-- index.html
|   `-- styles.css
|-- PROJECT_REPORT.md
`-- requirements.txt
```

## Detection Pipeline

1. Capture live packets from the selected adapter.
2. Extract source, destination, protocol, size, ports, and flags.
3. Build flow-style features compatible with the trained model.
4. Run the ML model for `Normal` vs `Suspicious` prediction.
5. Apply rule-based checks for suspicious behavior.
6. Combine both signals into the final packet status.
7. Store and display the latest `50` packets, plus suspicious-only entries.

## Main Model

The primary model is a binary `ExtraTreesClassifier` trained for:

- `Normal`
- `Suspicious`

Model artifacts:

- [nids_model_hgb.pkl](./models/nids_model_hgb.pkl)
- [scaler.pkl](./models/scaler.pkl)
- [model_features.pkl](./models/model_features.pkl)
- [label_encoder.pkl](./models/label_encoder.pkl)

## Performance

Holdout results used for main model selection:

- Overall accuracy: `99.37%`
- Weakest compatible holdout segment: `75.76%`

Full compatibility evaluation:

- `cyberfed`: `94.97%`
- `cic-ddos`: `99.75%`
- `cic-portscan`: `99.89%`
- `cic-tuesday`: `99.87%`
- `cic-wednesday`: `99.58%`

Detailed reports:

- [Main Model Report](./reports/MAIN_MODEL_REPORT.md)
- [Evaluation JSON](./reports/main_model_eval.json)

## Dataset Sources

The following Kaggle references were used for dataset selection, model training direction, evaluation, and refinement:

- [Cyber Security Attacks](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)
- [Cyber Security Attacks](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)
- [Kaggle Discussion](https://www.kaggle.com/discussions/general/335189)
- [BETH Dataset](https://www.kaggle.com/datasets/katehighnam/beth-dataset)
- [Cyber Threat Detection](https://www.kaggle.com/datasets/hussainsheikh03/cyber-threat-detection)

KaggleHub references used during the workflow:

```python
import kagglehub

path = kagglehub.dataset_download("hussainsheikh03/cyber-threat-detection")
print("Path to dataset files:", path)

path = kagglehub.dataset_download("katehighnam/beth-dataset")
print("Path to dataset files:", path)

path = kagglehub.dataset_download("teamincribo/cyber-security-attacks")
print("Path to dataset files:", path)

path = kagglehub.dataset_download("teamincribo/cyber-security-attacks")
print("Path to dataset files:", path)
```

## Model Selection Summary

The AI-model workflow followed this process:

- study compatible cybersecurity datasets
- identify feature schemas usable for NIDS prediction
- compare suitable models on available data
- select the highest-accuracy practical models
- reconfigure those models into a common prediction pipeline
- integrate the final selected model into the live dashboard

In short, the datasets were used to identify suitable high-accuracy models, those models were tested, and the final components were reconfigured to work together collaboratively for prediction in this project.

## Run Locally

```powershell
cd C:\Users\Asus\Coding\CyberSecurity\nids-final
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## API Endpoints

- `GET /api/summary`
- `GET /api/packets?limit=50`
- `GET /api/suspicious?limit=50`
- `GET /api/status`
- `GET /api/interfaces`
- `POST /api/capture/start`
- `POST /api/capture/stop`
- `POST /api/reset`

## Train Or Re-Evaluate

```powershell
cd C:\Users\Asus\Coding\CyberSecurity\nids-final
python scripts\train_main_model.py
python scripts\evaluate_main_model.py
```

Useful files:

- [train_main_model.py](./scripts/train_main_model.py)
- [evaluate_main_model.py](./scripts/evaluate_main_model.py)
- [Project Report](./PROJECT_REPORT.md)

## Notes

- On Windows, live capture may require `Npcap` and an elevated terminal.
- Choose the real Wi-Fi or Ethernet adapter instead of loopback or inactive virtual adapters.
- Live packet prediction quality depends on how closely packet-derived features match training-time flow features.

## Easter Egg

Click the `NIDS Dashboard` title **5 times quickly**.

## Final Report

For the journey, challenges, development summary, and conclusion, see:

- [PROJECT_REPORT.md](./PROJECT_REPORT.md)
