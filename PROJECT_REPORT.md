# Project Report

## Project Summary

This project is a Network Intrusion Detection System built to capture live network packets, analyze them with rule-based logic and trained machine learning models, and present the results on a live dashboard.

The final system combines:

- Live packet capture with Scapy
- Rule-based suspicious activity detection
- Machine learning based traffic classification
- A rolling dashboard with recent packets and suspicious packet cache

## Development Journey

The project started as a simple beginner-friendly NIDS idea with:

- Packet capture
- Basic feature extraction
- Simple safe vs suspicious rules
- A lightweight dashboard

From there, the project was expanded into a more complete system by:

- Building a working Flask backend
- Connecting live packet capture to real-time analysis
- Integrating stored ML models and evaluation scripts
- Limiting the dashboard to the most recent 50 entries
- Creating a separate temporary suspicious packet panel
- Improving adapter naming for easier live capture selection
- Reworking the main model so it performs reliably on compatible datasets

## Challenges Faced

- Live traffic and dataset traffic did not match perfectly, so raw packet data had to be converted into features that aligned with trained model expectations.
- Windows network capture exposed raw Npcap interface IDs such as `\Device\NPF_{...}`, which were not user-friendly and had to be translated into readable adapter labels.
- Some virtual adapters, loopback interfaces, and tunnel interfaces produced confusing traffic that increased false positives.
- Initial model integration produced too many suspicious labels because real-world traffic is noisier than curated dataset samples.
- The trained model artifacts and runtime environment had to be aligned carefully so version mismatches and warning noise did not break the workflow.

## What Was Built

- Backend and functional system design were self-made.
- Frontend dashboard styling and layout were made with the help of AI.
- Backend packet capture, feature engineering, model integration, APIs, logic, and project workflow were implemented manually and integrated into the final system.

## Project Screenshots

### Dashboard Overview

![Dashboard Overview](./screenshots/dashboard-overview.png)

### Recent Packet Logs

![Recent Packet Logs](./screenshots/dashboard-packets.png)

### Suspicious Packet Panel

![Suspicious Packet Panel](./screenshots/dashboard-suspicious-panel.png)

## Datasets Used

The following Kaggle sources were used as references for dataset selection, model evaluation, and training decisions:

- [Cyber Security Attacks](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)
- [Cyber Security Attacks](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)
- [Kaggle Discussion](https://www.kaggle.com/discussions/general/335189)
- [BETH Dataset](https://www.kaggle.com/datasets/katehighnam/beth-dataset)
- [Cyber Threat Detection](https://www.kaggle.com/datasets/hussainsheikh03/cyber-threat-detection)

Dataset download references used during the project:

```python
import kagglehub

# Download latest version
path = kagglehub.dataset_download("hussainsheikh03/cyber-threat-detection")
print("Path to dataset files:", path)

import kagglehub

# Download latest version
path = kagglehub.dataset_download("katehighnam/beth-dataset")
print("Path to dataset files:", path)

import kagglehub

# Download latest version
path = kagglehub.dataset_download("teamincribo/cyber-security-attacks")
print("Path to dataset files:", path)

import kagglehub

# Download latest version
path = kagglehub.dataset_download("teamincribo/cyber-security-attacks")
print("Path to dataset files:", path)
```

## Model Selection Approach

Using the Kaggle datasets, suitable models were tested and compared based on accuracy and compatibility with the project’s packet and flow features.

The process was:

- Identify datasets relevant to network intrusion and cyberattack traffic
- Train and evaluate candidate models
- Choose the highest-accuracy suitable models
- Reconfigure and adapt the selected models so they could work together in the final project pipeline
- Integrate the final selected model into the live prediction system

The resulting system uses the selected high-accuracy model artifacts together with rule-based checks so that live traffic can be judged for prediction in the project dashboard.

## Final Outcome

The final project is a practical NIDS prototype that:

- Captures real traffic
- Detects suspicious behavior using rules and ML
- Displays the latest network activity in a clear dashboard
- Separates suspicious packet activity into its own panel
- Uses trained models selected from tested dataset-based experiments

## Conclusion

This project evolved from a simple NIDS concept into a more complete real-time monitoring system. The main achievement was combining self-built backend functionality with trained ML models and a clean live dashboard, while adapting multiple datasets and model outputs into a single working pipeline.
