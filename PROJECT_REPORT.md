# Network Intrusion Detection System (NIDS)

**Siddhant Singh**  
**CSE 28, CSE Branch**  
**Madan Mohan Malaviya University of Technology, Gorakhpur**  
**Cybersecurity project task given by Dr. V. Kumar sir**

## Abstract

This project presents a practical Network Intrusion Detection System (NIDS) for real-time traffic monitoring, suspicious activity detection, and dashboard-based visualization. The system combines live packet capture using Scapy, rule-based traffic analysis, feature engineering, and machine-learning-based prediction to classify observed traffic as either `Normal` or `Suspicious`. A Flask backend was built to support the capture pipeline, REST APIs, storage logic, and model integration, while the frontend dashboard was designed with AI assistance for better visual presentation and usability. Multiple cybersecurity datasets were studied and evaluated to identify suitable model configurations for deployment in the project. The final system supports live interface selection, rolling packet logs, suspicious packet caching, and a documented evaluation pipeline. The resulting project serves as a working educational cybersecurity system that connects theoretical intrusion-detection ideas with practical real-time implementation.

## Keywords

Network Intrusion Detection System, NIDS, Cybersecurity, Flask, Scapy, Packet Analysis, Machine Learning, Intrusion Detection, Network Monitoring

## 1 Introduction

Modern computer networks face a wide range of threats including denial-of-service attempts, brute-force behavior, scanning activity, and suspicious traffic bursts. Traditional monitoring methods often rely only on logs or manual inspection, which makes real-time threat understanding difficult. A Network Intrusion Detection System helps bridge this gap by continuously observing network traffic and highlighting unusual or malicious behavior.

The objective of this project was to design and implement a practical NIDS that can inspect real network traffic and present findings through a usable dashboard. The project began as a beginner-friendly packet-monitoring idea and gradually evolved into a complete system integrating live packet capture, hybrid detection logic, machine-learning-assisted prediction, and a user-facing monitoring interface.

This work was completed as a cybersecurity project task under the guidance of **Dr. V. Kumar sir**, for the **CSE branch at Madan Mohan Malaviya University of Technology, Gorakhpur**.

## 2 Problem Statement

The project aimed to solve the following practical problem:

- how to capture real packets from the network
- how to extract useful features from those packets
- how to classify observed activity into safe and suspicious behavior
- how to present live analysis in a clean and understandable dashboard
- how to evaluate and select suitable ML models from available cybersecurity datasets

The goal was not just to build a static classifier, but to create a working pipeline that could support live prediction and dashboard-based monitoring.

## 3 Objectives

The main objectives of the project were:

- to capture packets from real network interfaces
- to extract network-level attributes such as IPs, protocol, ports, packet size, and flags
- to apply simple but practical rule-based intrusion checks
- to integrate trained ML models into the detection workflow
- to store and display only the latest relevant entries for usability
- to create a separate panel for suspicious packet activity
- to evaluate dataset-driven models and select a suitable main model for deployment

## 4 System Overview

The final NIDS system contains the following major components:

- **Packet Capture Layer**  
  Uses Scapy to capture live packets from selected network interfaces.

- **Feature Extraction Layer**  
  Extracts packet-level attributes and derives flow-style features required by the ML model.

- **Rule-Based Detection Layer**  
  Detects suspicious conditions such as excessive packet bursts from one source and suspicious public-host traffic on unusual ports.

- **Machine Learning Layer**  
  Uses a trained binary classifier to predict `Normal` or `Suspicious` traffic.

- **Storage Layer**  
  Maintains rolling recent packet history and a separate suspicious-only cache.

- **Frontend Dashboard**  
  Displays packet summaries, recent logs, suspicious logs, and interface-driven monitoring controls.

## 5 Methodology

### 5.1 Packet Capture

The project uses Scapy for live packet capture. Network interfaces are discovered dynamically and displayed with friendly names instead of raw Npcap identifiers, making real capture easier on Windows systems.

### 5.2 Feature Extraction

For each captured packet, the following information is collected or derived:

- source IP
- destination IP
- source port
- destination port
- protocol
- packet size
- TCP flags
- flow-based derived metrics such as packet rate and byte rate

These values are then transformed into a model-compatible feature vector.

### 5.3 Rule-Based Detection

Rule-based checks were included to provide fast interpretable intrusion indicators. The key rules include:

- unusually high packet rate from the same source
- suspicious destination-port behavior for non-private traffic

These rules work alongside the ML output rather than replacing it.

### 5.4 Machine Learning Integration

A dataset-driven model selection process was used to identify a practical main classifier. The deployed main model is a binary `ExtraTreesClassifier` trained for:

- `Normal`
- `Suspicious`

The model is integrated into the packet analysis pipeline so live traffic can be judged in real time.

### 5.5 Dashboard and Visualization

The dashboard displays:

- total packets
- safe packets
- suspicious packets
- latest 50 packet entries
- suspicious-only rolling cache

This design keeps the monitoring view readable even during continuous traffic capture.

## 6 Datasets Used

The following Kaggle sources were used as references for dataset selection, analysis, and model evaluation:

- [Cyber Security Attacks](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)
- [Cyber Security Attacks](https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks)
- [Kaggle Discussion](https://www.kaggle.com/discussions/general/335189)
- [BETH Dataset](https://www.kaggle.com/datasets/katehighnam/beth-dataset)
- [Cyber Threat Detection](https://www.kaggle.com/datasets/hussainsheikh03/cyber-threat-detection)

KaggleHub download references used during the project:

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

From these datasets, suitable high-accuracy models were tested and compared. The selected models and processing steps were then reconfigured so they could collaborate properly inside the final project pipeline.

## 7 Model Selection and Evaluation

The model selection process involved:

- identifying datasets compatible with network intrusion analysis
- comparing candidate models based on performance and practical deployment suitability
- selecting high-accuracy models
- reworking the final pipeline so the chosen model could support live packet prediction

The final deployed main model achieved:

- **Overall holdout accuracy:** `99.37%`
- **Weakest compatible holdout segment:** `75.76%`

Compatibility evaluation on larger dataset slices showed:

- `cyberfed`: `94.97%`
- `cic-ddos`: `99.75%`
- `cic-portscan`: `99.89%`
- `cic-tuesday`: `99.87%`
- `cic-wednesday`: `99.58%`

These values show that the selected main model was not chosen arbitrarily, but through a dataset-backed evaluation process.

## 8 Implementation Details

### 8.1 Backend

The backend and core functioning of the project were self-made. The backend handles:

- live capture control
- packet analysis
- ML prediction
- API endpoints
- rolling data storage
- suspicious packet caching

### 8.2 Frontend

The frontend dashboard design and styling were created with the help of AI. This support was used mainly for:

- dashboard layout
- styling structure
- presentation quality
- visual clarity

The backend logic, system architecture, detection pipeline, model integration, and project functionality were implemented manually.

## 9 Challenges Faced

Several practical challenges were encountered during development:

- Live packet data does not perfectly match curated dataset formats.
- Raw Windows capture adapters appear as `\Device\NPF_{...}` and needed friendly renaming.
- Virtual adapters, tunnel adapters, and loopback interfaces can create misleading traffic views.
- Early versions of the model integration produced excessive suspicious classifications.
- Model artifact versions had to be aligned with the runtime environment.
- Large tracked model files created GitHub repository management issues.

Each of these was addressed through iterative refinement of the detection logic, model pipeline, interface naming, repository cleanup, and documentation.

## 10 Project Journey

The journey of the project can be summarized as follows:

1. Start from a simple packet-monitoring NIDS concept.
2. Build a basic working backend around live capture and safe/suspicious classification.
3. Add a frontend dashboard for visualization.
4. Study available datasets for intrusion and cyberattack patterns.
5. Evaluate and select suitable models.
6. Reconfigure the selected model pipeline for the project’s live traffic workflow.
7. Improve usability through rolling logs, suspicious cache, screenshots, reports, and GitHub documentation.

This progression transformed the project from a simple prototype into a more complete real-time NIDS system.

## 11 Results

The final project successfully demonstrates:

- live packet inspection
- dashboard-based monitoring
- hybrid rule + ML detection
- suspicious traffic caching
- model evaluation and documented deployment
- project-level documentation suitable for GitHub presentation and academic submission

The implementation works as a practical educational prototype for understanding the relationship between packet capture, intrusion analysis, machine-learning-assisted classification, and user-facing monitoring.

## 12 Conclusion

This project demonstrates how a Network Intrusion Detection System can be developed from a simple concept into a working real-time cybersecurity system. By combining Scapy-based live capture, rule-based analysis, feature extraction, machine learning, and dashboard visualization, the system provides a meaningful demonstration of practical intrusion-detection workflow. The project also highlights the importance of adapting dataset-driven models carefully before deploying them in live environments.

Overall, the final NIDS project meets its main objectives and serves as a strong educational and practical cybersecurity implementation.

## Acknowledgment

The project was completed as a cybersecurity task under the guidance of **Dr. V. Kumar sir** for the **CSE branch at Madan Mohan Malaviya University of Technology, Gorakhpur**.

Frontend dashboard design support was taken with the help of AI, while the backend architecture, integration logic, and project functionality were developed manually.

## Project Screenshots

### Dashboard Overview

![Dashboard Overview](https://raw.githubusercontent.com/Singh-Siddhant/NIDS-portal/main/dashboard-overview.png)

### Recent Packet Logs

![Recent Packet Logs](https://raw.githubusercontent.com/Singh-Siddhant/NIDS-portal/main/dashboard-packets.png)

### Suspicious Packet Panel

![Suspicious Packet Panel](https://raw.githubusercontent.com/Singh-Siddhant/NIDS-portal/main/dashboard-suspicious-panel.png)

## References

1. TeamIncribo, *Cyber Security Attacks*. Kaggle. Available at: https://www.kaggle.com/datasets/teamincribo/cyber-security-attacks
2. Kate Highnam, *BETH Dataset*. Kaggle. Available at: https://www.kaggle.com/datasets/katehighnam/beth-dataset
3. Hussain Sheikh, *Cyber Threat Detection*. Kaggle. Available at: https://www.kaggle.com/datasets/hussainsheikh03/cyber-threat-detection
4. Kaggle Discussion Thread. Available at: https://www.kaggle.com/discussions/general/335189
