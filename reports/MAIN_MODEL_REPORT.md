# Main Model Report

## Main model

- Model: `ExtraTreesClassifier`
- Task: binary `Normal` vs `Suspicious`
- Artifact path: `nids-final-v/models/nids_model_hgb.pkl`

## Training setup

- Source datasets:
  - `cyber-threat-detection/cyberfeddefender_dataset.csv`
  - `network-intrusion-dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  - `network-intrusion-dataset/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  - `network-intrusion-dataset/Tuesday-WorkingHours.pcap_ISCX.csv`
  - `network-intrusion-dataset/Wednesday-workingHours.pcap_ISCX.csv`
- Shared feature set: 14 overlapping flow features
- Output classes:
  - `Normal`
  - `Suspicious`

## Holdout test result

This is the defensible number for model selection because it comes from a train/test split during training.

- Overall accuracy: `99.37%`
- Per-dataset accuracy on the holdout split:
  - `cyberfed`: `75.76%`
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX`: `99.74%`
  - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX`: `99.90%`
  - `Tuesday-WorkingHours.pcap_ISCX`: `99.62%`
  - `Wednesday-workingHours.pcap_ISCX`: `99.62%`

## Full dataset evaluation

These runs confirm the saved model works across the compatible datasets, but they are not pure unseen-data metrics because the training pipeline sampled from the same source files.

- `cyberfed`: `94.97%`
- `cic-ddos`: `99.75%`
- `cic-portscan`: `99.89%`
- `cic-tuesday`: `99.87%`
- `cic-wednesday`: `99.58%`

## Interpretation

- The main model clears the requested threshold of `75%` on the weakest compatible holdout segment.
- It clears `80%` easily on aggregate metrics.
- The live dashboard now has a better-aligned primary model for `Safe` vs `Suspicious` decisions than the older 4-class artifact.

## Reproduce

```powershell
cd C:\Users\Asus\Coding\CyberSecurity\nids-final-v
python scripts\train_main_model.py
python scripts\evaluate_main_model.py
```
