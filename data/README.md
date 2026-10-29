# ThreatLens Data Directory

## Supported Datasets

1. **CIC-IDS2017 (Primary Reference)**
   - Provider: Canadian Institute for Cybersecurity, University of New Brunswick
   - URL: https://www.unb.ca/cic/datasets/ids-2017.html
   - Characteristics: 8 CSV files covering Monday to Friday traffic with natural normal background traffic (B-Profile) and 14 attack types.
   - Attack categories: DoS, DDoS, PortScan, Web Attack, Infiltration, Botnet, Heartbleed, Brute Force.

2. **UNSW-NB15 (Secondary Benchmark)**
   - Provider: Cyber Range Lab of UNSW Canberra
   - URL: https://research.unsw.edu.au/projects/unsw-nb15-dataset

3. **CSE-CIC-IDS2018 (Additional Evaluation Extension)**
   - Provider: Communications Security Establishment & CIC
   - URL: https://www.unb.ca/cic/datasets/ids-2018.html

## Local Sample Datasets Provided

- `data/cicids2017_sample.csv`: Curated subset (Benign, DoS Hulk, FTP-Patator, SSH-Patator) for baseline training and evaluation.
- `data/cicids2017_heldout_sample.csv`: Dedicated held-out attack records (PortScan, Infiltration, Botnet) alongside Benign traffic, specifically reserved for the **Unseen Attack / Zero-Day Simulation Protocol**.

## Data Leakage Prevention Guidelines

1. **Identifier Exclusion**: Flow ID, Source IP, Destination IP, and exact Timestamps are stripped prior to feature scaling. This ensures the model learns network behavior patterns rather than memorizing malicious IP addresses.
2. **Split Strictness**: Scalers and imputation medians are computed **strictly on the training partition** and never exposed to validation or test splits.
3. **Threshold Calibration**: The anomaly threshold is calibrated on the validation set only, never on the held-out test data.
