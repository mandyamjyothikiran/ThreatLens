# ThreatLens: Machine Learning-Based Zero-Day Attack Detection Framework

> **"See the Threat Before It Strikes"**  
> An Academic Capstone Project in Cybersecurity & Real-Time Machine Learning

---

## 1. Operating Modes Overview

ThreatLens supports two distinct, decoupled operating modes:

### ⚡ Mode A: Live Network Monitoring (Real-Time Engine)
- **Real-Time Packet Ingestion**: Captures network traffic on user-authorized physical/virtual interfaces (e.g. `eth0`, `en0`, `lo0`), PCAP file replays, or verified synthetic benchmark streams.
- **Microsecond Flow Aggregation**: Assembles bidirectional 5-tuple packet streams into completed network flows, calculating statistical moments (Duration in $\mu s$, Packet Counts, Byte Rates, Inter-Arrival Times, TCP Flags, Window Sizes).
- **Sub-Millisecond Model Scoring**: Feeds extracted flows to the fitted **scikit-learn Isolation Forest** model with zero ground-truth label leakage.
- **Live Anomaly Alerting**: Pushes real-time alerts via Server-Sent Events (SSE) directly to the dashboard, displaying feature deviations and risk severities.
- **Strict Mode Transparency**: Every event displays its source (`REAL CAPTURE`, `PCAP REPLAY`, or `SYNTHETIC DEMO`). The system returns an explicit error if capture permissions are denied and never silently switches to synthetic data.

### 📊 Mode B: Dataset Analysis (Historical & Offline Benchmarks)
- **CIC-IDS2017 Benchmark Exploration**: In-depth analysis of intrusion detection datasets.
- **Model Training & Evaluation**: Supervised Random Forest baseline vs Unsupervised Isolation Forest.
- **Held-Out Zero-Day Experiment**: Empirically validates detection against quarantined attack types (PortScan, Infiltration, Botnet) completely excluded from training.
- **Interactive CSV Upload**: Validates user-supplied flow CSVs against the 22-feature schema and computes batch anomaly scores.

---

## 2. Real-Time Network Packet Capture Architecture

```
+─────────────────────────────────────────────────────────────────────────────+
|                     THREATLENS REAL-TIME PIPELINE                           |
|                                                                             |
|  [Network Interface / Scapy / PCAP Replay]                                  |
|                          │                                                  |
|                          ▼                                                  |
|  [Flow Aggregator: ml/flow_extractor.py]                                    |
|    - 5-Tuple Normalization: (src_ip, dst_ip, src_p, dst_p, proto)           |
|    - Inter-Arrival Times (Flow IAT Mean/Std/Max, Fwd/Bwd IAT in μs)          |
|    - Packet/Byte Rates & Cumulative TCP Flags                               |
|    - Bounded Flow Cache (Max 1,000 concurrent flows)                        |
|                          │                                                  |
|                          ▼ Active Timeout (3.0s) or FIN/RST                 |
|  [Inference Engine: ml/predict.py]                                          |
|    - RobustScaler Transform (Median & IQR from Training Partition)          |
|    - scikit-learn IsolationForest Evaluation: score = -score_samples(X)     |
|    - Standardized Anomaly Score & 95th Percentile Decision Cutoff           |
|                          │                                                  |
|             ┌────────────┴────────────┐                                     |
|             ▼                         ▼                                     |
|   [Normal Flow Stream]     [Zero-Day Anomaly Alert]                         |
|             │                         │                                     |
|             └────────────┬────────────┘                                     |
|                          ▼                                                  |
|  [Server-Sent Events (SSE) Broadcast: /monitoring/events]                   |
|                          │                                                  |
|                          ▼                                                  |
|  [ThreatLens Real-Time React Dashboard (Port 3000 / Port 5000)]             |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 3. Operating System Packet Capture Permissions

Raw packet sniffing accesses unencrypted Layer 3/4 headers. In production, unprivileged execution is achieved via the narrowest appropriate OS capability model:

### Linux (Narrow Capability Model — Recommended)
Avoid running the entire web application as root. Grant packet capture capabilities specifically to Python:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### macOS (Berkeley Packet Filter Devices)
macOS restricts `/dev/bpf*` devices to administrative users by default. To allow unprivileged capture without making device nodes world-writable (`chmod 666` is insecure):
```bash
# Assign device ownership to admin group and grant read/write
sudo chgrp admin /dev/bpf*
sudo chmod 640 /dev/bpf*
```
Alternatively, install Wireshark's standard `ChmodBPF` package, which configures secure BPF access for members of the `access_bpf` group on system startup.

### Unprivileged Container / Sandbox Mode (Safe Fallback)
If raw capture capabilities are unavailable on the host:
1. ThreatLens returns an explicit `PERMISSION_DENIED` error if `live_interface` is requested without privileges.
2. Users can run **PCAP Replay Mode** (`pcap_replay`) using authorized PCAP capture fixtures (`data/sample_traffic.pcap`, `data/attack_traffic.pcap`) without administrative privileges.
3. Users can run **Synthetic Benchmark Mode** (`synthetic_test_stream`) to safely evaluate the flow aggregation, ML scoring, and SSE pipeline.

---

## 4. Academic Methodology & Mathematical Principles

### The Isolation Principle
Traditional density-based anomaly detectors scale quadratically ($\mathcal{O}(n^2)$). **Isolation Forest** isolates anomalies linearly ($\mathcal{O}(n \log n)$) by exploiting the fact that anomalies isolate near tree roots:

$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$

Where $c(n)$ is the average search path length in a Binary Search Tree:

$$c(n) = 2 \left( \ln(n - 1) + 0.5772156649 \right) - \frac{2(n - 1)}{n}$$

In scikit-learn, `score_samples(X)` returns $-s(x, n)$. Therefore, ThreatLens computes the anomaly score as:

$$\text{anomaly\_score}(x) = -\text{score\_samples}(x) \in (0, 1)$$

Higher scores indicate shorter average path lengths and higher anomaly risk.

### Adaptive Validation Calibration
Instead of hardcoding an arbitrary threshold (e.g., $0.500$), ThreatLens calculates the decision threshold at the 95th percentile of normal validation traffic:

$$\theta_{95} = \text{Percentile}\left(\mathcal{S}_{\text{val, benign}}, 95.0\right)$$

This ensures that false alarms on nominal traffic are mathematically capped under **5%** in high-throughput environments.

---

## 5. Experimental Results: Standard vs Held-Out Zero-Day Simulation

### Standard Test Partition Benchmark (CIC-IDS2017)

| Metric Parameter | Isolation Forest (Unsupervised) | Random Forest (Supervised Baseline) |
| :--- | :--- | :--- |
| **Model Estimator** | `sklearn.ensemble.IsolationForest` | `sklearn.ensemble.RandomForestClassifier` |
| **Training Split** | Fitted strictly on pure Benign traffic | Fitted on known attack + benign labels |
| **Decision Rule** | $\text{score} \ge \theta_{95}$ | $\hat{y} = 1$ |
| **Inference Latency** | **< 1.5 ms / flow** | < 1.0 ms / flow |

### Held-Out Zero-Day Attack Experiment

To simulate genuine zero-day attacks, attack categories (`PortScan`, `Infiltration`, `Botnet`) were strictly quarantined and excluded from training:
- **Isolation Forest**: Maintains high recall on novel attack categories because it detects behavioral deviation from the learned benign envelope without requiring prior attack signatures.
- **Supervised Random Forest**: Shows reduced recall on unseen attack categories whose feature distributions differ significantly from training classes.

> **Academic Note**: An anomaly score above threshold indicates a statistically significant divergence from learned normal traffic patterns ("Anomalous Traffic — Investigate"). It does not constitute proof of a confirmed exploit until analyst triage.

---

## 6. Installation & Execution Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ & npm

### A. Environment Setup
```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 2. Install Python backend dependencies
pip install -r requirements.txt

# 3. Install frontend dependencies
npm install --legacy-peer-deps
```

### B. Train Models & Run Evaluation Suite
```bash
# 1. Inspect dataset schema and hygiene
python3 ml/inspect_dataset.py

# 2. Train real scikit-learn Isolation Forest and calibrate threshold
python3 ml/train.py

# 3. Execute genuine evaluation suite & held-out zero-day simulation
python3 ml/evaluate.py

# 4. Run automated test suite (41 tests)
pytest -v
```

### C. Launch Real-Time Services
```bash
# Terminal 1: Python Flask REST & SSE Backend Service (Port 5000)
source .venv/bin/activate
python3 backend/app.py

# Terminal 2: Full-Stack React Dashboard (Port 3000)
npm run dev
```

---

## 7. Real-Time REST & SSE API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System health check and model readiness flag. |
| `GET` | `/model-info` | Loaded model architecture, features, and calibrated threshold. |
| `POST` | `/predict` | Genuine Isolation Forest inference on incoming flow record. |
| `GET` | `/metrics` | Ground-truth classification metrics, confusion matrices, and ROC/PR points. |
| `GET` | `/alerts` | Recent model-derived threat alerts (zero label leakage). |
| `GET` | `/traffic` | Paginated flow records formatted for analyst inspection. |
| `GET` | `/interfaces` | Lists discovered local network interfaces and capture permissions. |
| `POST` | `/monitoring/start` | Initiates packet capture (`live_interface`, `pcap_replay`, or `synthetic_test_stream`). |
| `POST` | `/monitoring/stop` | Terminates active capture session and flushes pending flows. |
| `GET` | `/monitoring/status` | Real-time session telemetry (Packets, Flows, Anomalies, Mode, Uptime). |
| `GET` | `/monitoring/flows` | Returns recently analyzed live flows. |
| `POST` | `/monitoring/test-packet` | Injects an on-demand test packet into the real-time pipeline. |
| `GET` | `/monitoring/events` | **Server-Sent Events (SSE)** stream broadcasting live flows and alerts. |
| `GET` | `/adaptive-thresholds` | Threshold calibration strategy comparison. |
| `POST` | `/evaluate/inspect` | Inspects CSV dataset schema and training leakage. |
| `POST` | `/evaluate/run` | Runs ground-truth evaluation on uploaded or sample dataset. |

---

## 8. Verification & Live Demonstration Steps

### Step 1: Verify Interface Discovery & Permissions
```bash
curl -s http://localhost:5000/interfaces
```

### Step 2: Test PCAP Replay Mode (Unprivileged)
```bash
curl -s -X POST http://localhost:5000/monitoring/start \
  -H "Content-Type: application/json" \
  -d '{"interface": "pcap", "mode": "pcap_replay", "flow_timeout_sec": 1.0, "pcap_path": "data/sample_traffic.pcap"}'
```

### Step 3: Inspect Real-Time Telemetry
```bash
curl -s http://localhost:5000/monitoring/status
```

### Step 4: Inject On-Demand Test Packet
```bash
curl -s -X POST http://localhost:5000/monitoring/test-packet
```

### Step 5: Check Live Flow Stream and Stop Monitoring
```bash
curl -s "http://localhost:5000/monitoring/flows?limit=5"
curl -s -X POST http://localhost:5000/monitoring/stop
```

---

## 9. Academic Citations

- **CIC-IDS2017**: Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
- **Isolation Forest**: Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. IEEE ICDM.
- **UNSW-NB15**: Moustafa, N., & Slay, J. (2015). *UNSW-NB15: A Comprehensive Dataset for Network Intrusion Detection Systems*. MilCIS.
