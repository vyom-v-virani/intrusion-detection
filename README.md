# Real-Time Network Intrusion Detection System

A production-grade ML pipeline that captures live network traffic, detects attacks in real time using an LSTM + Isolation Forest ensemble, and visualizes anomaly scores on a live Grafana dashboard.

## Demo

The system correctly identifies DDoS and port scan attacks as they happen:

✅ normal | src=10.239.76.53 dst=142.250.80.46 | lstm=0.0056
🚨 ATTACK | src=192.168.1.1 dst=10.239.76.53 | lstm=0.7679
🚨 ATTACK | src=192.168.1.2 dst=10.239.76.53 | lstm=0.9568
🚨 ATTACK | src=192.168.1.3 dst=10.239.76.53 | lstm=0.9958
✅ normal | src=10.239.76.53 dst=142.250.80.46 | lstm=0.0082

## Architecture

Network Traffic → Scapy → Kafka → ML Inference → InfluxDB → Grafana

Each component runs as an independent service. Scapy captures packets and produces to Kafka. The inference service consumes from Kafka, scores packets through both models, and writes results to InfluxDB. Grafana queries InfluxDB and renders a live dashboard.

## Stack

| Component           | Technology                    |
| ------------------- | ----------------------------- |
| Packet capture      | Scapy                         |
| Message broker      | Apache Kafka                  |
| Sequence model      | PyTorch LSTM                  |
| Anomaly detection   | scikit-learn Isolation Forest |
| Time-series storage | InfluxDB 2.7                  |
| Live dashboard      | Grafana                       |
| Orchestration       | Kubernetes                    |
| Local dev           | Docker Compose                |

## ML Models

### LSTM (PyTorch)

A 2-layer LSTM with hidden size 64 trained on sequences of 20 consecutive packets. Learns temporal burst patterns — DDoS attacks appear as clusters of tiny UDP packets hitting the same port, port scans appear as sequential destination port increments. Achieves **99% accuracy and 98% attack recall** on the test set.

### Isolation Forest (scikit-learn)

Trained exclusively on benign traffic. Scores individual packets by measuring how quickly they get isolated from the normal cluster — anomalous packets isolate faster. Achieves **95% accuracy**.

### Training Data

Synthetic data engineered to mirror CICIDS attack profiles — DDoS (tiny UDP bursts to port 80), port scan (sequential SYN packets), and brute force (repeated SSH connection attempts). Attacks are generated in consecutive bursts so the LSTM has realistic temporal patterns to learn from.

## Hard Problems Solved

### 1. Backpressure and Rate Limiting

During DDoS simulation, Scapy captured packets faster than the inference service could process them, causing Kafka consumer lag to grow unboundedly. Implemented a token bucket rate limiter on the Kafka producer — refills at 500 tokens/second with burst capacity of 1000. This kept consumer lag near zero during attack simulation while allowing short legitimate bursts through.

### 2. Class Imbalance and Temporal Structure

Initial LSTM training achieved 0% attack recall. The root cause was that randomly scattered attack packets meant any 20-packet window looked statistically identical to normal traffic — no temporal signal to learn. Restructured the data generator to produce attacks in consecutive bursts of 30-60 packets, dropping loss from 0.49 to 0.04 and recall from 0% to 98%.

## Results

| Model            | Accuracy | Attack Recall | False Positive Rate |
| ---------------- | -------- | ------------- | ------------------- |
| LSTM             | 99%      | 98%           | 1%                  |
| Isolation Forest | 95%      | 69%           | 5%                  |

## Project Structure

intrusion-detection/
├── capture/
│ └── producer.py # Scapy capture + token bucket rate limiter
├── inference/
│ ├── train.py # LSTM + Isolation Forest training
│ └── service.py # Kafka consumer + ML inference + InfluxDB writer
├── data/
│ └── generate.py # Synthetic training data generator
├── tests/
│ └── simulate_attack.py # DDoS + port scan simulation scripts
├── kubernetes/ # K8s deployment manifests
├── Dockerfile # Inference service container
└── docker-compose.yml # Local development environment

## Running Locally

**Requirements:** Docker Desktop, Python 3.12

**1. Start infrastructure:**

```bash
docker-compose up -d
```

**2. Install dependencies:**

```bash
pip install -r requirements.txt
```

**3. Generate training data and train models:**

```bash
python data/generate.py
python inference/train.py
```

**4. Start inference service:**

```bash
python inference/service.py
```

**5. Start packet capture:**

```bash
python capture/producer.py
```

**6. Simulate an attack:**

```bash
python tests/simulate_attack.py
```

**7. View live dashboard:** `http://localhost:3000` (admin/admin)

## Deployment

Build and push the inference service image:

```bash
docker build -t ids-inference:latest .
docker push your-registry/ids-inference:latest
```

Deploy to Kubernetes:

```bash
kubectl apply -f kubernetes/
```
