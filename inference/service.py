from kafka import KafkaConsumer
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import torch
import torch.nn as nn
import pickle
import json
import numpy as np
from collections import deque, defaultdict
import time

# ── Config ─────────────────────────────────────────────────────────────
KAFKA_BROKER = 'localhost:9092'
INFLUX_URL = 'http://localhost:8086'
INFLUX_TOKEN = 'mytoken123'
INFLUX_ORG = 'ids-org'
INFLUX_BUCKET = 'network-traffic'
SEQUENCE_LEN = 20
FEATURES = ['packet_size', 'protocol', 'ttl', 'src_port', 'dst_port', 'tcp_flags']
# ── Normalization ──────────────────────────────────────────────────────
def normalize(val, min_val, max_val):
    return (val - min_val) / (max_val - min_val + 1e-9)

def normalize_packet(p):
    mins = np.array([40, 0, 1, 1024, 1, 0])
    maxs = np.array([1500, 17, 128, 65535, 65535, 255])
    return (np.array([
        p.get('packet_size', 0),
        p.get('protocol', 0),
        p.get('ttl', 0),
        p.get('src_port', 0),
        p.get('dst_port', 0),
        p.get('tcp_flags', 0)
    ]) - mins) / (maxs - mins + 1e-9)

# ── Load models ────────────────────────────────────────────────────────
with open('inference/models/iso_forest.pkl', 'rb') as f:
    iso_forest = pickle.load(f)

class LSTMClassifier(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=0.2)
        self.fc = nn.Linear(hidden_size, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return out.squeeze()

lstm_model = LSTMClassifier(input_size=len(FEATURES))
lstm_model.load_state_dict(torch.load('inference/models/lstm.pt'))
lstm_model.eval()

# ── InfluxDB client ────────────────────────────────────────────────────
def get_write_api():
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    return client, client.write_api(write_options=SYNCHRONOUS)

influx_client, write_api = get_write_api()

# ── Kafka consumer ─────────────────────────────────────────────────────
consumer = KafkaConsumer(
    'network-packets',
    bootstrap_servers=KAFKA_BROKER,
    auto_offset_reset='latest',
    value_deserializer=lambda v: json.loads(v.decode('utf-8'))
)

packet_window = deque(maxlen=SEQUENCE_LEN)

print("Inference service running — waiting for packets...")

for message in consumer:
    packet = message.value

    feature_vec = np.array([normalize_packet(packet)])

    # ── Isolation Forest ───────────────────────────────────────────
    iso_score = float(iso_forest.decision_function(feature_vec)[0])

    # ── LSTM ───────────────────────────────────────────────────────
    packet_window.append(feature_vec[0])
    lstm_score = 0.0
    if len(packet_window) == SEQUENCE_LEN:
        seq = torch.FloatTensor(np.array(list(packet_window))).unsqueeze(0)
        with torch.no_grad():
            lstm_score = float(torch.sigmoid(lstm_model(seq)))

    is_attack = int(lstm_score > 0.7)

    # ── Write to InfluxDB ──────────────────────────────────────────
    point = (
        Point("packet")
        .tag("is_attack", str(is_attack))
        .tag("protocol", str(packet.get('protocol', 0)))
        .field("packet_size", float(packet.get('packet_size', 0)))
        .field("src_port", float(packet.get('src_port', 0)))
        .field("dst_port", float(packet.get('dst_port', 0)))
        .field("iso_score", iso_score)
        .field("lstm_score", lstm_score)
        .field("is_attack", is_attack)
    )
    try:
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    except Exception:
        try:
            influx_client, write_api = get_write_api()
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        except Exception:
            pass  # silently skip if InfluxDB still unavailable

    status = "🚨 ATTACK" if is_attack else "✅ normal"
    print(f"{status} | src={packet.get('src_ip')} dst={packet.get('dst_ip')} | lstm={lstm_score:.4f} iso={iso_score:.3f}")