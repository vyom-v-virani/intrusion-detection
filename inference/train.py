import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import pickle
import os

# ── Load data ──────────────────────────────────────────────────────────
df = pd.read_csv('data/friday.csv')
features = ['packet_size', 'protocol', 'ttl', 'src_port', 'dst_port', 'tcp_flags']
X = df[features].values
y = df['label'].values

# ── Scale features ─────────────────────────────────────────────────────
def normalize_features(X):
    mins = np.array([40, 0, 1, 1024, 1, 0])
    maxs = np.array([1500, 17, 128, 65535, 65535, 255])
    return (X - mins) / (maxs - mins + 1e-9)
X_scaled = normalize_features(X)

# ── Train/test split ───────────────────────────────────────────────────
split = int(0.8 * len(X_scaled))
X_train, X_test = X_scaled[:split], X_scaled[split:]
y_train, y_test = y[:split], y[split:]

# ──────────────────────────────────────────────────────────────────────
# Model 1: Isolation Forest
# Detects single packets that look anomalous compared to normal traffic
# ──────────────────────────────────────────────────────────────────────
print("Training Isolation Forest...")
iso_forest = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
iso_forest.fit(X_train[y_train == 0])  # train only on normal traffic

iso_preds = iso_forest.predict(X_test)
iso_preds = (iso_preds == -1).astype(int)  # -1 means anomaly in sklearn
print("Isolation Forest Results:")
print(classification_report(y_test, iso_preds, target_names=['Normal', 'Attack']))

# ──────────────────────────────────────────────────────────────────────
# Model 2: LSTM
# Detects patterns across sequences of packets over time
# ──────────────────────────────────────────────────────────────────────
print("\nTraining LSTM...")

SEQUENCE_LEN = 20  # look at 20 packets at a time

def make_sequences(X, y, seq_len):
    """Slide a window of seq_len across the data."""
    xs, ys = [], []
    for i in range(len(X) - seq_len):
        xs.append(X[i:i+seq_len])
        ys.append(y[i+seq_len])
    return np.array(xs), np.array(ys)

X_seq_train, y_seq_train = make_sequences(X_train, y_train, SEQUENCE_LEN)
X_seq_test, y_seq_test = make_sequences(X_test, y_test, SEQUENCE_LEN)

# Convert to PyTorch tensors
X_train_t = torch.FloatTensor(X_seq_train)
y_train_t = torch.FloatTensor(y_seq_train)
X_test_t = torch.FloatTensor(X_seq_test)
y_test_t = torch.FloatTensor(y_seq_test)

train_loader = DataLoader(TensorDataset(X_train_t, y_train_t), batch_size=64, shuffle=True)

class LSTMClassifier(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=0.2)
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return out.squeeze()

model = LSTMClassifier(input_size=len(features))
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
pos_weight = torch.tensor([4.0])
criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

# Train for 20 epochs
for epoch in range(20):
    model.train()
    total_loss = 0
    for X_batch, y_batch in train_loader:
        optimizer.zero_grad()
        preds = model(X_batch)
        loss = criterion(preds, y_batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    print(f"Epoch {epoch+1}/20 — loss: {total_loss/len(train_loader):.4f}")

# Evaluate LSTM
model.eval()
with torch.no_grad():
    lstm_preds = (torch.sigmoid(model(X_test_t)) > 0.5).int().numpy()
print("\nLSTM Results:")
print(classification_report(y_seq_test, lstm_preds, target_names=['Normal', 'Attack']))

# ── Save everything ────────────────────────────────────────────────────
os.makedirs('inference/models', exist_ok=True)
torch.save(model.state_dict(), 'inference/models/lstm.pt')
with open('inference/models/iso_forest.pkl', 'wb') as f:
    pickle.dump(iso_forest, f)

print("\nModels saved to inference/models/")
