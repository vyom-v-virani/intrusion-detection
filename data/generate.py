import pandas as pd
import numpy as np

np.random.seed(42)

def generate_normal_traffic(n):
    """Normal traffic - random sources, varied sizes, common ports."""
    return pd.DataFrame({
        'packet_size': np.random.normal(500, 150, n).clip(50, 1500),
        'protocol': np.random.choice([6, 17], n, p=[0.7, 0.3]),
        'ttl': np.random.normal(64, 5, n).clip(40, 128),
        'src_port': np.random.randint(32768, 60999, n),
        'dst_port': np.random.choice([80, 443, 22, 53, 8080, 8443, 3478, 5228], n, p=[0.3, 0.4, 0.05, 0.1, 0.05, 0.05, 0.025, 0.025]),
        'tcp_flags': np.random.choice([2, 18, 16, 24], n, p=[0.3, 0.3, 0.2, 0.2]),
        'label': 0
    })

def generate_ddos_burst(n):
    """
    DDoS pattern — same few source IPs, tiny packets, 
    hammering the same destination port rapidly.
    """
    src_ips = np.random.randint(0, 5, n)  # only 5 unique attackers
    return pd.DataFrame({
        'packet_size': np.random.normal(60, 10, n).clip(40, 100),  # tiny packets
        'protocol': np.full(n, 17),  # all UDP
        'ttl': np.random.normal(25, 3, n).clip(1, 40),  # low TTL
        'src_port': (src_ips * 1000 + np.random.randint(0, 100, n)),  # clustered ports
        'dst_port': np.full(n, 80),  # all hitting port 80
        'tcp_flags': np.full(n, 0),  # no flags (UDP)
        'label': 1
    })

def generate_port_scan(n):
    """
    Port scan pattern — one source IP, sequential destination ports,
    small SYN packets probing for open ports.
    """
    return pd.DataFrame({
        'packet_size': np.random.normal(54, 2, n).clip(40, 60),  # tiny SYN packets
        'protocol': np.full(n, 6),  # all TCP
        'ttl': np.random.normal(45, 3, n).clip(30, 60),
        'src_port': np.random.randint(40000, 50000, n),  # high fixed src port
        'dst_port': np.arange(n) % 65535,  # sequential port scanning
        'tcp_flags': np.full(n, 2),  # all SYN flags
        'label': 1
    })

def generate_brute_force(n):
    """
    Brute force pattern — repeated connection attempts to port 22 (SSH),
    medium sized packets, same source.
    """
    return pd.DataFrame({
        'packet_size': np.random.normal(200, 20, n).clip(100, 300),
        'protocol': np.full(n, 6),  # all TCP
        'ttl': np.random.normal(55, 2, n).clip(40, 64),
        'src_port': np.random.randint(30000, 35000, n),  # narrow port range
        'dst_port': np.full(n, 22),  # all targeting SSH
        'tcp_flags': np.random.choice([2, 18, 4], n, p=[0.5, 0.3, 0.2]),  # SYN/ACK/RST
        'label': 1
    })

# ── Build sequences with realistic temporal structure ──────────────────
# Normal traffic is randomly interleaved
# Attacks come in bursts of 20-50 consecutive packets (so LSTM sees the pattern)

segments = []

# Add normal traffic in chunks
for _ in range(40):
    n = np.random.randint(150, 250)
    segments.append(generate_normal_traffic(n))

# Add attack bursts — each burst is 30-60 consecutive attack packets
for _ in range(30):
    attack_type = np.random.choice(['ddos', 'portscan', 'bruteforce'])
    burst_size = np.random.randint(30, 60)
    if attack_type == 'ddos':
        segments.append(generate_ddos_burst(burst_size))
    elif attack_type == 'portscan':
        segments.append(generate_port_scan(burst_size))
    else:
        segments.append(generate_brute_force(burst_size))

# Interleave: normal, attack, normal, attack...
# This gives the LSTM realistic transitions to learn from
import random
random.shuffle(segments)
df = pd.concat(segments).reset_index(drop=True)

normal_count = (df['label'] == 0).sum()
attack_count = (df['label'] == 1).sum()

df.to_csv('data/friday.csv', index=False)
print(f"Generated {len(df)} samples ({normal_count} normal, {attack_count} attack)")
print(f"Attack ratio: {attack_count/len(df):.1%}")
print(df['label'].value_counts())