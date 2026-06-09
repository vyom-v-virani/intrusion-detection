from scapy.all import sniff, IP, TCP, UDP
from kafka import KafkaProducer
import json
import time

class TokenBucket:
    def __init__(self, rate, capacity):
        """
        rate     — how many tokens get added per second (e.g. 500)
        capacity — max tokens the bucket can hold (e.g. 1000)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity          # start full
        self.last_refill = time.time()  # track when we last added tokens

    def add_tokens(self):
        """Refill the bucket based on how much time has passed."""
        now = time.time()
        elapsed = now - self.last_refill        # seconds since last refill
        new_tokens = elapsed * self.rate        # how many tokens to add
        self.tokens = min(self.capacity, self.tokens + new_tokens)  # cap at max
        self.last_refill = now

    def consume(self):
        """Try to take 1 token. Returns True if successful, False if empty."""
        self.add_tokens()           # refill first based on elapsed time
        if self.tokens >= 1:
            self.tokens -= 1
            return True             # token available, proceed
        return False                # bucket empty, drop the packet

# Connect to Kafka
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def extract_features(packet):
    """Pull the relevant fields out of each packet."""
    if not packet.haslayer(IP):
        return None  # ignore non-IP packets (ARP, etc.)

    features = {
        "timestamp": time.time(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,  # 6=TCP, 17=UDP
        "packet_size": len(packet),
        "ttl": packet[IP].ttl,
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0
    }

    if packet.haslayer(TCP):
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
        features["tcp_flags"] = int(packet[TCP].flags)

    elif packet.haslayer(UDP):
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport

    return features

# Create the rate limiter — 500 packets/sec max, burst up to 1000
rate_limiter = TokenBucket(rate=10, capacity=20)

def process_packet(packet):
    """Called for every packet Scapy captures."""
    if not rate_limiter.consume():
        print("Rate limit hit — dropping packet")
        return  # drop the packet, don't send to Kafka

    features = extract_features(packet)
    if features:
        producer.send('network-packets', value=features)
        print(f"Sent: {features['src_ip']} → {features['dst_ip']} | size={features['packet_size']}")

print("Starting packet capture... (Ctrl+C to stop)")
sniff(prn=process_packet, store=False)
