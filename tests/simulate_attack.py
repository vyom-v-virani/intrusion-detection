from kafka import KafkaProducer
import json
import time

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def send_ddos_burst(n=50):
    """Simulate a DDoS attack — tiny UDP packets hammering port 80."""
    print(f"Sending DDoS burst ({n} packets)...")
    for i in range(n):
        packet = {
            "timestamp": time.time(),
            "src_ip": f"192.168.1.{i % 5}",  # 5 attacking IPs
            "dst_ip": "10.239.76.53",
            "protocol": 17,           # UDP
            "packet_size": 62,        # tiny
            "ttl": 24,                # low TTL
            "src_port": 40000 + i,
            "dst_port": 80,           # all hitting port 80
            "tcp_flags": 0
        }
        producer.send('network-packets', value=packet)
    producer.flush()
    print("DDoS burst sent.")

def send_port_scan(n=50):
    """Simulate a port scan — sequential ports, SYN packets."""
    print(f"Sending port scan ({n} packets)...")
    for i in range(n):
        packet = {
            "timestamp": time.time(),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.239.76.53",
            "protocol": 6,            # TCP
            "packet_size": 54,        # tiny SYN
            "ttl": 45,
            "src_port": 44000,
            "dst_port": i * 100,      # sequential ports
            "tcp_flags": 2            # SYN
        }
        producer.send('network-packets', value=packet)
    producer.flush()
    print("Port scan sent.")

def send_normal(n=30):
    """Send normal traffic to reset the window."""
    print(f"Sending normal traffic ({n} packets)...")
    for i in range(n):
        packet = {
            "timestamp": time.time(),
            "src_ip": "10.239.76.53",
            "dst_ip": "142.250.80.46",
            "protocol": 6,
            "packet_size": 500,
            "ttl": 64,
            "src_port": 50000 + i,
            "dst_port": 443,
            "tcp_flags": 18
        }
        producer.send('network-packets', value=packet)
    producer.flush()
    print("Normal traffic sent.")

# Run the simulation
send_normal(30)       # establish normal baseline
time.sleep(1)
send_ddos_burst(50)   # trigger attack detection
time.sleep(1)
send_normal(10)       # back to normal
time.sleep(1)
send_port_scan(50)    # trigger second attack