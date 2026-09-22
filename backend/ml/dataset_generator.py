import os
import pandas as pd
import numpy as np
import random

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'network_dataset.csv')

def generate_network_dataset(num_samples=5000, output_path=DATASET_PATH):
    """
    Generate a statistically representative, realistic network intrusion dataset
    based on NSL-KDD and CIC-IDS2017 features.
    """
    np.random.seed(42)
    random.seed(42)

    data = []

    # Distribution of traffic categories:
    # 65% Normal, 10% DoS, 8% DDoS, 7% Port Scan, 5% Brute Force, 3% Botnet, 2% Web Attack
    categories = [
        ('Normal', 0.65),
        ('DoS', 0.10),
        ('DDoS', 0.08),
        ('Port Scan', 0.07),
        ('Brute Force', 0.05),
        ('Botnet', 0.03),
        ('Web Attack', 0.02)
    ]

    for label, prob in categories:
        count = int(num_samples * prob)
        for _ in range(count):
            if label == 'Normal':
                proto = random.choices(['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'], weights=[0.45, 0.25, 0.05, 0.20, 0.05])[0]
                duration = max(0.01, round(np.random.exponential(scale=1.2), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 53, 22, 25, 8080, 8443, 3000])
                packet_count = int(np.random.gamma(shape=3.0, scale=12.0)) + 2
                packet_size = max(40.0, round(np.random.normal(loc=550.0, scale=250.0), 2))
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.05), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.05), 2)
                num_conn = random.randint(1, 15)
                conn_duration = max(0.05, round(np.random.exponential(scale=2.5), 2))
                failed_conn = random.choices([0, 1, 2], weights=[0.92, 0.06, 0.02])[0]
                is_anomaly = 0

            elif label == 'DoS':
                proto = random.choices(['TCP', 'UDP', 'ICMP'], weights=[0.7, 0.2, 0.1])[0]
                duration = max(0.05, round(np.random.uniform(0.1, 2.0), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 8080])
                packet_count = int(np.random.uniform(5000, 35000))
                packet_size = round(np.random.normal(loc=64.0, scale=10.0), 2)
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.05), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.05), 2)
                num_conn = random.randint(80, 400)
                conn_duration = max(0.01, round(np.random.uniform(0.01, 0.5), 2))
                failed_conn = random.randint(30, 250)
                is_anomaly = 1

            elif label == 'DDoS':
                proto = random.choices(['TCP', 'UDP'], weights=[0.6, 0.4])[0]
                duration = max(0.1, round(np.random.uniform(0.2, 3.5), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 53, 123])
                packet_count = int(np.random.uniform(15000, 60000))
                packet_size = round(np.random.normal(loc=120.0, scale=40.0), 2)
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.05), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.05), 2)
                num_conn = random.randint(200, 900)
                conn_duration = max(0.01, round(np.random.uniform(0.01, 0.8), 2))
                failed_conn = random.randint(80, 450)
                is_anomaly = 1

            elif label == 'Port Scan':
                proto = 'TCP'
                duration = max(0.02, round(np.random.uniform(0.05, 0.9), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080])
                packet_count = int(np.random.uniform(500, 4000))
                packet_size = round(np.random.normal(loc=48.0, scale=8.0), 2)
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.05), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.05), 2)
                num_conn = random.randint(150, 600)
                conn_duration = max(0.01, round(np.random.uniform(0.01, 0.15), 2))
                failed_conn = random.randint(100, 500)
                is_anomaly = 1

            elif label == 'Brute Force':
                proto = 'TCP'
                duration = max(0.5, round(np.random.uniform(1.0, 8.0), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([22, 3389, 21, 23, 3306])
                packet_count = int(np.random.uniform(800, 5000))
                packet_size = round(np.random.normal(loc=180.0, scale=50.0), 2)
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.1), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.1), 2)
                num_conn = random.randint(30, 150)
                conn_duration = max(0.2, round(np.random.uniform(0.5, 4.0), 2))
                failed_conn = random.randint(25, 120)
                is_anomaly = 1

            elif label == 'Botnet':
                proto = random.choices(['TCP', 'UDP', 'HTTP', 'DNS'], weights=[0.4, 0.2, 0.3, 0.1])[0]
                duration = max(0.2, round(np.random.uniform(0.5, 5.0), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([443, 6667, 8088, 9001, 80])
                packet_count = int(np.random.uniform(1000, 8000))
                packet_size = round(np.random.normal(loc=900.0, scale=300.0), 2)
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.1), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.1), 2)
                num_conn = random.randint(40, 200)
                conn_duration = max(0.1, round(np.random.uniform(0.2, 2.5), 2))
                failed_conn = random.randint(5, 40)
                is_anomaly = 1

            else: # Web Attack
                proto = random.choices(['HTTP', 'TCP'], weights=[0.8, 0.2])[0]
                duration = max(0.1, round(np.random.uniform(0.2, 3.0), 3))
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 8080])
                packet_count = int(np.random.uniform(200, 2500))
                packet_size = round(np.random.normal(loc=1800.0, scale=600.0), 2)
                flow_bytes = round(packet_count * packet_size, 2)
                packets_per_sec = round(packet_count / max(duration, 0.1), 2)
                bytes_per_sec = round(flow_bytes / max(duration, 0.1), 2)
                num_conn = random.randint(10, 80)
                conn_duration = max(0.1, round(np.random.uniform(0.3, 2.0), 2))
                failed_conn = random.randint(2, 25)
                is_anomaly = 1

            data.append({
                'duration': duration,
                'protocol_type': proto,
                'src_port': src_port,
                'dst_port': dst_port,
                'packet_count': packet_count,
                'packet_size': packet_size,
                'bytes_per_sec': bytes_per_sec,
                'packets_per_sec': packets_per_sec,
                'flow_bytes': flow_bytes,
                'num_conn': num_conn,
                'conn_duration': conn_duration,
                'failed_conn': failed_conn,
                'is_anomaly': is_anomaly,
                'attack_type': label
            })

    df = pd.DataFrame(data)
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated network traffic dataset with {len(df)} samples saved to {output_path}")
    return df

if __name__ == '__main__':
    generate_network_dataset()
