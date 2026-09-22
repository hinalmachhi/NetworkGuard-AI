import sqlite3
import os
import random
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'networkguard.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Network traffic table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            destination_port INTEGER NOT NULL,
            packet_count INTEGER NOT NULL,
            packet_size REAL NOT NULL,
            duration REAL NOT NULL,
            packets_per_sec REAL NOT NULL,
            bytes_per_sec REAL NOT NULL,
            flow_bytes REAL NOT NULL,
            num_conn INTEGER NOT NULL,
            conn_duration REAL NOT NULL,
            failed_conn INTEGER NOT NULL,
            status TEXT NOT NULL, -- 'Normal', 'Suspicious', 'Anomalous'
            risk_score INTEGER NOT NULL, -- 0 to 100
            anomaly_type TEXT DEFAULT 'Normal', -- 'Normal', 'DoS', 'DDoS', 'Port Scan', 'Brute Force', 'Botnet', 'Web Attack'
            possible_reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            traffic_id INTEGER,
            source_ip TEXT,
            destination_ip TEXT,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
            risk_score INTEGER NOT NULL,
            status TEXT DEFAULT 'New', -- 'New', 'Reviewed', 'Resolved'
            description TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (traffic_id) REFERENCES network_traffic(id)
        )
    ''')

    # System settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # Default settings
    default_settings = [
        ('anomaly_threshold', '70'),
        ('active_model', 'random_forest'),
        ('simulation_speed', 'normal'),
        ('simulation_active', 'false')
    ]
    for key, val in default_settings:
        cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', (key, val))

    # Seed Admin User if not exists
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        pwd_hash = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                       ('admin', pwd_hash, 'Administrator'))

    # Check if network_traffic is empty; if so, seed sample baseline data
    cursor.execute('SELECT COUNT(*) as count FROM network_traffic')
    count = cursor.fetchone()['count']
    if count == 0:
        seed_sample_traffic_and_alerts(cursor)

    conn.commit()
    conn.close()
    print("Database initialized successfully at:", DB_PATH)

def seed_sample_traffic_and_alerts(cursor):
    """Seed 150 realistic network traffic records and associated alerts"""
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']
    internal_ips = [f"192.168.1.{i}" for i in range(10, 85)] + [f"10.0.0.{i}" for i in range(5, 45)]
    external_ips = [
        "104.244.42.1", "172.217.16.206", "151.101.65.140", "185.199.108.153",
        "45.33.32.156", "198.51.100.42", "203.0.113.19", "93.184.216.34",
        "8.8.8.8", "1.1.1.1", "142.250.190.46", "52.84.125.33"
    ]
    attack_external_ips = [
        "45.143.221.12", "194.26.29.114", "185.220.101.5", "103.152.220.19",
        "77.247.110.88", "193.106.191.22", "109.237.103.4"
    ]

    base_time = datetime.datetime.now() - datetime.timedelta(hours=6)

    records = []
    alerts = []

    # 150 records: ~70% Normal, ~15% Suspicious, ~15% Anomalous
    for i in range(150):
        t = base_time + datetime.timedelta(seconds=i * random.randint(120, 150))
        ts_str = t.strftime('%Y-%m-%d %H:%M:%S')

        # Determine packet class
        roll = random.random()
        if roll < 0.70:
            # Normal
            status = 'Normal'
            risk_score = random.randint(5, 30)
            anomaly_type = 'Normal'
            possible_reason = 'Standard verified protocol traffic'
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            proto = random.choice(['TCP', 'UDP', 'HTTP', 'DNS'])
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([80, 443, 53, 22, 8080])
            packet_count = random.randint(5, 120)
            packet_size = round(random.uniform(200, 1500), 2)
            duration = round(random.uniform(0.05, 4.5), 3)
            packets_per_sec = round(packet_count / max(duration, 0.1), 2)
            flow_bytes = round(packet_count * packet_size, 2)
            bytes_per_sec = round(flow_bytes / max(duration, 0.1), 2)
            num_conn = random.randint(1, 15)
            conn_duration = round(random.uniform(0.1, 10.0), 2)
            failed_conn = random.randint(0, 1)

        elif roll < 0.85:
            # Suspicious
            status = 'Suspicious'
            risk_score = random.randint(45, 68)
            anomaly_type = random.choice(['Port Scan', 'Brute Force', 'Suspicious Burst'])
            possible_reason = random.choice([
                'Unusually high packet rate across short intervals',
                'Multiple rapid SYN handshakes to closed ports',
                'Consecutive failed authentication handshakes',
                'Elevated bytes per second to foreign IP'
            ])
            src_ip = random.choice(attack_external_ips + internal_ips[:5])
            dst_ip = random.choice(internal_ips)
            proto = random.choice(['TCP', 'UDP'])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([21, 22, 23, 3389, 445, 8080, 5000])
            packet_count = random.randint(250, 1500)
            packet_size = round(random.uniform(64, 800), 2)
            duration = round(random.uniform(0.2, 2.0), 3)
            packets_per_sec = round(packet_count / max(duration, 0.1), 2)
            flow_bytes = round(packet_count * packet_size, 2)
            bytes_per_sec = round(flow_bytes / max(duration, 0.1), 2)
            num_conn = random.randint(25, 80)
            conn_duration = round(random.uniform(0.05, 2.0), 2)
            failed_conn = random.randint(4, 18)

        else:
            # Anomalous / Malicious
            status = 'Anomalous'
            risk_score = random.randint(75, 98)
            anomaly_type = random.choice(['DoS', 'DDoS', 'Port Scan', 'Brute Force', 'Botnet', 'Web Attack'])
            if anomaly_type in ['DoS', 'DDoS']:
                possible_reason = 'Extreme packet flooding detected exceeding baseline bandwidth (>10,000 pps)'
                proto = 'TCP'
                dst_port = 80
                packet_count = random.randint(8000, 45000)
                duration = round(random.uniform(0.1, 1.5), 3)
                packet_size = 64.0
                failed_conn = random.randint(50, 300)
            elif anomaly_type == 'Port Scan':
                possible_reason = 'Systematic sequential port scanning sweep across critical server interfaces'
                proto = 'TCP'
                dst_port = random.choice([22, 80, 443, 1433, 3306, 3389])
                packet_count = random.randint(1200, 5000)
                duration = round(random.uniform(0.1, 0.8), 3)
                packet_size = 48.0
                failed_conn = random.randint(100, 500)
            elif anomaly_type == 'Brute Force':
                possible_reason = 'Repeated high-frequency failed password credential stuffing on administrative port'
                proto = 'TCP'
                dst_port = random.choice([22, 3389, 21])
                packet_count = random.randint(900, 3500)
                duration = round(random.uniform(1.0, 5.0), 3)
                packet_size = round(random.uniform(120, 450), 2)
                failed_conn = random.randint(40, 120)
            else:
                possible_reason = 'Abnormal payload structure and persistent C2 beaconing signatures detected'
                proto = random.choice(['TCP', 'UDP', 'HTTP'])
                dst_port = random.choice([443, 8088, 9001])
                packet_count = random.randint(1500, 6000)
                duration = round(random.uniform(0.5, 3.0), 3)
                packet_size = round(random.uniform(1200, 2500), 2)
                failed_conn = random.randint(10, 50)

            src_ip = random.choice(attack_external_ips)
            dst_ip = random.choice(internal_ips[:10])
            src_port = random.randint(1024, 65535)
            packets_per_sec = round(packet_count / max(duration, 0.1), 2)
            flow_bytes = round(packet_count * packet_size, 2)
            bytes_per_sec = round(flow_bytes / max(duration, 0.1), 2)
            num_conn = random.randint(100, 500)
            conn_duration = round(random.uniform(0.01, 1.0), 2)

        cursor.execute('''
            INSERT INTO network_traffic (
                source_ip, destination_ip, protocol, source_port, destination_port,
                packet_count, packet_size, duration, packets_per_sec, bytes_per_sec,
                flow_bytes, num_conn, conn_duration, failed_conn, status,
                risk_score, anomaly_type, possible_reason, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            src_ip, dst_ip, proto, src_port, dst_port,
            packet_count, packet_size, duration, packets_per_sec, bytes_per_sec,
            flow_bytes, num_conn, conn_duration, failed_conn, status,
            risk_score, anomaly_type, possible_reason, ts_str
        ))
        traffic_id = cursor.lastrowid

        # If suspicious or anomalous, create alert
        if status in ['Suspicious', 'Anomalous']:
            if risk_score >= 85:
                severity = 'Critical'
            elif risk_score >= 70:
                severity = 'High'
            elif risk_score >= 50:
                severity = 'Medium'
            else:
                severity = 'Low'

            alert_status = random.choice(['New', 'New', 'Reviewed', 'Resolved'])
            desc = f"Detected {anomaly_type} event from {src_ip} targeting {dst_ip}:{dst_port}. {possible_reason}"

            cursor.execute('''
                INSERT INTO alerts (
                    traffic_id, source_ip, destination_ip, anomaly_type,
                    severity, risk_score, status, description, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                traffic_id, src_ip, dst_ip, anomaly_type,
                severity, risk_score, alert_status, desc, ts_str
            ))

if __name__ == '__main__':
    init_db()
