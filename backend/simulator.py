import time
import threading
import random
import datetime
from collections import deque
from database import get_db_connection
from ml.predictor import predictor

class NetworkTrafficSimulator:
    def __init__(self):
        self.is_running = False
        self.thread = None
        self.lock = threading.Lock()
        self.speed = 1.5 # seconds per packet
        self.live_buffer = deque(maxlen=40)
        self.recent_alerts = deque(maxlen=10)
        self.pending_injections = deque()
        self.total_packets_simulated = 0
        self.anomalies_simulated = 0
        self.init_live_buffer()

    def init_live_buffer(self):
        """Pre-populate buffer with 20 baseline points so graphs are never empty on first load"""
        now = datetime.datetime.now()
        for i in range(20, 0, -1):
            t = (now - datetime.timedelta(seconds=i * 2)).strftime('%H:%M:%S')
            normal_pkts = random.randint(15, 60)
            self.live_buffer.append({
                'time': t,
                'total_packets': normal_pkts,
                'normal_packets': normal_pkts,
                'anomalous_packets': 0,
                'bytes_transferred': round(normal_pkts * random.uniform(300, 700) / 1024, 2), # KB
                'active_connections': random.randint(12, 35),
                'risk_score': random.randint(10, 25),
                'status': 'Normal'
            })

    def start(self):
        with self.lock:
            if not self.is_running:
                self.is_running = True
                self.thread = threading.Thread(target=self._run_loop, daemon=True)
                self.thread.start()
                self._update_db_setting('simulation_active', 'true')
                print("Network simulator background thread started.")
        return {'status': 'running', 'speed': self.speed}

    def stop(self):
        with self.lock:
            self.is_running = False
            self._update_db_setting('simulation_active', 'false')
            print("Network simulator background thread stopped.")
        return {'status': 'stopped'}

    def inject_attack(self, attack_type):
        """Queue a specific attack burst to be dispatched immediately"""
        valid_attacks = ['DoS', 'DDoS', 'Port Scan', 'Brute Force', 'Botnet', 'Web Attack']
        if attack_type not in valid_attacks:
            attack_type = 'DoS'
        with self.lock:
            self.pending_injections.append(attack_type)
        return {'status': 'queued', 'attack_type': attack_type}

    def _update_db_setting(self, key, value):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error updating setting {key}: {e}")

    def _generate_synthetic_packet(self, forced_attack=None):
        internal_ips = [f"192.168.1.{i}" for i in range(10, 60)] + [f"10.0.0.{i}" for i in range(5, 30)]
        legit_external = [
            "172.217.16.206", "104.244.42.1", "151.101.65.140", "185.199.108.153",
            "8.8.8.8", "1.1.1.1", "142.250.190.46", "52.84.125.33"
        ]
        threat_ips = [
            "45.143.221.12", "194.26.29.114", "185.220.101.5", "103.152.220.19",
            "77.247.110.88", "193.106.191.22", "109.237.103.4"
        ]

        if forced_attack:
            attack_type = forced_attack
        else:
            # 80% normal background, 20% sporadic suspicious or attack events
            roll = random.random()
            if roll < 0.78:
                attack_type = 'Normal'
            elif roll < 0.90:
                attack_type = random.choice(['Port Scan', 'Brute Force'])
            else:
                attack_type = random.choice(['DoS', 'DDoS', 'Botnet', 'Web Attack'])

        if attack_type == 'Normal':
            proto = random.choice(['TCP', 'UDP', 'HTTP', 'DNS'])
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(legit_external)
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([80, 443, 53, 22, 8080])
            packet_count = random.randint(4, 90)
            packet_size = round(random.uniform(250, 1400), 2)
            duration = round(random.uniform(0.05, 3.5), 3)
            num_conn = random.randint(1, 12)
            conn_duration = round(random.uniform(0.2, 5.0), 2)
            failed_conn = random.choices([0, 1], weights=[0.95, 0.05])[0]

        elif attack_type in ['DoS', 'DDoS']:
            proto = 'TCP' if attack_type == 'DoS' else random.choice(['TCP', 'UDP'])
            src_ip = random.choice(threat_ips)
            dst_ip = random.choice(internal_ips[:5])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 8080])
            packet_count = random.randint(8000, 35000)
            packet_size = round(random.uniform(60, 120), 2)
            duration = round(random.uniform(0.1, 1.2), 3)
            num_conn = random.randint(120, 500)
            conn_duration = round(random.uniform(0.01, 0.4), 2)
            failed_conn = random.randint(40, 250)

        elif attack_type == 'Port Scan':
            proto = 'TCP'
            src_ip = random.choice(threat_ips)
            dst_ip = random.choice(internal_ips[:10])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080])
            packet_count = random.randint(600, 3500)
            packet_size = 48.0
            duration = round(random.uniform(0.05, 0.7), 3)
            num_conn = random.randint(80, 350)
            conn_duration = round(random.uniform(0.01, 0.1), 2)
            failed_conn = random.randint(50, 200)

        elif attack_type == 'Brute Force':
            proto = 'TCP'
            src_ip = random.choice(threat_ips)
            dst_ip = random.choice(internal_ips[:5])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([22, 3389, 21])
            packet_count = random.randint(900, 4000)
            packet_size = round(random.uniform(150, 350), 2)
            duration = round(random.uniform(1.0, 4.0), 3)
            num_conn = random.randint(30, 120)
            conn_duration = round(random.uniform(0.5, 3.0), 2)
            failed_conn = random.randint(30, 95)

        else: # Botnet or Web Attack
            proto = random.choice(['HTTP', 'TCP', 'UDP'])
            src_ip = random.choice(threat_ips)
            dst_ip = random.choice(internal_ips[:8])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 8088])
            packet_count = random.randint(800, 3000)
            packet_size = round(random.uniform(900, 2200), 2)
            duration = round(random.uniform(0.3, 2.5), 3)
            num_conn = random.randint(20, 90)
            conn_duration = round(random.uniform(0.2, 2.0), 2)
            failed_conn = random.randint(5, 30)

        flow_bytes = round(packet_count * packet_size, 2)
        bytes_per_sec = round(flow_bytes / max(duration, 0.05), 2)
        packets_per_sec = round(packet_count / max(duration, 0.05), 2)

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'proto': proto,
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_count': packet_count,
            'packet_size': packet_size,
            'duration': duration,
            'flow_bytes': flow_bytes,
            'bytes_per_sec': bytes_per_sec,
            'packets_per_sec': packets_per_sec,
            'num_conn': num_conn,
            'conn_duration': conn_duration,
            'failed_conn': failed_conn,
            'protocol_type': proto
        }

    def _run_loop(self):
        while self.is_running:
            try:
                forced_attack = None
                with self.lock:
                    if self.pending_injections:
                        forced_attack = self.pending_injections.popleft()

                raw = self._generate_synthetic_packet(forced_attack=forced_attack)

                # Pass to ML Predictor
                res = predictor.predict({
                    'duration': raw['duration'],
                    'src_port': raw['src_port'],
                    'dst_port': raw['dst_port'],
                    'packet_count': raw['packet_count'],
                    'packet_size': raw['packet_size'],
                    'bytes_per_sec': raw['bytes_per_sec'],
                    'packets_per_sec': raw['packets_per_sec'],
                    'flow_bytes': raw['flow_bytes'],
                    'num_conn': raw['num_conn'],
                    'conn_duration': raw['conn_duration'],
                    'failed_conn': raw['failed_conn'],
                    'protocol_type': raw['proto']
                })

                now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                time_only = datetime.datetime.now().strftime('%H:%M:%S')
                reason_str = "; ".join(res['possible_reasons'])

                # Save to Database
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO network_traffic (
                        source_ip, destination_ip, protocol, source_port, destination_port,
                        packet_count, packet_size, duration, packets_per_sec, bytes_per_sec,
                        flow_bytes, num_conn, conn_duration, failed_conn, status,
                        risk_score, anomaly_type, possible_reason, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    raw['src_ip'], raw['dst_ip'], raw['proto'], raw['src_port'], raw['dst_port'],
                    raw['packet_count'], raw['packet_size'], raw['duration'],
                    raw['packets_per_sec'], raw['bytes_per_sec'], raw['flow_bytes'],
                    raw['num_conn'], raw['conn_duration'], raw['failed_conn'],
                    res['prediction'], res['risk_score'], res['anomaly_type'],
                    reason_str, now_str
                ))
                traffic_id = cursor.lastrowid

                # If Suspicious or Anomalous, create Alert
                new_alert = None
                if res['prediction'] in ['Suspicious', 'Anomalous']:
                    if res['risk_score'] >= 85:
                        severity = 'Critical'
                    elif res['risk_score'] >= 70:
                        severity = 'High'
                    elif res['risk_score'] >= 50:
                        severity = 'Medium'
                    else:
                        severity = 'Low'

                    desc = f"Simulated {res['anomaly_type']} activity intercepted from {raw['src_ip']} to {raw['dst_ip']}:{raw['dst_port']}. {reason_str}"
                    cursor.execute('''
                        INSERT INTO alerts (
                            traffic_id, source_ip, destination_ip, anomaly_type,
                            severity, risk_score, status, description, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, 'New', ?, ?)
                    ''', (
                        traffic_id, raw['src_ip'], raw['dst_ip'], res['anomaly_type'],
                        severity, res['risk_score'], desc, now_str
                    ))
                    alert_id = cursor.lastrowid
                    new_alert = {
                        'id': alert_id,
                        'source_ip': raw['src_ip'],
                        'destination_ip': raw['dst_ip'],
                        'anomaly_type': res['anomaly_type'],
                        'severity': severity,
                        'risk_score': res['risk_score'],
                        'status': 'New',
                        'timestamp': now_str,
                        'description': desc
                    }
                    self.recent_alerts.appendleft(new_alert)
                    self.anomalies_simulated += 1

                conn.commit()
                conn.close()

                self.total_packets_simulated += 1

                # Update live circular buffer
                is_anom = res['prediction'] in ['Suspicious', 'Anomalous']
                self.live_buffer.append({
                    'time': time_only,
                    'total_packets': raw['packet_count'],
                    'normal_packets': raw['packet_count'] if not is_anom else int(raw['packet_count'] * 0.1),
                    'anomalous_packets': raw['packet_count'] if is_anom else 0,
                    'bytes_transferred': round(raw['flow_bytes'] / 1024, 2), # KB
                    'active_connections': raw['num_conn'],
                    'risk_score': res['risk_score'],
                    'status': res['prediction'],
                    'anomaly_type': res['anomaly_type']
                })

            except Exception as e:
                print(f"Error in simulator loop: {e}")

            time.sleep(self.speed)

    def get_live_metrics(self):
        with self.lock:
            chart_data = list(self.live_buffer)
            alerts = list(self.recent_alerts)
            current_risk = chart_data[-1]['risk_score'] if chart_data else 20
            active_conns = chart_data[-1]['active_connections'] if chart_data else 25
            total_pkts = chart_data[-1]['total_packets'] if chart_data else 45
            data_mb = round(chart_data[-1]['bytes_transferred'] / 1024, 2) if chart_data else 0.5
            is_threat = current_risk >= 70 or any(p['anomalous_packets'] > 0 for p in chart_data[-3:])

            return {
                'is_running': self.is_running,
                'network_status': 'Threat Detected' if is_threat else 'Network Secure',
                'status_indicator': 'threat' if is_threat else 'secure',
                'current_risk_score': current_risk,
                'packets_per_sec': total_pkts,
                'data_transferred_mb': data_mb,
                'active_connections': active_conns,
                'total_simulated': self.total_packets_simulated,
                'anomalies_count': self.anomalies_simulated,
                'chart_data': chart_data,
                'recent_alerts': alerts
            }

# Singleton simulator instance
simulator = NetworkTrafficSimulator()
