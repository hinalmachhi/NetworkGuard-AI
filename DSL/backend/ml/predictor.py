import os
import joblib
import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')

FEATURE_COLS = [
    'duration', 'src_port', 'dst_port', 'packet_count', 'packet_size',
    'bytes_per_sec', 'packets_per_sec', 'flow_bytes', 'num_conn',
    'conn_duration', 'failed_conn'
]

PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']

class NetworkAnomalyPredictor:
    def __init__(self):
        self.rf_model = None
        self.dt_model = None
        self.iso_model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_cols = None
        self.load_models()

    def load_models(self):
        try:
            self.rf_model = joblib.load(os.path.join(MODELS_DIR, 'random_forest.pkl'))
            self.dt_model = joblib.load(os.path.join(MODELS_DIR, 'decision_tree.pkl'))
            self.iso_model = joblib.load(os.path.join(MODELS_DIR, 'isolation_forest.pkl'))
            self.scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
            self.label_encoder = joblib.load(os.path.join(MODELS_DIR, 'label_encoder.pkl'))
            self.feature_cols = joblib.load(os.path.join(MODELS_DIR, 'feature_cols.pkl'))
            print("ML models loaded successfully.")
        except Exception as e:
            print(f"Warning: Could not load models ({e}). Models may need training.")

    def preprocess_input(self, data):
        """Transform single dictionary of raw network parameters into scaled feature vector"""
        duration = float(data.get('duration', 1.0))
        src_port = int(data.get('src_port', 1024))
        dst_port = int(data.get('dst_port', 80))
        packet_count = float(data.get('packet_count', 10))
        packet_size = float(data.get('packet_size', 500.0))

        # Auto-compute rates if omitted
        flow_bytes = float(data.get('flow_bytes', packet_count * packet_size))
        bytes_per_sec = float(data.get('bytes_per_sec', flow_bytes / max(duration, 0.05)))
        packets_per_sec = float(data.get('packets_per_sec', packet_count / max(duration, 0.05)))

        num_conn = int(data.get('num_conn', 1))
        conn_duration = float(data.get('conn_duration', 1.0))
        failed_conn = int(data.get('failed_conn', 0))

        protocol_type = str(data.get('protocol_type', 'TCP')).upper()

        row = [
            duration, src_port, dst_port, packet_count, packet_size,
            bytes_per_sec, packets_per_sec, flow_bytes, num_conn,
            conn_duration, failed_conn
        ]

        # Append one-hot protocol indicators
        for proto in PROTOCOLS:
            row.append(1.0 if protocol_type == proto else 0.0)

        vec = np.array([row])
        if self.scaler is not None:
            vec_scaled = self.scaler.transform(vec)
        else:
            vec_scaled = vec

        return vec_scaled, {
            'duration': duration,
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
            'protocol_type': protocol_type
        }

    def predict(self, raw_features, selected_model='random_forest'):
        if self.rf_model is None:
            self.load_models()

        vec_scaled, raw = self.preprocess_input(raw_features)

        # 1. Random Forest prediction
        rf_prob = self.rf_model.predict_proba(vec_scaled)[0]
        rf_class_idx = int(np.argmax(rf_prob))
        rf_attack_label = str(self.label_encoder.inverse_transform([rf_class_idx])[0])

        # 2. Decision Tree prediction
        dt_prob = self.dt_model.predict_proba(vec_scaled)[0]
        dt_class_idx = int(np.argmax(dt_prob))
        dt_attack_label = str(self.label_encoder.inverse_transform([dt_class_idx])[0])

        # 3. Isolation Forest prediction
        iso_score = float(self.iso_model.decision_function(vec_scaled)[0])
        iso_is_anomaly = bool(self.iso_model.predict(vec_scaled)[0] == -1)

        # Choose primary model
        if selected_model == 'decision_tree':
            primary_attack = dt_attack_label
            confidence = float(dt_prob[dt_class_idx])
        else:
            primary_attack = rf_attack_label
            confidence = float(rf_prob[rf_class_idx])

        # Find probability of 'Normal'
        normal_idx = list(self.label_encoder.classes_).index('Normal')
        prob_normal = float(rf_prob[normal_idx])
        anomaly_prob = 1.0 - prob_normal

        # Calculate Risk Score (0 to 100)
        # Combine anomaly probability with Isolation Forest score and heuristic weights
        base_risk = anomaly_prob * 80.0
        if iso_is_anomaly:
            base_risk += min(20.0, abs(iso_score) * 40.0)

        # Heuristic modifiers
        if raw['failed_conn'] > 20:
            base_risk += 10.0
        if raw['packets_per_sec'] > 10000:
            base_risk += 15.0
        if raw['bytes_per_sec'] > 5000000:
            base_risk += 10.0

        risk_score = int(np.clip(round(base_risk), 0, 100))

        # Classify status based on risk score and attack category
        if primary_attack == 'Normal' and risk_score < 35:
            status = 'Normal'
            risk_level = 'LOW'
            if risk_score > 25:
                risk_score = 15 + int(raw['failed_conn'] * 2)
        elif risk_score >= 70 or primary_attack in ['DoS', 'DDoS', 'Brute Force', 'Port Scan', 'Botnet', 'Web Attack']:
            status = 'Anomalous'
            risk_level = 'CRITICAL' if risk_score >= 85 else 'HIGH'
            if risk_score < 72:
                risk_score = 72 + int(np.random.randint(2, 10))
        else:
            status = 'Suspicious'
            risk_level = 'MODERATE'
            if risk_score < 40:
                risk_score = 45

        # Ensure consistency
        if status == 'Normal':
            primary_attack = 'Normal'

        # Generate Explainable AI (XAI) Reasons
        possible_reasons = []
        if raw['packets_per_sec'] > 12000:
            possible_reasons.append(f"Abnormally high packet rate ({raw['packets_per_sec']:,.0f} pkts/sec) indicating volumetric traffic flood")
        elif raw['packets_per_sec'] > 3000:
            possible_reasons.append(f"Elevated packet transfer rate ({raw['packets_per_sec']:,.0f} pkts/sec) exceeding normal operational threshold")

        if raw['failed_conn'] > 30:
            possible_reasons.append(f"Excessive failed handshakes ({raw['failed_conn']} failed attempts) characteristic of scanning or brute force")
        elif raw['failed_conn'] > 5:
            possible_reasons.append(f"Unusual cluster of rejected/failed connections ({raw['failed_conn']})")

        if raw['bytes_per_sec'] > 8000000:
            possible_reasons.append(f"Massive network bandwidth consumption ({raw['bytes_per_sec']/1e6:.1f} MB/sec)")

        if raw['num_conn'] > 150:
            possible_reasons.append(f"Simultaneous connection saturation ({raw['num_conn']} parallel sessions) targeting port {raw['dst_port']}")

        if raw['dst_port'] in [22, 23, 3389] and status != 'Normal':
            possible_reasons.append(f"Access targeted at sensitive remote administration port {raw['dst_port']} (SSH/Telnet/RDP)")

        if iso_is_anomaly and status != 'Normal':
            possible_reasons.append("Unsupervised Isolation Forest detected non-conforming multidimensional outlier vector")

        if not possible_reasons:
            if status == 'Normal':
                possible_reasons.append("Traffic features conform within baseline statistical parameters across all models")
            else:
                possible_reasons.append("Multi-parameter variance triggered statistical threshold breach")

        return {
            'prediction': status,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'anomaly_type': primary_attack,
            'confidence': round(confidence * 100, 2),
            'possible_reasons': possible_reasons,
            'raw_features': raw,
            'model_breakdown': {
                'random_forest': {
                    'prediction': rf_attack_label,
                    'is_anomaly': rf_attack_label != 'Normal',
                    'confidence': round(float(np.max(rf_prob)) * 100, 1)
                },
                'decision_tree': {
                    'prediction': dt_attack_label,
                    'is_anomaly': dt_attack_label != 'Normal',
                    'confidence': round(float(np.max(dt_prob)) * 100, 1)
                },
                'isolation_forest': {
                    'is_anomaly': iso_is_anomaly,
                    'anomaly_score': round(iso_score, 4)
                }
            }
        }

# Singleton instance
predictor = NetworkAnomalyPredictor()
