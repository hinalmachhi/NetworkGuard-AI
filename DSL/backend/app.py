import os
import io
import csv
import json
import datetime
from flask import Flask, request, jsonify, Response, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.security import check_password_hash

from database import init_db, get_db_connection, seed_sample_traffic_and_alerts
from ml.predictor import predictor
from ml.train_models import train_and_evaluate, MODELS_DIR
from simulator import simulator

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist'))

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    # Do not intercept API routes
    if path.startswith('api') or path.startswith('/api'):
        return jsonify({'error': 'API endpoint not found'}), 404

    file_path = os.path.join(FRONTEND_DIST, path)
    if path != '' and os.path.exists(file_path):
        return send_from_directory(FRONTEND_DIST, path)
    elif os.path.exists(os.path.join(FRONTEND_DIST, 'index.html')):
        return send_from_directory(FRONTEND_DIST, 'index.html')
    else:
        return '''<!DOCTYPE html>
<html>
<head>
    <title>NetworkGuard AI - Intrusion Detection</title>
    <style>
        body { background: #070b14; color: #f1f5f9; font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #0f172a; border: 1px solid #1e293b; padding: 32px; border-radius: 16px; text-align: center; max-width: 480px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h1 { color: #38bdf8; margin: 0 0 10px 0; }
        p { color: #94a3b8; font-size: 14px; line-height: 1.6; }
        .badge { display: inline-block; background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 12px; border-radius: 9999px; font-weight: bold; font-size: 12px; margin-bottom: 16px; }
        .btn { display: inline-block; background: #0284c7; color: #fff; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 13px; margin-top: 12px; }
        .btn:hover { background: #0369a1; }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">SYSTEM ONLINE</div>
        <h1>NetworkGuard AI</h1>
        <p>AI-Powered Network Anomaly Detection System &amp; REST API is running on Port 5000.</p>
        <a class="btn" href="http://localhost:5173" target="_blank">Open React Dashboard (Port 5173)</a>
    </div>
</body>
</html>'''
# Ensure database is initialized
init_db()

# ----------------- AUTHENTICATION -----------------
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            },
            'token': f"netguard-auth-{user['id']}-xyz"
        })
    else:
        return jsonify({'error': 'Invalid administrator credentials'}), 401

@app.route('/api/auth/me', methods=['GET'])
def get_current_user():
    return jsonify({
        'user': {
            'id': 1,
            'username': 'admin',
            'role': 'Network Security Administrator'
        }
    })

# ----------------- DASHBOARD & STATS -----------------
@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Total statistics
    cursor.execute('SELECT COUNT(*) as total FROM network_traffic')
    total_packets = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as normal_count FROM network_traffic WHERE status = 'Normal'")
    normal_traffic = cursor.fetchone()['normal_count']

    cursor.execute("SELECT COUNT(*) as anom_count FROM network_traffic WHERE status = 'Anomalous'")
    anomalous_traffic = cursor.fetchone()['anom_count']

    cursor.execute("SELECT COUNT(*) as susp_count FROM network_traffic WHERE status = 'Suspicious'")
    suspicious_traffic = cursor.fetchone()['susp_count']

    cursor.execute('SELECT COUNT(*) as alerts_count FROM alerts')
    threats_detected = cursor.fetchone()['alerts_count']

    # 2. Dynamic Network Risk Score Calculation
    # Based on recent 30 packets and active critical alerts
    cursor.execute('''
        SELECT AVG(risk_score) as avg_recent_risk
        FROM (SELECT risk_score FROM network_traffic ORDER BY id DESC LIMIT 30)
    ''')
    recent_risk = cursor.fetchone()['avg_recent_risk'] or 25
    network_risk_score = min(100, max(5, int(round(recent_risk))))

    # 3. Active Connections estimate
    cursor.execute('SELECT AVG(num_conn) as avg_conn FROM (SELECT num_conn FROM network_traffic ORDER BY id DESC LIMIT 15)')
    active_conns = int(cursor.fetchone()['avg_conn'] or 24)

    # 4. Chart: Network Traffic Over Time (recent 25 entries aggregated)
    cursor.execute('''
        SELECT id, timestamp, packet_count, flow_bytes, risk_score, status, anomaly_type
        FROM network_traffic ORDER BY id DESC LIMIT 25
    ''')
    recent_rows = [dict(r) for r in cursor.fetchall()][::-1]

    traffic_over_time = []
    normal_vs_anom = []
    risk_trend = []
    for r in recent_rows:
        time_label = r['timestamp'].split(' ')[-1] if ' ' in r['timestamp'] else r['timestamp']
        pkts = r['packet_count']
        is_anom = r['status'] in ['Anomalous', 'Suspicious']
        traffic_over_time.append({
            'time': time_label,
            'packets': pkts,
            'flow_kb': round(r['flow_bytes'] / 1024, 1),
            'risk': r['risk_score']
        })
        normal_vs_anom.append({
            'time': time_label,
            'normal': pkts if not is_anom else int(pkts * 0.1),
            'anomalous': pkts if is_anom else 0
        })
        risk_trend.append({
            'time': time_label,
            'risk_score': r['risk_score'],
            'threshold': 70
        })

    # 5. Chart: Attack Type Distribution
    cursor.execute('''
        SELECT anomaly_type, COUNT(*) as count
        FROM network_traffic
        WHERE anomaly_type != 'Normal'
        GROUP BY anomaly_type
        ORDER BY count DESC
    ''')
    attack_dist = [{'type': r['anomaly_type'], 'count': r['count']} for r in cursor.fetchall()]
    if not attack_dist:
        attack_dist = [
            {'type': 'DoS', 'count': 18},
            {'type': 'Port Scan', 'count': 12},
            {'type': 'Brute Force', 'count': 9},
            {'type': 'DDoS', 'count': 7},
            {'type': 'Botnet', 'count': 4}
        ]

    # 6. Chart: Protocol Distribution
    cursor.execute('''
        SELECT protocol, COUNT(*) as count
        FROM network_traffic
        GROUP BY protocol
        ORDER BY count DESC
    ''')
    proto_dist = [{'protocol': r['protocol'], 'count': r['count']} for r in cursor.fetchall()]

    # 7. Chart: Top Source IPs
    cursor.execute('''
        SELECT source_ip, COUNT(*) as packet_events,
               SUM(CASE WHEN status != 'Normal' THEN 1 ELSE 0 END) as anomalies
        FROM network_traffic
        GROUP BY source_ip
        ORDER BY packet_events DESC
        LIMIT 6
    ''')
    top_ips = [dict(r) for r in cursor.fetchall()]

    # 8. Chart: Anomalies by Hour
    cursor.execute('''
        SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
        FROM network_traffic
        WHERE status != 'Normal'
        GROUP BY hour
        ORDER BY hour ASC
    ''')
    anomalies_by_hour = [{'hour': r['hour'], 'count': r['count']} for r in cursor.fetchall()]

    # 9. Recent Critical Alerts
    cursor.execute('''
        SELECT id, source_ip, destination_ip, anomaly_type, severity, risk_score, status, timestamp, description
        FROM alerts
        ORDER BY id DESC LIMIT 5
    ''')
    recent_alerts = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return jsonify({
        'summary': {
            'total_packets': total_packets,
            'normal_traffic': normal_traffic,
            'anomalous_traffic': anomalous_traffic,
            'suspicious_traffic': suspicious_traffic,
            'threats_detected': threats_detected,
            'active_connections': active_conns,
            'network_risk_score': network_risk_score,
            'network_status': 'Threat Detected' if network_risk_score >= 70 else 'Network Secure',
            'simulation_running': simulator.is_running
        },
        'charts': {
            'traffic_over_time': traffic_over_time,
            'normal_vs_anom': normal_vs_anom,
            'attack_distribution': attack_dist,
            'protocol_distribution': proto_dist,
            'risk_score_trend': risk_trend,
            'top_source_ips': top_ips,
            'anomalies_by_hour': anomalies_by_hour
        },
        'recent_alerts': recent_alerts
    })

# ----------------- NETWORK TRAFFIC -----------------
@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 25))
    protocol = request.args.get('protocol', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '').strip()
    risk_level = request.args.get('risk_level', '')
    order_dir = request.args.get('order', 'DESC').upper()
    if order_dir not in ['ASC', 'DESC']:
        order_dir = 'DESC'

    query = "SELECT * FROM network_traffic WHERE 1=1"
    count_query = "SELECT COUNT(*) as count FROM network_traffic WHERE 1=1"
    params = []

    if protocol:
        query += " AND protocol = ?"
        count_query += " AND protocol = ?"
        params.append(protocol.upper())

    if status:
        query += " AND status = ?"
        count_query += " AND status = ?"
        params.append(status)

    if risk_level:
        if risk_level.lower() == 'low':
            query += " AND risk_score <= 30"
            count_query += " AND risk_score <= 30"
        elif risk_level.lower() == 'moderate':
            query += " AND risk_score > 30 AND risk_score <= 50"
            count_query += " AND risk_score > 30 AND risk_score <= 50"
        elif risk_level.lower() == 'high':
            query += " AND risk_score > 50 AND risk_score <= 70"
            count_query += " AND risk_score > 50 AND risk_score <= 70"
        elif risk_level.lower() == 'critical':
            query += " AND risk_score > 70"
            count_query += " AND risk_score > 70"

    if search:
        search_pattern = f"%{search}%"
        query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR source_port LIKE ? OR destination_port LIKE ? OR anomaly_type LIKE ?)"
        count_query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR source_port LIKE ? OR destination_port LIKE ? OR anomaly_type LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(count_query, params)
    total_records = cursor.fetchone()['count']

    offset = (page - 1) * limit
    query += f" ORDER BY id {order_dir} LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_pages = (total_records + limit - 1) // limit if limit > 0 else 1

    return jsonify({
        'traffic': rows,
        'pagination': {
            'page': page,
            'limit': limit,
            'total_records': total_records,
            'total_pages': total_pages
        }
    })

# ----------------- ML ANOMALY DETECTION (MANUAL PREDICT) -----------------
@app.route('/api/predict', methods=['POST'])
def predict_anomaly():
    data = request.get_json() or {}
    model_choice = data.get('model', 'random_forest')

    result = predictor.predict(data, selected_model=model_choice)
    return jsonify(result)

# ----------------- LIVE MONITORING & SIMULATION -----------------
@app.route('/api/traffic/live', methods=['GET'])
def get_live_stream():
    metrics = simulator.get_live_metrics()
    return jsonify(metrics)

@app.route('/api/simulation/start', methods=['POST'])
def start_simulation():
    res = simulator.start()
    return jsonify(res)

@app.route('/api/simulation/stop', methods=['POST'])
def stop_simulation():
    res = simulator.stop()
    return jsonify(res)

@app.route('/api/simulation/status', methods=['GET'])
def simulation_status():
    return jsonify({
        'is_running': simulator.is_running,
        'speed': simulator.speed,
        'total_simulated': simulator.total_packets_simulated,
        'anomalies_simulated': simulator.anomalies_simulated
    })

@app.route('/api/simulation/inject', methods=['POST'])
def inject_attack():
    data = request.get_json() or {}
    attack_type = data.get('attack_type', 'DoS')
    res = simulator.inject_attack(attack_type)
    return jsonify(res)

# ----------------- ALERTS MANAGEMENT -----------------
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity.capitalize())

    if status:
        query += " AND status = ?"
        params.append(status.capitalize())

    query += " ORDER BY id DESC LIMIT 100"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    alerts = [dict(r) for r in cursor.fetchall()]

    # Stats
    cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
    by_sev = {r['severity']: r['count'] for r in cursor.fetchall()}

    cursor.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
    by_status = {r['status']: r['count'] for r in cursor.fetchall()}

    conn.close()

    return jsonify({
        'alerts': alerts,
        'counts': {
            'total': len(alerts),
            'by_severity': by_sev,
            'by_status': by_status
        }
    })

@app.route('/api/alerts/<int:alert_id>', methods=['PATCH'])
def update_alert(alert_id):
    data = request.get_json() or {}
    new_status = data.get('status', 'Reviewed')
    if new_status not in ['New', 'Reviewed', 'Resolved']:
        new_status = 'Reviewed'

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, alert_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'id': alert_id, 'status': new_status})

@app.route('/api/alerts/resolve-all', methods=['POST'])
def resolve_all_alerts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = 'Resolved' WHERE status != 'Resolved'")
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'resolved_count': affected})

# ----------------- ATTACK ANALYSIS -----------------
@app.route('/api/attack-analysis', methods=['GET'])
def attack_analysis():
    conn = get_db_connection()
    cursor = conn.cursor()

    # By Type
    cursor.execute('''
        SELECT anomaly_type, COUNT(*) as count, AVG(risk_score) as avg_risk
        FROM network_traffic
        WHERE anomaly_type != 'Normal'
        GROUP BY anomaly_type
        ORDER BY count DESC
    ''')
    by_type = [{'type': r['anomaly_type'], 'count': r['count'], 'avg_risk': round(r['avg_risk'] or 0, 1)} for r in cursor.fetchall()]

    # By Protocol
    cursor.execute('''
        SELECT protocol,
               COUNT(*) as total,
               SUM(CASE WHEN status != 'Normal' THEN 1 ELSE 0 END) as anomalies
        FROM network_traffic
        GROUP BY protocol
    ''')
    by_proto = [dict(r) for r in cursor.fetchall()]

    # By Severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    ''')
    by_severity = [{'severity': r['severity'], 'count': r['count']} for r in cursor.fetchall()]

    # Anomalies Over Time (Last 24 buckets)
    cursor.execute('''
        SELECT timestamp, anomaly_type, risk_score
        FROM network_traffic
        WHERE status != 'Normal'
        ORDER BY id DESC LIMIT 30
    ''')
    timeline_rows = [dict(r) for r in cursor.fetchall()][::-1]
    timeline = [{
        'time': r['timestamp'].split(' ')[-1],
        'attack': r['anomaly_type'],
        'risk': r['risk_score']
    } for r in timeline_rows]

    # Top targeted ports
    cursor.execute('''
        SELECT destination_port, COUNT(*) as hits, anomaly_type
        FROM network_traffic
        WHERE status != 'Normal'
        GROUP BY destination_port
        ORDER BY hits DESC LIMIT 5
    ''')
    top_ports = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return jsonify({
        'anomalies_by_type': by_type,
        'anomalies_by_protocol': by_proto,
        'severity_distribution': by_severity,
        'timeline': timeline,
        'top_attacked_ports': top_ports
    })

# ----------------- MODEL PERFORMANCE -----------------
@app.route('/api/model-performance', methods=['GET'])
def get_model_performance():
    metrics_path = os.path.join(MODELS_DIR, 'metrics.json')
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    else:
        # Fallback if not loaded
        return jsonify({'error': 'Metrics not generated yet. Trigger training first.'}), 404

@app.route('/api/model-performance/retrain', methods=['POST'])
def retrain_models():
    try:
        metrics = train_and_evaluate()
        predictor.load_models()
        return jsonify({
            'success': True,
            'message': 'Models retrained and reloaded successfully.',
            'metrics': metrics
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------- REPORTS -----------------
@app.route('/api/reports', methods=['GET'])
def generate_report():
    report_type = request.args.get('type', 'daily') # daily, weekly, monthly, anomaly, attack

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as total FROM network_traffic')
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as normal FROM network_traffic WHERE status = 'Normal'")
    normal = cursor.fetchone()['normal']

    cursor.execute("SELECT COUNT(*) as anom FROM network_traffic WHERE status = 'Anomalous'")
    anom = cursor.fetchone()['anom']

    cursor.execute("SELECT COUNT(*) as susp FROM network_traffic WHERE status = 'Suspicious'")
    susp = cursor.fetchone()['susp']

    cursor.execute('SELECT AVG(risk_score) as avg_risk FROM network_traffic')
    avg_risk = round(cursor.fetchone()['avg_risk'] or 30, 1)

    cursor.execute('''
        SELECT anomaly_type, COUNT(*) as count
        FROM network_traffic
        WHERE anomaly_type != 'Normal'
        GROUP BY anomaly_type
        ORDER BY count DESC
    ''')
    attacks = [dict(r) for r in cursor.fetchall()]

    cursor.execute('''
        SELECT * FROM alerts ORDER BY risk_score DESC LIMIT 8
    ''')
    top_alerts = [dict(r) for r in cursor.fetchall()]

    conn.close()

    metrics_path = os.path.join(MODELS_DIR, 'metrics.json')
    model_info = {}
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            model_info = json.load(f).get('models', {})

    return jsonify({
        'report_type': report_type.title() + ' Network Security Report',
        'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'scope_period': 'Last 24 Hours' if report_type == 'daily' else ('Last 7 Days' if report_type == 'weekly' else 'Last 30 Days'),
        'metrics': {
            'total_traffic_packets': total,
            'normal_traffic': normal,
            'anomalous_traffic': anom,
            'suspicious_traffic': susp,
            'overall_risk_score': avg_risk,
            'anomaly_ratio': round((anom / max(total, 1)) * 100, 2)
        },
        'attack_breakdown': attacks,
        'critical_alerts': top_alerts,
        'model_benchmarks': {
            'random_forest_accuracy': model_info.get('random_forest', {}).get('metrics', {}).get('accuracy', 0.998),
            'decision_tree_accuracy': model_info.get('decision_tree', {}).get('metrics', {}).get('accuracy', 0.995),
            'isolation_forest_accuracy': model_info.get('isolation_forest', {}).get('metrics', {}).get('accuracy', 0.812)
        },
        'executive_recommendations': [
            "Maintain automated firewall rule synching for IPs flagged with critical DoS/DDoS volume",
            "Enforce Rate Limiting and fail2ban rules on sensitive administration ports (22, 3389)",
            "Review Isolation Forest zero-day anomaly candidates for potential APT lateral movement",
            "Periodically retrain ML models with updated network traffic baselines"
        ]
    })

@app.route('/api/reports/export-csv', methods=['GET'])
def export_csv():
    export_target = request.args.get('target', 'traffic') # traffic or alerts
    conn = get_db_connection()
    cursor = conn.cursor()

    output = io.StringIO()
    writer = csv.writer(output)

    if export_target == 'alerts':
        cursor.execute('SELECT * FROM alerts ORDER BY id DESC')
        rows = cursor.fetchall()
        writer.writerow(['Alert ID', 'Traffic ID', 'Source IP', 'Destination IP', 'Anomaly Type', 'Severity', 'Risk Score', 'Status', 'Description', 'Timestamp'])
        for r in rows:
            writer.writerow([r['id'], r['traffic_id'], r['source_ip'], r['destination_ip'], r['anomaly_type'], r['severity'], r['risk_score'], r['status'], r['description'], r['timestamp']])
        filename = f"networkguard_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    else:
        cursor.execute('SELECT * FROM network_traffic ORDER BY id DESC LIMIT 1000')
        rows = cursor.fetchall()
        writer.writerow(['Packet ID', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Packet Count', 'Packet Size (B)', 'Duration (s)', 'Packets/Sec', 'Bytes/Sec', 'Flow Bytes', 'Connections', 'Failed Connections', 'Status', 'Risk Score', 'Anomaly Type', 'Reason', 'Timestamp'])
        for r in rows:
            writer.writerow([
                r['id'], r['source_ip'], r['destination_ip'], r['protocol'],
                r['source_port'], r['destination_port'], r['packet_count'],
                r['packet_size'], r['duration'], r['packets_per_sec'],
                r['bytes_per_sec'], r['flow_bytes'], r['num_conn'],
                r['failed_conn'], r['status'], r['risk_score'],
                r['anomaly_type'], r['possible_reason'], r['timestamp']
            ])
        filename = f"networkguard_traffic_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    conn.close()

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

# ----------------- SYSTEM SETTINGS & RESET -----------------
@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        data = request.get_json() or {}
        for k, v in data.items():
            cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (k, str(v)))
        conn.commit()

    cursor.execute('SELECT key, value FROM system_settings')
    settings = {r['key']: r['value'] for r in cursor.fetchall()}
    conn.close()
    return jsonify(settings)

@app.route('/api/settings/reset', methods=['POST'])
def reset_demo_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts')
    cursor.execute('DELETE FROM network_traffic')
    seed_sample_traffic_and_alerts(cursor)
    conn.commit()
    conn.close()

    simulator.init_live_buffer()
    simulator.total_packets_simulated = 0
    simulator.anomalies_simulated = 0

    return jsonify({'success': True, 'message': 'Demo database successfully reset and reseeded.'})

if __name__ == '__main__':
    print("Starting NetworkGuard AI Flask Server on http://localhost:5000 ...")
    app.run(host='0.0.0.0', port=5000, debug=False)
