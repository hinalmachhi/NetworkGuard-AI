import urllib.request
import urllib.parse
import json

BASE_URL = 'http://localhost:5000/api'

def req(endpoint, method='GET', data=None):
    url = f"{BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    body = json.dumps(data).encode() if data else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode())

def run_e2e_tests():
    print("================ RUNNING FULL-STACK E2E TESTS ================")

    # 1. Login
    print("\n[1] Testing Admin Login...")
    login_res = req('/auth/login', method='POST', data={'username': 'admin', 'password': 'admin123'})
    assert login_res['success'] == True, "Login failed"
    print(" -> Login Successful! User:", login_res['user']['username'], "| Role:", login_res['user']['role'])

    # 2. Dashboard
    print("\n[2] Testing Dashboard Summary & 7 Charts...")
    dash = req('/dashboard')
    assert 'summary' in dash, "Summary missing"
    assert len(dash['charts']['traffic_over_time']) > 0, "Traffic over time empty"
    assert len(dash['charts']['normal_vs_anom']) > 0, "Normal vs Anomaly empty"
    assert len(dash['charts']['attack_distribution']) > 0, "Attack distribution empty"
    assert len(dash['charts']['protocol_distribution']) > 0, "Protocol distribution empty"
    assert len(dash['charts']['risk_score_trend']) > 0, "Risk score trend empty"
    assert len(dash['charts']['top_source_ips']) > 0, "Top source IPs empty"
    assert len(dash['charts']['anomalies_by_hour']) > 0, "Anomalies by hour empty"
    print(f" -> Dashboard Data OK! Packets: {dash['summary']['total_packets']} | Normal: {dash['summary']['normal_traffic']} | Risk: {dash['summary']['network_risk_score']}%")

    # 3. Traffic Inspection & Filtering
    print("\n[3] Testing Traffic Query & Filtering...")
    traffic_res = req('/traffic?page=1&limit=10&protocol=TCP&status=Normal')
    assert len(traffic_res['traffic']) > 0, "No TCP Normal traffic found"
    print(f" -> Traffic Query OK! Returned {len(traffic_res['traffic'])} rows. Total records: {traffic_res['pagination']['total_records']}")

    # 4. Anomaly Detection ML Inference
    print("\n[4] Testing ML Anomaly Detection Endpoint...")
    anom_payload = {
        'duration': 0.3,
        'protocol_type': 'TCP',
        'src_port': 50123,
        'dst_port': 80,
        'packet_count': 45000,
        'packet_size': 64.0,
        'bytes_per_sec': 9600000.0,
        'packets_per_sec': 150000.0,
        'flow_bytes': 2880000.0,
        'num_conn': 500,
        'conn_duration': 0.05,
        'failed_conn': 320,
        'model': 'random_forest'
    }
    pred = req('/predict', method='POST', data=anom_payload)
    print(f" -> ML Prediction: {pred['prediction']} | Attack: {pred['anomaly_type']} | Risk: {pred['risk_score']}% ({pred['risk_level']})")
    print(f"    Explainable AI Reasons: {pred['possible_reasons']}")
    assert pred['prediction'] == 'Anomalous', "Expected Anomalous prediction"
    assert pred['risk_score'] >= 70, "Expected high risk score"

    # 5. Live Simulation Toggle & Attack Injection
    print("\n[5] Testing Simulation Engine & Attack Burst Injection...")
    sim_start = req('/simulation/start', method='POST')
    print(" -> Simulation started:", sim_start['status'])
    inject = req('/simulation/inject', method='POST', data={'attack_type': 'DDoS'})
    print(" -> Attack injected:", inject['attack_type'])
    live_metrics = req('/traffic/live')
    print(f" -> Live Stream OK! Packets/sec: {live_metrics['packets_per_sec']} | Dynamic Risk: {live_metrics['current_risk_score']}% | Status: {live_metrics['network_status']}")
    sim_stop = req('/simulation/stop', method='POST')
    print(" -> Simulation stopped:", sim_stop['status'])

    # 6. Alerts Triage
    print("\n[6] Testing Alerts Management...")
    alerts_data = req('/alerts')
    assert len(alerts_data['alerts']) > 0, "No alerts found"
    first_alert = alerts_data['alerts'][0]
    print(f" -> First alert: ID #{first_alert['id']} | {first_alert['anomaly_type']} | Severity: {first_alert['severity']}")
    patch_res = req(f"/alerts/{first_alert['id']}", method='PATCH', data={'status': 'Reviewed'})
    assert patch_res['status'] == 'Reviewed', "Alert status patch failed"
    print(f" -> Alert #{first_alert['id']} successfully updated to 'Reviewed'")

    # 7. Attack Analysis & Forensics
    print("\n[7] Testing Attack Forensics Endpoint...")
    attack_data = req('/attack-analysis')
    assert len(attack_data['anomalies_by_type']) > 0, "No anomaly types found"
    print(f" -> Attack Analysis OK! Categories mapped: {[a['type'] for a in attack_data['anomalies_by_type']]}")

    # 8. Model Performance
    print("\n[8] Testing ML Model Benchmarks Endpoint...")
    perf = req('/model-performance')
    rf_acc = perf['models']['random_forest']['metrics']['accuracy'] * 100
    dt_acc = perf['models']['decision_tree']['metrics']['accuracy'] * 100
    iso_acc = perf['models']['isolation_forest']['metrics']['accuracy'] * 100
    print(f" -> Models Loaded! RF Accuracy: {rf_acc:.1f}% | DT Accuracy: {dt_acc:.1f}% | IF Accuracy: {iso_acc:.1f}%")

    # 9. Reports
    print("\n[9] Testing Security Report Generation...")
    report = req('/reports?type=daily')
    print(f" -> Report Generated: '{report['report_type']}' | Scope: {report['scope_period']} | Total Packets: {report['metrics']['total_traffic_packets']}")

    print("\n================ ALL E2E BACKEND & ML TESTS PASSED 100% ================\n")

if __name__ == '__main__':
    run_e2e_tests()
