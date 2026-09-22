import json
from database import init_db, get_db_connection
from ml.predictor import predictor
from simulator import simulator

def test_backend():
    print("Testing DB initialization...")
    init_db()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as count FROM network_traffic")
    traffic_count = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM alerts")
    alert_count = c.fetchone()['count']
    c.execute("SELECT COUNT(*) as count FROM users")
    user_count = c.fetchone()['count']
    conn.close()

    print(f"-> DB Counts: Traffic={traffic_count}, Alerts={alert_count}, Users={user_count}")
    assert traffic_count > 0, "No traffic records found in DB"
    assert user_count > 0, "No user records found in DB"

    print("\nTesting ML Predictor on Normal Traffic Sample...")
    normal_sample = {
        'duration': 1.2,
        'src_port': 54321,
        'dst_port': 443,
        'packet_count': 15,
        'packet_size': 600.0,
        'bytes_per_sec': 7500.0,
        'packets_per_sec': 12.5,
        'flow_bytes': 9000.0,
        'num_conn': 3,
        'conn_duration': 1.8,
        'failed_conn': 0,
        'protocol_type': 'TCP'
    }
    res_norm = predictor.predict(normal_sample)
    print(f"-> Normal result: Status={res_norm['prediction']}, Risk={res_norm['risk_score']}%, Attack={res_norm['anomaly_type']}")
    print(f"   Reasons: {res_norm['possible_reasons']}")
    assert res_norm['prediction'] == 'Normal', f"Expected Normal, got {res_norm['prediction']}"

    print("\nTesting ML Predictor on DoS Attack Sample...")
    dos_sample = {
        'duration': 0.5,
        'src_port': 48123,
        'dst_port': 80,
        'packet_count': 25000,
        'packet_size': 64.0,
        'bytes_per_sec': 3200000.0,
        'packets_per_sec': 50000.0,
        'flow_bytes': 1600000.0,
        'num_conn': 350,
        'conn_duration': 0.1,
        'failed_conn': 180,
        'protocol_type': 'TCP'
    }
    res_dos = predictor.predict(dos_sample)
    print(f"-> DoS result: Status={res_dos['prediction']}, Risk={res_dos['risk_score']}%, Attack={res_dos['anomaly_type']}")
    print(f"   Reasons: {res_dos['possible_reasons']}")
    assert res_dos['prediction'] == 'Anomalous', f"Expected Anomalous, got {res_dos['prediction']}"

    print("\nTesting Simulator Live Buffer...")
    live = simulator.get_live_metrics()
    print(f"-> Live metrics: Status={live['network_status']}, Buffer points={len(live['chart_data'])}, Risk={live['current_risk_score']}")
    assert len(live['chart_data']) > 0, "Live buffer should have pre-populated points"

    print("\nALL BACKEND & ML CHECKS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    test_backend()
