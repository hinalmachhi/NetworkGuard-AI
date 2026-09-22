import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

try:
    from ml.dataset_generator import generate_network_dataset, DATASET_PATH
except ImportError:
    from dataset_generator import generate_network_dataset, DATASET_PATH

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

FEATURE_COLS = [
    'duration', 'src_port', 'dst_port', 'packet_count', 'packet_size',
    'bytes_per_sec', 'packets_per_sec', 'flow_bytes', 'num_conn',
    'conn_duration', 'failed_conn'
]

PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']

def preprocess_dataframe(df):
    """Clean and encode features"""
    df = df.copy()
    # Handle missing values if any
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(df[FEATURE_COLS].median())

    # One-hot encode protocol_type with fixed columns
    for proto in PROTOCOLS:
        df[f'proto_{proto}'] = (df['protocol_type'] == proto).astype(int)

    feature_matrix = FEATURE_COLS + [f'proto_{proto}' for proto in PROTOCOLS]
    return df, feature_matrix

def train_and_evaluate():
    # 1. Load or generate dataset
    if not os.path.exists(DATASET_PATH):
        print("Dataset not found. Generating new dataset...")
        df = generate_network_dataset(num_samples=5000)
    else:
        df = pd.read_csv(DATASET_PATH)

    print(f"Loaded dataset with {len(df)} samples.")
    print("Class distribution:\n", df['attack_type'].value_counts())

    # 2. Preprocess data
    df_processed, feature_cols = preprocess_dataframe(df)

    X = df_processed[feature_cols].values
    y_binary = df_processed['is_anomaly'].values
    y_attack = df_processed['attack_type'].values

    # Encode attack labels
    label_encoder = LabelEncoder()
    y_attack_encoded = label_encoder.fit_transform(y_attack)

    # 3. Train/Test Split (80% train, 20% test)
    X_train, X_test, y_bin_train, y_bin_test, y_att_train, y_att_test = train_test_split(
        X, y_binary, y_attack_encoded, test_size=0.20, random_state=42, stratify=y_attack_encoded
    )

    # 4. Scale numerical features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 5. Train Random Forest (Attack Classifier & Binary Anomaly)
    print("\n[1/3] Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_att_train)
    rf_preds = rf.predict(X_test_scaled)
    # Binary predictions: anything other than Normal (class index of 'Normal') is anomaly
    normal_idx = list(label_encoder.classes_).index('Normal')
    rf_bin_preds = (rf_preds != normal_idx).astype(int)

    # 6. Train Decision Tree Classifier
    print("[2/3] Training Decision Tree Classifier...")
    dt = DecisionTreeClassifier(max_depth=12, random_state=42)
    dt.fit(X_train_scaled, y_att_train)
    dt_preds = dt.predict(X_test_scaled)
    dt_bin_preds = (dt_preds != normal_idx).astype(int)

    # 7. Train Isolation Forest (Unsupervised Anomaly Detection)
    print("[3/3] Training Isolation Forest...")
    iso = IsolationForest(n_estimators=100, contamination=0.35, random_state=42, n_jobs=-1)
    # Fit Isolation Forest on training data
    iso.fit(X_train_scaled)
    # Isolation forest outputs -1 for anomaly, 1 for normal
    iso_preds_raw = iso.predict(X_test_scaled)
    iso_bin_preds = (iso_preds_raw == -1).astype(int)

    # 8. Evaluation Metrics
    def compute_metrics(y_true, y_pred):
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
        return {
            'accuracy': round(float(accuracy_score(y_true, y_pred)), 4),
            'precision': round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            'recall': round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            'f1': round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            'confusion_matrix': {
                'true_negative': int(tn),
                'false_positive': int(fp),
                'false_negative': int(fn),
                'true_positive': int(tp),
                'matrix': cm.tolist()
            }
        }

    rf_metrics = compute_metrics(y_bin_test, rf_bin_preds)
    dt_metrics = compute_metrics(y_bin_test, dt_bin_preds)
    iso_metrics = compute_metrics(y_bin_test, iso_bin_preds)

    # Compute Feature Importances from Random Forest
    importances = rf.feature_importances_
    feature_importance_list = [
        {'feature': feat, 'importance': round(float(imp), 4)}
        for feat, imp in sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    ]

    # Multiclass attack breakdown metrics for Random Forest
    attack_classes = list(label_encoder.classes_)
    rf_multiclass_cm = confusion_matrix(y_att_test, rf_preds).tolist()

    all_metrics = {
        'trained_at': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_samples': len(df),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'feature_columns': feature_cols,
        'attack_classes': attack_classes,
        'models': {
            'random_forest': {
                'name': 'Random Forest',
                'type': 'Supervised Ensemble',
                'metrics': rf_metrics,
                'feature_importance': feature_importance_list[:8]
            },
            'decision_tree': {
                'name': 'Decision Tree',
                'type': 'Supervised Tree',
                'metrics': dt_metrics
            },
            'isolation_forest': {
                'name': 'Isolation Forest',
                'type': 'Unsupervised Anomaly Detector',
                'metrics': iso_metrics
            }
        },
        'multiclass_confusion_matrix': {
            'labels': attack_classes,
            'matrix': rf_multiclass_cm
        }
    }

    # 9. Save artifacts
    joblib.dump(rf, os.path.join(MODELS_DIR, 'random_forest.pkl'))
    joblib.dump(dt, os.path.join(MODELS_DIR, 'decision_tree.pkl'))
    joblib.dump(iso, os.path.join(MODELS_DIR, 'isolation_forest.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.pkl'))
    joblib.dump(label_encoder, os.path.join(MODELS_DIR, 'label_encoder.pkl'))
    joblib.dump(feature_cols, os.path.join(MODELS_DIR, 'feature_cols.pkl'))

    with open(os.path.join(MODELS_DIR, 'metrics.json'), 'w') as f:
        json.dump(all_metrics, f, indent=2)

    print("\n================ ML MODEL EVALUATION RESULTS ================")
    print(f"Random Forest  -> Accuracy: {rf_metrics['accuracy']*100:.2f}% | Precision: {rf_metrics['precision']*100:.2f}% | Recall: {rf_metrics['recall']*100:.2f}% | F1: {rf_metrics['f1']*100:.2f}%")
    print(f"Decision Tree  -> Accuracy: {dt_metrics['accuracy']*100:.2f}% | Precision: {dt_metrics['precision']*100:.2f}% | Recall: {dt_metrics['recall']*100:.2f}% | F1: {dt_metrics['f1']*100:.2f}%")
    print(f"Isolation Forest -> Accuracy: {iso_metrics['accuracy']*100:.2f}% | Precision: {iso_metrics['precision']*100:.2f}% | Recall: {iso_metrics['recall']*100:.2f}% | F1: {iso_metrics['f1']*100:.2f}%")
    print(f"Models successfully saved to: {MODELS_DIR}")
    return all_metrics

if __name__ == '__main__':
    train_and_evaluate()
