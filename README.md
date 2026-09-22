# NetworkGuard AI — Network Anomaly Detection System using Machine Learning

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/Frontend-React%2019-61dafb.svg)](https://react.dev/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn%201.6-orange.svg)](https://scikit-learn.org/)
[![Tailwind CSS](https://img.shields.io/badge/Styles-Tailwind%20CSS%20v4-38bdf8.svg)](https://tailwindcss.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite3-003B57.svg)](https://www.sqlite.org/)

> **A functional, full-stack, AI-powered Network Intrusion Detection & Anomaly Monitoring Platform built as a 3rd/4th-year Engineering Capstone Project.**

---

## 1. Project Objective

In modern enterprise infrastructures, cyber threats such as Distributed Denial of Service (DDoS), sequential port scans, credential brute-forcing, botnet command-and-control beaconing, and zero-day exploits threaten organizational uptime. Traditional signature-based firewalls fail against unknown traffic variations.

**NetworkGuard AI** solves this by uniting **Supervised Machine Learning** (Random Forest & Decision Trees) with **Unsupervised Anomaly Detection** (Isolation Forests) to classify real-time and simulated network traffic flows into:
- 🟢 **Normal Traffic** (Verified protocol behavior)
- 🟡 **Suspicious Traffic** (Elevated statistical variance)
- 🔴 **Anomalous / Malicious Traffic** (DoS, DDoS, Port Scan, Brute Force, Botnet, Web Attack)

---

## 2. System Architecture

```
                                  [ Network Traffic Source ]
                                (Simulated Engine / Live Packet Feed)
                                               │
                                               ▼
                                 [ Data Ingestion & Extraction ]
                      (12 Features: Duration, Ports, Packet Count, Rates, Sockets)
                                               │
                                               ▼
                                   [ Feature Preprocessing ]
                           (Protocol One-Hot Encoding + Standard Scaling)
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        ▼                                             ▼
          [ Supervised Classification ]                  [ Unsupervised Detection ]
           • Random Forest Classifier                     • Isolation Forest Outlier Score
           • Decision Tree Classifier                     (Contamination: 0.35)
                        │                                             │
                        └──────────────────────┬──────────────────────┘
                                               ▼
                                    [ Decision Engine & XAI ]
                         • Multi-class Attack Categorization (DoS/Scan/etc.)
                         • Dynamic Network Risk Score (0–100 Scale)
                         • Explainable AI (XAI) Reason Breakdown
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        ▼                                             ▼
               [ SQLite Database ]                            [ Flask REST API ]
           • network_traffic table                        • /api/dashboard
           • alerts table                                 • /api/traffic & /api/predict
           • users & settings                             • /api/traffic/live stream
                        │                                             │
                        └──────────────────────┬──────────────────────┘
                                               ▼
                               [ React 19 Cyber Dashboard UI ]
                 • Real-time Recharts Area/Line/Bar/Pie Data Visualizations
                 • Security Alerts Triage & Incident Resolution
                 • ML Prediction Sandbox with Explainability & Presets
                 • Automated Executive Security PDF & CSV Report Generator
```

---

## 3. Technology Stack

| Layer | Technologies Used |
|---|---|
| **Frontend UI** | React.js 19, Tailwind CSS v4, Lucide Icons, Recharts Analytics |
| **Backend API** | Python 3.11+, Flask 3.1, Flask-CORS, Werkzeug Security |
| **Machine Learning** | Scikit-learn, Pandas, NumPy, Joblib |
| **ML Algorithms** | Random Forest Classifier, Decision Tree Classifier, Isolation Forest |
| **Database** | SQLite 3 (Auto-migrating, connection pooling, seed data) |
| **Live Simulator** | Multi-threaded Python daemon generating continuous packet telemetry |

---

## 4. Key Features & Dashboard Modules

### 1. Security Overview Dashboard
- **6 Top Metric Cards**: Total Packets, Normal Traffic, Anomalous Traffic, Threats Detected, Active Connections, Dynamic Risk Score (0–100).
- **7 Interactive Forensic Charts**:
  1. *Network Traffic Over Time* (Area Chart with gradient fill)
  2. *Normal vs Anomalous Traffic* (Dual-stream stacked area)
  3. *Attack Type Distribution* (Donut chart: DoS, Port Scan, Brute Force, etc.)
  4. *Protocol Distribution* (Bar chart: TCP, UDP, ICMP, HTTP, DNS)
  5. *Risk Score Trend* (Line chart against danger threshold line at 70)
  6. *Top Network Sources & Threat Origins* (Packet events and anomaly counts)
  7. *Anomalies by Time of Day* (Hourly incident frequency)
- **Recent Intercepted Alerts Feed** with triage status.

### 2. Network Traffic Inspection Table
- Full tabular log displaying Packet ID, Source/Destination IPs & Ports, Protocol, Packet Count, Size, Flow Duration, Packets/Sec, Bytes/Sec, Status (🟢 Normal, 🟡 Suspicious, 🔴 Anomalous), Risk Score, and Timestamp.
- Interactive multi-parameter filtering: Filter by Protocol, Status, Risk Level (Low, Moderate, High, Critical), Search IP/Port.
- Individual **Packet Forensics Modal** with Explainable AI reasoning.

### 3. ML-Based Anomaly Detection Sandbox
- Manual testing workbench allowing users to input any 12 network features.
- Quick Demonstration Presets:
  - *Normal HTTPS Browsing*
  - *DDoS SYN Flood Volumetric Attack*
  - *Stealthy Port Scan Sweep*
  - *SSH Brute Force Credential Crack*
- Outputs large verdict banner, Attack Type, Risk Score, and **Explainable AI "Possible Reasons"**.

### 4. Real-Time Live Monitoring Stream
- Large pulsating status badge: 🟢 **NETWORK SECURE** vs 🔴 **THREAT DETECTED**.
- Live streaming line charts updated every 1.5s.
- Instantaneous Attack Injector buttons ("Inject DoS", "Inject Port Scan", "Inject Brute Force") to demonstrate immediate SIEM response.

### 5. Security Alerts Management
- Full incident triage console with severity rankings (Low 🟢, Medium 🟡, High 🟠, Critical 🔴).
- Interactive actions: "View Details", "Mark Reviewed", "Resolve Alert", and "Resolve All Alerts".

### 6. Attack Forensics & Vector Analysis
- Deconstructs anomalies across categories, protocols, peak hours, and targeted ports.
- Provides actionable cybersecurity countermeasures (SYN cookies, psad, fail2ban, DNS sinkholing).

### 7. Executive Report Generator
- Generates Daily, Weekly, Monthly, Anomaly-focused, and Attack Taxonomy reports.
- Clean printable formatting via **"Download PDF"** (`window.print()`).
- Direct **"Export CSV"** for external SIEM analysis.

### 8. ML Model Benchmarks
- Side-by-side performance comparison of Random Forest, Decision Tree, and Isolation Forest.
- Visual Confusion Matrix (True Negatives, False Positives, False Negatives, True Positives).
- Feature Importance ranking chart.
- One-click **"Retrain ML Models"** trigger.

---

## 5. Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Node.js v18 or higher (v20+ recommended) & npm

### Quick One-Click Startup (Windows)
Double-click `run_all.bat` (or right-click `run_all.ps1` -> Run with PowerShell).
This automatically starts both the Flask backend on port 5000 and the React frontend on port 5173.

---

### Manual Setup Step-by-Step

#### Step 1: Clone Repository & Open Directory
```bash
git clone <repository_url>
cd DSL
```

#### Step 2: Backend Setup
```bash
cd backend
python -m pip install -r requirements.txt

# (Optional) Retrain ML models and generate fresh metrics
python ml/train_models.py

# Launch Flask API Server
python app.py
```
*Backend server will start at: `http://localhost:5000`*

#### Step 3: Frontend Setup (in a new terminal)
```bash
cd frontend
npm install
npm run dev
```
*Frontend dashboard will be accessible at: `http://localhost:5173`*

---

## 6. Default Credentials

- **Username**: `admin`
- **Password**: `admin123`
*(A convenient "Auto-fill Admin Credentials" button is provided directly on the login screen for viva demonstrations)*

---

## 7. REST API Documentation

| Endpoint | Method | Description |
|---|---|---|
| `/api/auth/login` | `POST` | Authenticates administrator credentials |
| `/api/dashboard` | `GET` | Fetches aggregated statistics and 7 chart datasets |
| `/api/traffic` | `GET` | Paginated, filterable, and searchable packet logs |
| `/api/predict` | `POST` | Executes ML inference on 12 network features |
| `/api/traffic/live` | `GET` | Returns rolling buffer for high-frequency live charts |
| `/api/simulation/start` | `POST` | Starts daemon background packet generator |
| `/api/simulation/stop` | `POST` | Pauses background packet generator |
| `/api/simulation/inject`| `POST` | Dispatches instantaneous attack burst (DoS, Port Scan, etc.) |
| `/api/alerts` | `GET` | Retrieves security alerts filtered by severity/status |
| `/api/alerts/<id>` | `PATCH`| Updates alert status to `Reviewed` or `Resolved` |
| `/api/attack-analysis` | `GET` | Retrieves attack taxonomy and protocol breakdown |
| `/api/model-performance`| `GET` | Returns accuracy, confusion matrix, and feature importances |
| `/api/model-performance/retrain` | `POST` | Retrains models on fresh synthesized dataset |
| `/api/reports` | `GET` | Generates structured audit reports (daily/weekly/monthly) |
| `/api/reports/export-csv` | `GET` | Downloads streaming CSV of traffic or alerts |
| `/api/settings/reset` | `POST` | Resets SQLite database to fresh seed state |

---

## 8. College Project Viva & Presentation Guide

When presenting this project to professors or external examiners, follow this recommended walkthrough:

1. **Login Page**:
   - Highlight secure hashed authentication (`werkzeug.security.generate_password_hash`).
   - Mention the responsive dark cyber design and role-based access control.

2. **Main Dashboard**:
   - Point out the **6 Stat Cards** and explain the **Dynamic Network Risk Score (0–100)**.
   - Explain how the 7 charts update dynamically as network packets arrive.

3. **ML Anomaly Detection Sandbox**:
   - Click one of the quick presets (e.g. **DDoS SYN Flood**).
   - Click **"Detect Anomaly"** and explain the **Explainable AI (XAI)** reasoning output (e.g. volumetric packet rate > 80,000 pps, failed handshake count > 200).
   - Show the model consensus breakdown across Random Forest, Decision Tree, and Isolation Forest.

4. **Live Monitoring Simulation**:
   - Click **"Start Network Simulation"**.
   - Watch the packets/sec, throughput, and risk score stream in real time every 1.5 seconds.
   - Click **"Inject DoS"** or **"Inject Port Scan"**; show how the status immediately flips to 🔴 **"THREAT DETECTED"** and fires an instant alert!

5. **Alerts & Attack Analysis**:
   - Review the newly intercepted alert, inspect the details modal, and click **"Resolve Alert"**.
   - Show the Attack Analysis forensic charts categorizing DoS, Port Scan, Brute Force, and protocol breakdowns.

6. **ML Performance & Reports**:
   - Show the head-to-head comparison chart, the Confusion Matrix (TP/FP/TN/FN), and Feature Importance weights.
   - Switch to **Reports**, generate a Daily Report, and demonstrate **Download PDF** and **Export CSV**.

---

## 9. License & Academic Attribution
Developed for educational, university capstone project, and laboratory research demonstrations in Machine Learning & Cyber Defense.
