# 🛡️ NetworkGuard AI — Intelligent IDS & Anomaly Detector

**NetworkGuard AI** is a real-time, multi-model Network Intrusion Detection System (IDS) and Anomaly Monitoring Platform. The system leverages live telemetry data and machine learning algorithms to continuously analyze network traffic, identify potential cyber threats, and mitigate security incidents.

---

## 📸 Application Dashboards

### 1. Live Security Dashboard
*Real-time packet telemetry, risk score tracking, and intrusion overview.*

![Security Dashboard](screenshots/dashboard.png)

---

### 2. ML Anomaly Detection Sandbox
*Telemetry parameter testing, live attack presets, and model consensus breakdown.*

![Anomaly Detection](screenshots/anomaly-detection.png)

---

### 3. Security Alerts Console
*Incident response console with severity classification and threat triage actions.*

![Security Alerts Console](screenshots/alerts.png)

---

### 4. ML Model Performance Benchmarks
*Algorithm comparison benchmarks, confusion matrix, and feature importances.*

![ML Benchmarks](screenshots/ml-performance.png)

---

## ✨ Core Features

- **Multi-Model Consensus Engine:**
  - **Random Forest & Decision Tree:** Primary supervised classifiers for known attack vectors (DDoS, Brute Force, Port Scan, Botnet, and DoS).
  - **Isolation Forest:** Multi-dimensional unsupervised anomaly detection to catch zero-day attacks and abnormal traffic spikes.
- **Interactive Anomaly Sandbox:** Test scenarios with pre-configured attack presets (Normal HTTPS, DDoS SYN Flood, Stealthy Port Scan, SSH Brute Force).
- **Real-Time Traffic Simulator:** Injects synthetic network traffic and monitors telemetry flow dynamically.
- **Explainable AI (XAI) & Incident Console:** Real-time threat classification, automated risk scoring, and triage console.
- **Security Reporting & Audit:** Detailed incident summaries and verifiable ML pipeline performance benchmarks.

---

## 🏗️ Project Structure

```text
NetworkGuard-AI/
├── backend/
│   ├── app.py                   # Flask API entrypoint & telemetry server
│   ├── database.py              # SQLite storage for packet logs and alert history
│   ├── simulator.py             # Network traffic simulator and attack injector
│   ├── ml/
│   │   ├── dataset_generator.py # Synthetic network traffic data generation pipeline
│   │   ├── train_models.py      # ML model training and evaluation routines
│   │   └── predictor.py         # Multi-model real-time inference logic
│   └── models/                  # Serialized trained model artifacts (.pkl)
├── frontend/
│   ├── src/                     # React dashboard components, graphs, and UI views
│   ├── dist/                    # Production build assets
│   └── vite.config.js           # Vite development server configuration
└── screenshots/                 # Application UI preview screenshots


🚀 Getting Started
1. Backend Setup (Flask API)

# Navigate to the backend directory
cd backend

# Create and activate a virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

# Start the Flask backend server
python app.py

The backend API server will run on http://127.0.0.1:5000.

2. Frontend Setup (React UI)

# Open a new terminal and navigate to the frontend directory
cd frontend

# Install node dependencies
npm install

# Run the development server
npm run dev
The application dashboard will be live at http://localhost:5173.

🛠️ Tech Stack
Frontend: React, Vite, Tailwind CSS, Lucide Icons

Backend: Python, Flask, SQLite

Machine Learning: Scikit-Learn (Random Forest, Decision Tree, Isolation Forest), Pandas, NumPy

Telemetry & Simulation: Multi-threaded packet flow simulator

👥 Project Contributors
Hinal Machhi (@hinalmachhi)

Vedika Manjarekar

Saini Pagdhare
