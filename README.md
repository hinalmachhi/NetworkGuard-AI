# 🛡️ NetworkGuard-AI

## AI-Powered Network Intrusion Detection & Anomaly Monitoring System

NetworkGuard-AI is a machine-learning-based Network Intrusion Detection System (IDS) designed to monitor network traffic, identify suspicious activities, and provide security insights through an interactive web dashboard.

The system combines a Flask backend, React frontend, network traffic simulation, SQLite storage, and multiple Machine Learning models for network threat and anomaly detection.

---

## 📌 Project Overview

NetworkGuard-AI provides a simulated environment for monitoring and analyzing network traffic.

The system:

- Generates and simulates network traffic
- Processes network telemetry through a Flask backend
- Applies Machine Learning models to network traffic
- Detects suspicious and anomalous activities
- Generates security alerts
- Stores packet logs and alert history
- Displays security information through an interactive React dashboard

The project is intended for academic, educational, and demonstration purposes.

---

## ✨ Key Features

### 🔍 Network Traffic Monitoring
Monitor simulated network traffic and telemetry data in real time.

### 🤖 Machine Learning-Based Detection
Uses multiple Machine Learning algorithms to analyze network traffic and detect suspicious behavior.

### 🧠 Multi-Model Detection
The system includes:

- Random Forest
- Decision Tree
- Isolation Forest

### ⚠️ Security Alerts
Detected suspicious activities can be represented through security alerts and monitoring information.

### 📊 Interactive Dashboard
A React-based dashboard provides visual representation of network activity, predictions, alerts, and monitoring information.

### 🎯 Attack Simulation
The traffic simulator can generate different network traffic scenarios for testing the detection system.

### 💾 Data Storage
SQLite is used to store packet logs and alert history.

### 📈 ML Model Evaluation
The project includes model training and evaluation functionality for analyzing Machine Learning performance.

---

# 🖥️ Application Screenshots

> Screenshots will be added to the `screenshots/` folder.

## 1. 🔐 Security Dashboard

Real-time overview of network activity, security monitoring, and detected threats.

![Security Dashboard](screenshots/01-dashboard.png)

---

## 2. 📡 Network Traffic Monitoring

Visualization of simulated network traffic and telemetry information.

![Network Traffic Monitoring](screenshots/02-network-traffic.png)

---

## 3. 🚨 Anomaly Detection

Machine Learning-based analysis of network traffic for identifying abnormal activity.

![Anomaly Detection](screenshots/03-anomaly-detection.png)

---

## 4. ⚠️ Security Alerts

Displays security events and detected suspicious activities.

![Security Alerts](screenshots/04-security-alerts.png)

---

## 5. 📊 ML Model Performance

Model training and evaluation results for the Machine Learning models.

![ML Model Performance](screenshots/05-ml-performance.png)

---

# 🏗️ System Architecture

```text
                    ┌──────────────────────────┐
                    │      React Frontend      │
                    │    Security Dashboard    │
                    └────────────┬─────────────┘
                                 │
                                 │ REST API
                                 ▼
                    ┌──────────────────────────┐
                    │      Flask Backend       │
                    │          app.py          │
                    └────────────┬─────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             │                   │                   │
             ▼                   ▼                   ▼
      ┌─────────────┐    ┌──────────────┐    ┌─────────────┐
      │  Traffic    │    │  ML Models   │    │   SQLite    │
      │  Simulator  │    │              │    │  Database   │
      └─────────────┘    └──────┬───────┘    └─────────────┘
                                 │

📂 Project Structure
NetworkGuard-AI/
│
├── backend/
│   ├── app.py
│   ├── database.py
│   ├── simulator.py
│   │
│   ├── ml/
│   │   ├── dataset_generator.py
│   │   ├── train_models.py
│   │   └── predictor.py
│   │
│   └── models/
│       └── *.pkl
│
├── frontend/
│   ├── src/
│   ├── dist/
│   └── vite.config.js
│
├── screenshots/
│   ├── 01-dashboard.png
│   ├── 02-network-traffic.png
│   ├── 03-anomaly-detection.png
│   ├── 04-security-alerts.png
│   └── 05-ml-performance.png
│
├── README.md
├── requirements.txt
├── run_all.bat
├── run_all.ps1
├── run_backend.bat
└── run_frontend.bat

🛠️ Technology Stack
Frontend
React
Vite
Tailwind CSS
Lucide Icons
Backend
Python
Flask
SQLite
Machine Learning
Scikit-Learn
Pandas
NumPy
Machine Learning Algorithms
Random Forest
Decision Tree
Isolation Forest
Simulation
Python Multithreading
Network Traffic Simulator
🤖 Machine Learning Pipeline

The Machine Learning workflow consists of three major stages.

1. Dataset Generation

The dataset_generator.py module is used to generate synthetic network traffic data for the Machine Learning pipeline.

2. Model Training

The train_models.py module contains the model training and evaluation routines.

The project uses:

Random Forest
Decision Tree
Isolation Forest
3. Real-Time Prediction

The predictor.py module provides the prediction logic used for analyzing network traffic.

🌐 Network Traffic Simulation

The simulator.py module is responsible for simulating network traffic and attack scenarios.

The simulator provides test traffic that can be processed by the backend and analyzed by the Machine Learning models.

This allows the system to demonstrate network monitoring and threat detection without requiring a live production network.
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              Random Forest  Decision Tree  Isolation Forest

🔄 System Workflow
Network Traffic
       │
       ▼
Traffic Simulator
       │
       ▼
Flask Backend
       │
       ▼
Traffic Processing
       │
       ▼
Machine Learning Models
       │
       ▼
Prediction / Anomaly Detection
       │
       ▼
Security Alert
       │
       ▼
React Dashboard

🗄️ Database
NetworkGuard-AI uses SQLite for local data storage.

The database component is implemented in:
backend/database.py
The database is used for storing information related to:

Packet logs
Alert history
Network monitoring data
⚙️ Installation & Setup
Prerequisites

Make sure the following are installed:

Python
Node.js
npm
Git

1. Clone the Repository
git clone https://github.com/hinalmachhi/NetworkGuard-AI.git

Navigate to the project:
cd NetworkGuard-AI

🐍 Backend Setup
Navigate to the backend directory:
cd backend


Create a virtual environment:
python -m venv venv

Windows
venv\Scripts\activate
Linux / macOS
source venv/bin/activate
Install the required Python dependencies:
pip install -r ../requirements.txt
Start the Flask backend:
python app.py
The backend will run on:
http://127.0.0.1:5000

⚛️ Frontend Setup

Open a new terminal.

Navigate to the frontend:
cd frontend
Install Node dependencies:
npm install
Start the development server:

npm run dev

The frontend will be available at:

http://localhost:5173
▶️ Running the Project

The project requires both the backend and frontend services to be running.

Backend
cd backend
python app.py
Frontend
cd frontend
npm run dev

Then open:

http://localhost:5173
🧪 Testing

The system can be tested using the simulated network traffic environment.

Basic testing workflow:

Start the Flask backend.
Start the React frontend.
Open the NetworkGuard-AI dashboard.
Generate or simulate network traffic.
Monitor the traffic through the dashboard.
Observe Machine Learning predictions.
Check detected anomalies and security alerts.
Verify stored monitoring and alert information.
📊 Expected Results

The system provides a dashboard-based environment for:

Network traffic monitoring
Machine Learning-based prediction
Anomaly detection
Security alert monitoring
Model evaluation
Historical data storage
🔮 Future Scope

Future improvements can include:

Real network packet capture
Deep Learning-based threat detection
Cloud-based monitoring
User authentication and authorization
Email or SMS security notifications
Advanced threat intelligence integration
Automated incident response
Distributed network monitoring
SIEM integration
Containerized deployment
👥 Project Contributors
Name
Hinal Machhi
Vedika Manjarekar
Saini Pagdhare
📄 Project Purpose

This project was developed as an academic project to demonstrate the application of Machine Learning, web technologies, database management, and network security concepts in a simulated Network Intrusion Detection System.

⭐ Project Highlights
✔ Real-Time Network Monitoring
✔ Machine Learning-Based Detection
✔ Multi-Model Analysis
✔ Network Traffic Simulation
✔ Security Alert Monitoring
✔ Interactive React Dashboard
✔ Flask REST API
✔ SQLite Data Storage
✔ ML Model Training & Evaluation
