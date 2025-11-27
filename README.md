# 🌐 SENTINEL AI

**AI-Driven DDoS Detection & Mitigation for 5G Networks using Machine Learning + SDN + Real-Time Analytics**

---

## 📌 Project Overview

**Sentinel AI** is an enterprise-grade, AI-powered **5G DDoS Detection & Mitigation System** integrating:

- **Machine Learning (Python + Flask)**
- **Software-Defined Networking (SDN) via Ryu Controller**
- **Mininet network emulation**
- **React real-time monitoring dashboard**
- **Node.js backend orchestration**
- **Locust traffic & DDoS load testing**

The system delivers **real-time attack detection**, **network slice intelligence**, and **autonomous mitigation** using OpenFlow rules.

---

## ⭐ Key Capabilities

### 🔥 AI-Powered Detection
- Ensemble ML models: RandomForest, XGBoost, LightGBM, LSTM, SVM  
- Sub-50ms real-time inference  
- 17+ flow features extracted from Scapy/pyshark  

### 📶 5G Network Slice Support
- eMBB (High Bandwidth)  
- URLLC (Low Latency)  
- mMTC (IoT)  

### 🧠 Self-Healing SDN Architecture
- Automatically blocks malicious IPs  
- Auto-unblocks after recovery  
- Falls back to rule-based detection if ML model fails  

### 🔐 SDN Controller (Ryu)
- Dynamic flow rules  
- DROP/FORWARD decisions  
- IP quarantine system  

### 📊 Real-Time Dashboard
- Live traffic charts  
- Slice classifier  
- Blocked IP list  
- Detection confidence  
- ML logs & alerts  

---

## 🏗 System Architecture

```
┌─────────────────┐      ┌───────────────────┐      ┌─────────────────┐
│   Traffic       │ ---> │  Packet Capture    │ ---> │  Feature         │
│ (Real/Simulated)│      │ (Scapy / Pyshark) │      │ Extraction       │
└─────────────────┘      └───────────────────┘      └─────────────────┘
                              │
                              ▼
┌─────────────────┐      ┌───────────────────┐      ┌─────────────────┐
│ Network Slicing │ <--- │   ML Engine        │ ---> │  Backend API     │
│ eMBB/URLLC/mMTC │      │ RandomForest etc. │      │ Node.js          │
└─────────────────┘      └───────────────────┘      └─────────────────┘
                              │
                              ▼
┌─────────────────┐      ┌───────────────────┐      ┌─────────────────┐
│ Ryu SDN         │ <--- │  Mitigation Logic │ ---> │  React Dashboard │
│ Controller      │      │ Auto-block IPs    │      │ Real-time UI     │
└─────────────────┘      └───────────────────┘      └─────────────────┘
```

---

## 🗂 Repository Structure

```
Ly-Project/
│
├── frontend/            # React Dashboard (Port 5173)
├── backend/             # Node.js API Server (Port 3000)
├── model/               # ML Engine + Flask API (Port 5001)
│
├── ryu-venv/            # Python env for Ryu SDN Controller
├── README.md
└── LICENSE
```

---

## ⚙️ Installation Guide

### 1️⃣ Install WSL & Ubuntu
```bash
wsl --install
wsl --install -d Ubuntu-20.04
```

### 2️⃣ Install Mininet
```bash
sudo apt update
sudo apt upgrade
sudo apt install mininet -y
sudo mn --test pingall
```

### 3️⃣ Install Python, Pip, Ryu
```bash
sudo apt install -y python3-pip
pip3 install --upgrade pip setuptools wheel
pip3 install eventlet==0.33.3
pip3 install ryu
```

### 4️⃣ Create Ryu Virtual Environment
```bash
python3.8 -m venv ryu-venv
source ryu-venv/bin/activate
ryu-manager --version
```

---

## 🖥️ Running the Entire System

### **Terminal 1 — Ryu SDN Controller**
```bash
source ryu-venv/bin/activate
ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
```

### **Terminal 2 — Mininet Topology**
```bash
sudo mn --topo single,3 --mac --switch ovsk \
--controller=remote,ip=127.0.0.1,port=6633
```

### **Terminal 3 — Backend**
```bash
cd backend
npm install
npm start
```

### **Terminal 4 — Frontend**
```bash
cd frontend
npm install
npm run dev
```

### **Terminal 5 — ML Model (Flask)**
```bash
cd model
pip install -r requirements.txt
cd app
python app.py
```

---

## 🚦 Load Testing with Locust

### Install Locust:
```bash
pip install locust
```

### Run Locust:
```bash
locust -f locustfile.py
```

### Access Load Test UI:
```
http://localhost:8089
```

---

## 🧠 Machine Learning Models Included

| Model               | Purpose                     |
| ------------------- | --------------------------- |
| Random Forest       | Primary classifier          |
| XGBoost             | Gradient boosted accuracy   |
| LightGBM            | Fast, memory-efficient      |
| LSTM                | Temporal behavior detection |
| SVM                 | Boundary-based detection    |
| Logistic Regression | Baseline                    |
| KNN                 | Similarity detection        |

---

## 🔐 SDN Flow Control (Ryu)

The backend issues:

- **DROP rules** for blocking malicious IPs
- **ALLOW rules** for clean traffic
- **Flow cleanup** after threat resolves

Protocols used:

- OpenFlow 1.3
- REST API of `ryu.app.ofctl_rest`

---

## 🔄 Self-Healing Pipeline

```
DDoS Detected
     ↓
Block IP (OpenFlow DROP rule)
     ↓
Monitor traffic for recovery
     ↓
Auto-unblock IP
     ↓
System returns to stable state
```

---

## 📊 Dashboard Features

- Live packet monitoring
- Threat alerts
- Real-time ML predictions
- Slice classification
- Blocked IP list
- System health & status

---

## 🛠 Future Enhancements

- Docker & Kubernetes deployment
- Federated learning for edge devices
- 5G NR physical-layer packet support
- GPU-accelerated inference

---

## 📜 License

This project is for academic and research use.
Refer to the LICENSE file for details.

---

## 🎯 Conclusion

**Sentinel AI** provides a complete, autonomous, real-time DDoS defense system for modern 5G networks, utilizing:

- AI
- SDN
- Network slicing
- Real-time analytics
- Self-healing mechanisms

Perfect for research, enterprise labs, and advanced cybersecurity projects.
