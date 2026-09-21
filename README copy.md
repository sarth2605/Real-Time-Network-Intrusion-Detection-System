# Real-Time Network Intrusion Detection System (NIDS)
### Final Year Bachelor of Computer Science (BCS) Capstone Project

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/Flask-3.0.x-green.svg)](https://flask.palletsprojects.com/)
[![WebSockets](https://img.shields.io/badge/Flask--SocketIO-5.3%2B-orange.svg)](https://flask-socketio.readthedocs.io/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2F%20SQLAlchemy-lightgrey.svg)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-Pytest%20(31%2F31%20Passed)-brightgreen.svg)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/License-Educational%20Use-blueviolet.svg)](#-security-and-authorization-notice)

---

## 📖 Project Description

The **Real-Time Network Intrusion Detection System (NIDS)** is an intelligent, full-stack cybersecurity operations platform designed to inspect network traffic flows, identify unauthorized behaviors and anomalous patterns in real time, and report high-fidelity security alerts to a modern Security Operations Center (SOC) dashboard.

Built as a BCS Final Year Capstone Project, the system combines raw packet capture (using Scapy), a stateful heuristic detection engine with sliding time windows, persistent SQLite storage, and instant WebSocket broadcasting via Flask-SocketIO. For academic presentations and environments without elevated network interface access, the application includes a **Safe Local Simulation Mode** that naturally exercises all detection algorithms without generating offensive network exploits.

---

## ✨ Key Features

- 🔍 **Real-Time Network Packet Inspection**: Captures live IPv4 traffic (TCP, UDP, ICMP, ARP) using Scapy sniffer threads with automatic fallback to synthetic local simulation.
- ⚡ **Stateful Multi-Threat Detection Engine**:
  - **Port Scan Reconnaissance**: Detects rapid scanning sweeps across destination ports using sliding windows and IP isolation.
  - **Brute-Force Detection**: Monitors authentication service ports (SSH, FTP, HTTP, RDP) for repeated failed attempts.
  - **Suspicious Activity & Anomaly Detection**: Flags connection floods (>100 conns/60s), packet rate surges (>40 pkts/s), and TCP SYN flood signatures.
- 🛡️ **Intelligent Alert Deduplication**: Employs configurable cooldown timers to eliminate repetitive alert spamming during prolonged scan bursts.
- 🌐 **Cybersecurity SOC Dashboard**:
  - High-visibility KPI summary cards (Total Packets, Normal Traffic, Suspicious Activity, Brute Force, Port Scans).
  - Dynamic Chart.js visualizations (Live Traffic Throughput, Protocol Breakdown, Attack Distribution, Severity Split).
  - Live streaming packet feed with auto-scrolling terminal aesthetic.
- 🚨 **Dedicated Alerts Management Portal**:
  - Filter alerts dynamically by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and attack type.
  - Full-text search by Source IP, Destination IP, or description.
  - Forensic CSV report exporter for audit documentation.
- 🔒 **Administrator Authentication & Security**:
  - Password hashing via Werkzeug (`scrypt`/`pbkdf2`).
  - Session-based route protection (`@login_required`) for operational pages.
  - CLI setup script (`setup_admin.py`) for credential provisioning without hardcoded secrets.
- 📝 **Centralized Security Audit Logging**: Standardized Python logging pipeline to `logs/security_logs.txt` with ISO timestamps and log levels (`INFO`, `WARNING`, `ERROR`).
- 🧪 **Automated Testing Suite**: 31 unit and integration tests powered by `pytest` with a comprehensive 28-point Quality Assurance Matrix.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Programming Language** | Python 3.10+ (Tested up to Python 3.13) |
| **Web Framework** | Flask 3.0.x (WSGI Server, Routing, Session Management) |
| **Real-Time WebSockets** | Flask-SocketIO 5.3+, Simple-WebSocket, Eventlet |
| **Network Ingestion** | Scapy 2.5+, Raw Sockets, Synthetic Packet Replay Engine |
| **Database & ORM** | SQLite 3, Flask-SQLAlchemy 3.1.x |
| **Frontend UI** | HTML5 Semantic Architecture, Modern CSS3 (SOC Dark Glassmorphism), Vanilla JavaScript (ES6+) |
| **Data Visualization** | Chart.js 4.x (Live Line, Doughnut, and Bar Charts) |
| **Testing Framework** | Pytest 9.x (Unit, Integration, and WebSocket fixtures) |
| **Security & Utilities** | Werkzeug Security, Python Standard `logging`, `ipaddress` |

---

## 🏗️ Project Architecture

```text
               ┌────────────────────────────────────────────────────────┐
               │             Traffic Ingestion Subsystem                │
               │  [Live Scapy Sniffer]  OR  [Safe Synthetic Simulator]   │
               └───────────────────────────┬────────────────────────────┘
                                           │ (Raw Packet / Frame Metadata)
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │                Detection Engine Pipeline               │
               │                                                        │
               │  ┌──────────────────┐ ┌──────────────────┐ ┌────────┐ │
               │  │ PortScanDetector │ │BruteForceDetector│ │SuspAct.│ │
               │  │ (>10 ports / 30s)│ │(>5 fails / 60s)  │ │(Floods)│ │
               │  └────────┬─────────┘ └────────┬─────────┘ └───┬────┘ │
               │           └────────────────────┼───────────────┘      │
               │                                ▼                      │
               │                     [Cooldown Deduplicator]            │
               └───────────────────────────┬────────────────────────────┘
                                           │ (Verified Alerts & Packets)
                             ┌─────────────┴─────────────┐
                             ▼                           ▼
               ┌───────────────────────────┐ ┌───────────────────────────┐
               │     Data Persistence      │ │   Real-Time WebSocket     │
               │ • SQLite (intrusion.db)   │ │ • Flask-SocketIO Bus      │
               │ • logs/security_logs.txt  │ │ • Event: stats_update     │
               │ • Alerts, Traffic, Users  │ │ • Event: live_packet      │
               │                           │ │ • Event: new_alert        │
               └─────────────┬─────────────┘ └───────────┬───────────────┘
                             │                           │
                             └─────────────┬─────────────┘
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │               Web SOC Interface (Frontend)             │
               │  • Administrator Authentication (/login)               │
               │  • Executive SOC Dashboard (/dashboard)                │
               │  • Live Packet Stream & Interactive Chart.js Graphs    │
               │  • Forensic Alerts Management & CSV Exporter (/alerts) │
               └────────────────────────────────────────────────────────┘
```

---

## 📁 Folder Structure

```text
Real-Time Network Intrusion Detection System/
│
├── app.py                           # Application entrypoint & Flask-SocketIO coordinator
├── config.py                        # Centralized thresholds, database URI, and settings
├── setup_admin.py                   # CLI administrator provisioning script
├── requirements.txt                 # Project dependencies
├── testing_checklist.md             # 28-point QA verification matrix
├── README.md                        # Project documentation
│
├── backend/                         # Core detection & ingestion logic
│   ├── __init__.py                  # Package initializer
│   ├── packet_capture.py            # Scapy sniffer & synthetic background generator
│   ├── detection_engine.py          # Central detector coordinator & SocketIO dispatcher
│   ├── port_scan_detector.py        # Port scanning reconnaissance detector
│   ├── brute_force_detector.py      # Authentication brute-force detector
│   ├── suspicious_activity_detector.py # Volumetric, rate, and SYN flood detector
│   ├── traffic_simulator.py         # Safe demonstration attack generator
│   ├── database.py                  # SQLAlchemy models (User, NetworkTraffic, SecurityAlert)
│   └── logger.py                    # Structured security audit logging setup
│
├── templates/                       # Jinja2 HTML templates
│   ├── login.html                   # Dark SOC-themed administrator login screen
│   ├── dashboard.html               # Main real-time SOC operations dashboard
│   └── alerts.html                  # Forensic alerts search, filter, and CSV export view
│
├── static/                          # Static assets
│   ├── css/
│   │   └── style.css                # Dark SOC theme (cyber accents, cards, glassmorphism)
│   └── js/
│       ├── dashboard.js             # WebSocket subscriber, Chart.js managers, live tables
│       └── alerts.js                # Alerts table filtering, pagination, CSV download
│
├── database/                        # Database storage
│   └── intrusion.db                 # SQLite relational database
│
├── logs/                            # Audit trails
│   └── security_logs.txt            # Timestamped security event log file
│
└── tests/                           # Automated Pytest Suite
    ├── __init__.py                  # Tests package marker
    ├── conftest.py                  # Test fixtures (Flask app, test client, SocketIO, detectors)
    ├── test_detection_modules.py    # Unit tests for the 3 heuristic detection engines
    └── test_system_integration.py   # Integration tests for startup, DB, REST APIs, and WebSockets
```

---

## ⚙️ Installation & Setup

### 1. Prerequisites
- **Python 3.10 or newer** (Tested on Python 3.10, 3.11, 3.12, 3.13).
- **Windows Live Capture Driver (Optional)**: If running live packet sniffing on physical Windows adapters, install **[Npcap](https://npcap.com/)** with *"Install Npcap in WinPcap API-compatible Mode"* enabled.
  > *Note: If Npcap is not present or non-root privileges are used, the system automatically falls back to the built-in synthetic traffic engine, ensuring 100% functionality.*

---

### 2. Virtual Environment Setup

Open a terminal (PowerShell or Bash) in the project directory:

```bash
# Navigate to the project root
cd "Real-Time Network Intrusion Detection System"

# Create a virtual environment named 'venv'
python -m venv venv
```

Activate the virtual environment:

- **Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Windows (Command Prompt)**:
  ```cmd
  venv\Scripts\activate.bat
  ```
- **Linux / macOS**:
  ```bash
  source venv/bin/activate
  ```

---

### 3. Dependency Installation

Install all required Python libraries from `requirements.txt`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

### 4. Administrator Provisioning (Optional)

A default administrator account (`admin` / `admin123`) is automatically provisioned on first launch. You can also customize credentials using the standalone setup script:

```bash
python setup_admin.py --username soc_admin --password "SuperSecretPass123!" --role admin
```

Alternatively, set environment variables prior to startup:
```powershell
$env:NIDS_ADMIN_USER="analyst"
$env:NIDS_ADMIN_PASSWORD="StrongPassword2026!"
```

---

### 5. Running the Project

Launch the Flask and WebSocket application:

```bash
python app.py
```

Console output will confirm the running services:
```text
======================================================================
Real-Time Network Intrusion Detection System (NIDS)
BCS Final Year Capstone Project
Starting Web Dashboard on: http://127.0.0.1:5000
======================================================================
[Traffic Simulator] Background demonstration traffic generator started.
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000 (Press CTRL+C to quit)
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

Login with the default credentials:
- **Username**: `admin`
- **Password**: `admin123`

---

## 🎮 Safe Simulation Mode

The system features an integrated **Safe Simulation Engine** designed for local academic demonstration. It generates synthetic packets in-memory without initiating network attacks or sending packets across external networks.

### Demonstration Scenarios Available:
1. **Normal Network Traffic**: Simulates routine HTTP/HTTPS, DNS queries, and TLS connections across arbitrary web services.
2. **Authentication Brute-Force**: Simulates rapid failed authentication attempts against SSH (port 22) or FTP (port 21) from an external IP.
3. **Port Scan Reconnaissance**: Simulates a sequential probe contacting >10 unique ports (21, 22, 23, 80, 443, 3389, 8080...) in under 5 seconds.
4. **Volumetric / Rate Flooding**: Simulates high-frequency UDP bursts and TCP SYN floods to trigger suspicious activity alerts.

### How to Trigger Simulations:
- **From Dashboard UI**: Click any of the scenario buttons inside the **"Threat Simulation Controls"** card on the SOC dashboard.
- **Via REST API**:
  ```bash
  curl -X POST http://127.0.0.1:5000/api/simulate \
       -H "Content-Type: application/json" \
       -d '{"scenario": "port_scan"}'
  ```

---

## 🔍 Defensive Detection Rules & Heuristics

All detection rules use defensive sliding-window heuristics and can be tuned in [`config.py`](file:///c:/Users/sarth/OneDrive/Documents/Github/Real-Time%20Network%20Intrusion%20Detection%20System/config.py):

| Attack Category | Trigger Criteria | Window | Cooldown | Default Severity | Target Indicators |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Port Scan** | Single IP accesses **>10 unique ports** | 30 sec | 20 sec | **HIGH** | Multi-port reconnaissance probes |
| **Brute Force** | Single IP accumulates **>5 failed attempts** | 60 sec | 25 sec | **HIGH** | Sensitive ports: 21, 22, 23, 80, 443, 3389, 8080 |
| **Connection Surge** | Single IP creates **>100 connection attempts** | 60 sec | 20 sec | **HIGH** | Connection exhaustion / DoS reconnaissance |
| **High Packet Rate** | Traffic rate reaches **>40 packets/sec** | 2 sec | 20 sec | **MEDIUM / HIGH** | Volumetric flooding surges |
| **TCP SYN Flood** | Single IP transmits **>25 SYN packets** without ACKs | 5 sec | 20 sec | **HIGH** | Half-open SYN flood signatures |

---

## 🧪 Automated Testing & Verification

The project includes an automated test suite executed via `pytest`:

```bash
# Run the complete test suite with verbose output
pytest tests/ -v
```

### Test Suite Structure:
- **`tests/test_detection_modules.py`** (15 tests): Unit tests validating sliding windows, threshold boundary triggers, cooldown duplicate suppression, and multi-IP tracking isolation.
- **`tests/test_system_integration.py`** (16 tests): Tests covering app startup, password hashing, database operations, REST endpoints, and WebSocket event broadcasts.

See [testing_checklist.md](file:///c:/Users/sarth/OneDrive/Documents/Github/Real-Time%20Network%20Intrusion%20Detection%20System/testing_checklist.md) for the full 28-point Quality Assurance Matrix.

---

## 📸 Screenshots & User Interface

*(Replace these image placeholders with your project screenshots before project submission)*

### 1. Security Operations Center (SOC) Dashboard
![SOC Operations Dashboard](static/img/screenshots/dashboard_overview.png)
*Figure 1: Main real-time SOC operations dashboard showing live KPI counters, Chart.js metrics, and streaming packet table.*

### 2. Live Threat Distribution & Analytics
![Dynamic Charts](static/img/screenshots/analytics_charts.png)
*Figure 2: Real-time traffic throughput trendline, attack type distribution, and severity breakdown charts.*

### 3. Forensic Alerts Management Page
![Alerts Management](static/img/screenshots/alerts_management.png)
*Figure 3: Dedicated alerts table featuring severity filters, search by IP, and CSV forensic export.*

### 4. SOC Analyst Authentication Gateway
![Login Screen](static/img/screenshots/login_screen.png)
*Figure 4: Secure administrator login portal with hashed credentials and session protection.*

---

## 🚀 Future Enhancements

- 🤖 **Machine Learning Intrusion Detection**: Integrate Random Forest, XGBoost, or Autoencoders trained on datasets such as NSL-KDD / CIC-IDS2017 to flag zero-day protocol anomalies.
- 🛑 **Active Automated Defense**: Add automated IP blocking integrations (Windows Filtering Platform / Linux `iptables` / `nftables`) upon critical alert confirmation.
- 📡 **Distributed Sensor Architecture**: Deploy lightweight remote capture agents (Beats/fluentbit) pushing packets to a centralized NIDS clustering backend via Apache Kafka or RabbitMQ.
- 📁 **Offline PCAP Forensics**: Allow security analysts to upload raw `.pcap` or `.pcapng` capture files for historical attack replay and investigation.
- 🔔 **External Webhook Notifications**: Real-time incident dispatching to Slack, Microsoft Teams, Discord, or enterprise SIEM platforms (Splunk, Elastic SIEM).
- 🔑 **Multi-Factor Authentication (MFA)**: Time-based One-Time Password (TOTP) support for analyst logins.

---

## 🛡️ Security and Authorization Notice

> [!IMPORTANT]
> **Defensive Purpose & Legal Compliance**:
> This software is created exclusively for **academic demonstration, research, and defensive monitoring of authorized systems**.
>
> 1. **No Exploitative Code**: This system contains zero exploit code, payload injectors, port busters, or network attack capabilities. All simulated events are generated using safe, local synthetic payloads.
> 2. **Authorization Required**: Capturing or analyzing network frames without prior explicit written consent from the network owner may violate laws including the *Computer Fraud and Abuse Act (CFAA)*, the *UK Computer Misuse Act*, and local cybersecurity regulations.
> 3. **Permitted Usage**: This software is intended strictly for execution on localhost (`127.0.0.1`), private lab virtual networks, or corporate networks where you are an authorized security administrator.

---

## 👨‍💻 Author & Project Information

- **Project Title**: Real-Time Network Intrusion Detection System (NIDS)
- **Author**: Sarthak (BCS Final Year Student)
- **Program**: Bachelor of Computer Science (BCS)
- **Academic Year**: 2025 – 2026
- **Specialization**: Network Security & Full-Stack Systems
- **Repository**: [Real-Time Network Intrusion Detection System](https://github.com/)

---
*Developed for academic demonstration and defensive cybersecurity monitoring.*
#   R e a l - T i m e - N e t w o r k - I n t r u s i o n - D e t e c t i o n - S y s t e m  
 #   R e a l - T i m e - N e t w o r k - I n t r u s i o n - D e t e c t i o n - S y s t e m  
 