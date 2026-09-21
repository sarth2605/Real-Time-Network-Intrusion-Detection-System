# Real-Time Network Intrusion Detection System

## Project Overview

A **Real-Time Network Intrusion Detection System (NIDS)** monitors network traffic in real time and detects suspicious or potentially malicious activities.

### Main Objectives

- Monitor network traffic
- Detect suspicious activity
- Detect brute-force attempts
- Detect port-scanning activity
- Generate real-time security alerts
- Maintain attack logs and statistics

---

## Project Architecture

```text
Network Traffic
      |
      v
Packet Capture Engine
(Python / Scapy)
      |
      v
Detection Engine
- Brute Force Detection
- Port Scan Detection
- Suspicious Activity Detection
      |
      v
Database / Logs
      |
      v
Web Dashboard & Alerts
```

---

## Technology Stack

### Backend
- Python
- Flask

### Network Monitoring
- Scapy
- PyShark (optional)

### Frontend
- HTML
- CSS
- JavaScript
- Chart.js

### Database
- SQLite

---

# Main Features

## 1. Real-Time Network Traffic Monitoring

The system monitors authorized network traffic and collects:

- Source IP Address
- Destination IP Address
- Protocol
- Port Number
- Packet Size
- Timestamp

Example:

```text
Source IP: 192.168.1.10
Destination IP: 192.168.1.1
Protocol: TCP
Port: 80
Status: Normal
```

---

## 2. Brute-Force Detection

The system can identify repeated failed authentication attempts from the same source.

Example detection rule:

```text
Same IP
+
More than 5 failed attempts
+
Within 60 seconds
=
Brute Force Alert
```

Example alert:

```text
BRUTE FORCE ATTACK DETECTED

Source IP: 192.168.1.50
Failed Attempts: 10
Severity: HIGH
```

---

## 3. Port Scanning Detection

The system identifies when a source attempts connections to many different ports within a short time period.

Example:

```text
192.168.1.50 -> Port 21
192.168.1.50 -> Port 22
192.168.1.50 -> Port 23
192.168.1.50 -> Port 80
192.168.1.50 -> Port 443
```

Example detection rule:

```text
More than 10 different ports
Within 30 seconds
=
Port Scan Alert
```

---

## 4. Suspicious Activity Detection

The system can flag unusual patterns such as:

- Excessive connection attempts
- Abnormally high packet rates
- Repeated activity from one source
- Unexpected protocol behavior

---

## 5. Real-Time Security Dashboard

The dashboard can display:

- Total Packets
- Normal Traffic
- Suspicious Activities
- Brute-Force Alerts
- Port Scan Alerts
- Recent Security Events

Example:

| Metric | Value |
|---|---:|
| Total Packets | 15,240 |
| Normal Traffic | 14,900 |
| Suspicious Activity | 20 |
| Brute Force | 5 |
| Port Scan | 3 |

---

## 6. Alert Severity Levels

- LOW
- MEDIUM
- HIGH
- CRITICAL

Example:

```text
HIGH SEVERITY ALERT

Attack Type: Port Scanning
Source IP: 192.168.1.50
Status: Detected
```

---

## 7. Attack Logs

All detected events can be stored in the database.

| ID | Attack Type | Source IP | Severity | Time |
|---|---|---|---|---|
| 1 | Port Scan | 192.168.1.50 | HIGH | 10:30 |
| 2 | Brute Force | 192.168.1.40 | CRITICAL | 10:35 |

---

# Recommended Folder Structure

```text
network-intrusion-detection-system/
|
├── backend/
│   ├── app.py
│   ├── packet_capture.py
│   ├── detection_engine.py
│   ├── brute_force.py
│   ├── port_scan.py
│   └── database.py
|
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── alerts.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
|
├── database/
│   └── intrusion.db
|
├── logs/
│   └── security_logs.txt
|
├── requirements.txt
└── README.md
```

---

# Antigravity IDE

Yes, this project can be developed using **Antigravity IDE**.

A module-by-module approach is recommended instead of generating everything at once.

---

# Antigravity IDE Master Prompt

```text
Create a complete Real-Time Network Intrusion Detection System
for a final-year Computer Science student project.

Project Requirements:

1. Monitor network traffic in real time.
2. Capture network packets using Python.
3. Display Source IP, Destination IP, Protocol,
   Port Number, Packet Size, and Timestamp.

Detection Modules:

1. Brute Force Detection:
   - Detect repeated failed login attempts from the same IP.
   - Trigger an alert when more than 5 failed attempts occur
     within 60 seconds.

2. Port Scanning Detection:
   - Detect when one IP attempts to connect to multiple
     different ports within a short period.
   - Trigger an alert when more than 10 ports are scanned
     within 30 seconds.

3. Suspicious Activity Detection:
   - Detect unusually high connection attempts from the
     same source IP.

Dashboard Requirements:

- Modern Cybersecurity Dashboard UI.
- Dark theme.
- Real-time statistics.
- Total packets counter.
- Normal traffic counter.
- Suspicious activities counter.
- Brute-force attack counter.
- Port scan counter.
- Recent security alerts.
- Severity levels: LOW, MEDIUM, HIGH, CRITICAL.
- Charts for network traffic.

Technology Stack:

Backend:
- Python
- Flask
- Scapy

Frontend:
- HTML
- CSS
- JavaScript
- Chart.js

Database:
- SQLite

API:
Create REST APIs for:
- Network traffic
- Alerts
- Attack logs
- Dashboard statistics

Create a proper folder structure and write clean,
well-commented code.

Add a README.md file with complete installation
and running instructions.

The project should be educational and designed for
monitoring authorized networks only.
```

---

# Development Phases

## Phase 1 — Basic System

- Dashboard
- Database
- Packet Monitoring
- Basic Logs

## Phase 2 — Detection Modules

- Port Scan Detection
- Brute Force Detection
- Suspicious Activity Detection
- Alert System

## Phase 3 — Advanced Features

- Real-time charts
- IP reputation or blocklist integration
- Email alerts
- PDF security reports
- User authentication

---

# Why This Is a Good Final-Year Project

This project demonstrates:

- Cybersecurity knowledge
- Network security concepts
- Python programming
- SOC monitoring concepts
- Real-time monitoring
- Attack detection
- Database management
- Web development

## Recommended Stack

For a student project, the recommended combination is:

**Python + Flask + Scapy + SQLite + HTML/CSS/JavaScript**

> Use this system only on networks and systems you own or are explicitly authorized to monitor.
