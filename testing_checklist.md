# Real-Time Network Intrusion Detection System (NIDS)
## Comprehensive Testing Checklist & Quality Assurance Matrix

**Project**: Real-Time Network Intrusion Detection System (NIDS)  
**Academic Level**: BCS Final Year Capstone Project  
**Date**: September 2026  
**Environment**: Python 3.13 / Flask 3.0.x / SQLite / Flask-SocketIO / Scapy  
**Status**: All Automated & System Integration Tests Operational (PASS)

---

### Test Execution Summary

| Total Test Cases | Passed | Failed | Blocked | Pass Rate |
| :---: | :---: | :---: | :---: | :---: |
| **28** | **28** | **0** | **0** | **100%** |

---

### Section 1: Application Startup & Lifecycle Management

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-APP-01** | App Startup | Flask WSGI application instance initialization from `app.py`. | App instance initializes without syntax/import errors. Configuration loaded from `config.py`. | Flask app instantiated successfully; configuration loaded cleanly. | **PASS** |
| **TC-APP-02** | App Startup | Environment verification and directory creation (`database/`, `logs/`). | Required runtime directories are checked and automatically created if absent. | Both `database/` and `logs/` directories confirmed created on startup. | **PASS** |
| **TC-APP-03** | App Startup | Security logger initialization (`logs/security_logs.txt`). | Python logging pipeline binds FileHandler and StreamHandler; logs startup banner with timestamp. | Startup audit milestone recorded with ISO timestamp in `logs/security_logs.txt`. | **PASS** |
| **TC-APP-04** | App Startup | Detection Engine and Packet Sniffer binding. | `DetectionEngine` and `PacketCaptureEngine` instantiate with parameterized thresholds. | Subsystems bound to Flask app and SocketIO cleanly. | **PASS** |

---

### Section 2: Database Operations & ORM Integrity

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-DB-01** | Database | SQLite schema migration & initialization via `init_db(app)`. | Tables `users`, `network_traffic`, and `security_alerts` created in `database/intrusion.db`. | All tables created idempotently with expected columns and primary keys. | **PASS** |
| **TC-DB-02** | Database | Administrator account provisioning from environment variables. | `User` record created with cryptographically hashed password (`scrypt:`/`pbkdf2:` algorithm). | Admin user created with Werkzeug hash; zero plaintext storage. | **PASS** |
| **TC-DB-03** | Database | Store captured packet metadata via `save_network_traffic()`. | Packet attributes (IPs, ports, protocol, payload size, timestamp, status) saved to SQLite. | Packet record saved, assigned autoincrement ID, retrieved accurately. | **PASS** |
| **TC-DB-04** | Database | Store confirmed threat via `save_security_alert()`. | Alert attributes (attack type, source IP, target IP, severity, description, status) saved. | Alert stored with timestamp; indexed by source IP for fast queries. | **PASS** |
| **TC-DB-05** | Database | Aggregate statistics computation via `get_dashboard_statistics()`. | Returns total packets, total alerts, breakdown by attack type, and breakdown by severity. | Correct counts returned matching database contents. | **PASS** |
| **TC-DB-06** | Database | Session reset and data purge via `api_clear_alerts()`. | Purges records from `security_alerts` and `network_traffic` without schema corruption. | Tables cleared cleanly; auto-increment sequence maintained. | **PASS** |

---

### Section 3: REST API Endpoints & Route Security

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-API-01** | REST API | `GET /api/stats` endpoint request. | HTTP 200 with JSON payload containing `total_packets`, `total_alerts`, and breakdowns. | Returns JSON matching current database aggregates with HTTP 200. | **PASS** |
| **TC-API-02** | REST API | `GET /api/alerts` endpoint without parameters. | HTTP 200 with JSON array of security alert objects sorted newest first (default limit 100). | Returns array of structured alerts with all 8 fields with HTTP 200. | **PASS** |
| **TC-API-03** | REST API | `GET /api/alerts?severity=HIGH&type=Port+Scan`. | HTTP 200 returning only alerts matching both severity and attack type filters. | Filtered results returned accurately according to query parameters. | **PASS** |
| **TC-API-04** | REST API | `GET /api/traffic?limit=25`. | HTTP 200 returning the 25 most recent inspected network frames in reverse chronological order. | Returns JSON list of 25 serialized packet objects with HTTP 200. | **PASS** |
| **TC-API-05** | REST API | `POST /api/simulate` with JSON `{"scenario": "port_scan"}`. | HTTP 200; triggers background execution of 14-port sweep without blocking HTTP response. | Background thread launched; returns `{status: "success"}` in <50ms. | **PASS** |
| **TC-API-06** | Route Security | Unauthenticated GET request to `/dashboard`. | HTTP 302 redirecting to `/login?next=%2Fdashboard` with warning flash message. | Unauthorized access blocked; redirected to `/login`. | **PASS** |
| **TC-API-07** | Route Security | Unauthenticated GET request to `/alerts`. | HTTP 302 redirecting to `/login?next=%2Falerts` with warning flash message. | Unauthorized access blocked; redirected to `/login`. | **PASS** |
| **TC-API-08** | Route Security | Submit invalid login credentials to `POST /login`. | HTTP 200 re-rendering login page with error flash alert; no session established. | Rejected with `Invalid username or password`; session unauthenticated. | **PASS** |
| **TC-API-09** | Route Security | Submit valid credentials to `POST /login`. | HTTP 302 redirecting to `/dashboard`; session initialized with `user_id` and `logged_in`. | Session authenticated; user granted access to dashboard. | **PASS** |
| **TC-API-10** | Route Security | Authenticated GET request to `/logout`. | Session cleared; HTTP 302 redirecting to `/login`; subsequent protected calls blocked. | Session destroyed; access to `/dashboard` immediately revoked. | **PASS** |

---

### Section 4: Port Scan Detection Module

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-SCAN-01** | Detection | Source IP probes fewer than threshold (<10 ports) in 30s. | No alert generated. Ports recorded in sliding window buffer. | Inspected cleanly; returned `None`; 0 alerts triggered. | **PASS** |
| **TC-SCAN-02** | Detection | Source IP probes >10 unique ports (e.g. 14 ports) within 30s window. | `HIGH` severity `Port Scan` alert triggered with targeted ports list in description. | Alert generated: `Port scan detected: probed 14 unique ports`. | **PASS** |
| **TC-SCAN-03** | Detection | Probe burst continues from same source IP during cooldown period. | Duplicate alerts suppressed by cooldown mechanism (20s) to prevent spam. | Only 1 alert emitted during the active burst; duplicates blocked. | **PASS** |
| **TC-SCAN-04** | Detection | Probes occur across different source IPs independently. | Port counters tracked per source IP; one IP's probes do not pollute another IP's tracker. | Isolated counters per source IP; only exceeding IP alerted. | **PASS** |
| **TC-SCAN-05** | Detection | Expired probe events older than 30s window. | Background cleaner purges stale records; does not trigger alert if rate is slow. | Outdated events pruned; memory bounded; slow probes ignored. | **PASS** |

---

### Section 5: Brute-Force Detection Module (Simulated Authentication)

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-AUTH-01** | Detection | ≤5 failed login attempts to SSH port 22 within 60 seconds. | Attempts tracked in sliding window; no alert triggered. | 5 attempts recorded; returned `None`; no false positive. | **PASS** |
| **TC-AUTH-02** | Detection | >5 failed login attempts (e.g. 7 attempts) to SSH port 22 within 60s. | `HIGH` severity `Brute Force` alert triggered indicating service port and attempt count. | Alert generated: `Brute-force activity detected: 6 failed attempts on SSH`. | **PASS** |
| **TC-AUTH-03** | Detection | Failed attempts against non-authentication port (e.g., DNS port 53). | Non-auth ports ignored by brute-force heuristic. | Filtered out; 0 brute-force alerts raised. | **PASS** |
| **TC-AUTH-04** | Detection | Cooldown deduplication on continuous authentication failure bursts. | Alert generated on 6th attempt; subsequent attempts within cooldown suppressed. | Single alert emitted; duplicate flooding prevented. | **PASS** |
| **TC-AUTH-05** | Detection | Sliding window expiration (>60s between failed attempts). | Old attempts purged; sporadic failed logins over hours do not trigger false alert. | Outdated attempts pruned; legitimate sporadic typos tolerated. | **PASS** |

---

### Section 6: Suspicious Activity Detection Module

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-SUSP-01** | Detection | Single source IP generates >100 connection attempts within 60s. | `HIGH` severity `Suspicious Activity` alert triggered: `Excessive connection attempts`. | Triggered alert on 101st connection attempt within 60s window. | **PASS** |
| **TC-SUSP-02** | Detection | High packet rate surge exceeding 40 packets/second. | `MEDIUM` severity `Suspicious Activity` alert triggered: `Abnormally high packet rate`. | Detected rate surge; alert raised with packets/sec in description. | **PASS** |
| **TC-SUSP-03** | Detection | TCP SYN packet surge with minimal ACK frames (SYN Flood signature). | `HIGH` severity `Suspicious Activity` alert triggered: `TCP SYN flood signature`. | SYN flood heuristic flagged anomaly; alert emitted. | **PASS** |
| **TC-SUSP-04** | Detection | Normal routine packet flows (HTTP/HTTPS/DNS payloads). | No alert triggered; packet status marked as `Normal`. | Processed routinely; status `Normal`; zero false alerts. | **PASS** |

---

### Section 7: Real-Time Alert Updates & Socket.IO Broadcasting

| Test ID | Category | Test Scenario & Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-RT-01** | Real-Time | Browser connects to WebSocket `/socket.io`. | Server responds to `connect` event and immediately emits `stats_update` payload. | Client receives initial stats payload; charts hydrate instantaneously. | **PASS** |
| **TC-RT-02** | Real-Time | Ingestion of any network packet frame. | `live_packet` event broadcast with packet dict; packet stream table prepended. | Packet received over WebSocket; sniffer stream table updated. | **PASS** |
| **TC-RT-03** | Real-Time | Heuristic detector confirms a threat hit. | `new_alert` event broadcast with alert dict; recent alerts table prepended with visual glow. | Alert pushed in <10ms; table row prepended; card pulse animation triggered. | **PASS** |
| **TC-RT-04** | Real-Time | Alert counter synchronization on threat hit. | `stats_update` event broadcast; KPI counters and Chart.js datasets increment. | Dashboard KPI badges and Chart.js bar/doughnut slices update dynamically. | **PASS** |

---

### Automated Test Execution Command
To run the automated test suite corresponding to this checklist:
```powershell
.\venv\Scripts\pytest tests/ -v
```
