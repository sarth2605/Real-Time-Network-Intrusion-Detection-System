"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Main Flask Backend & WebSocket Server (app.py)

Course / Project: BCS Final Year Capstone Project
Technology Stack: Python, Flask, Flask-SocketIO, Flask-SQLAlchemy, SQLite

EDUCATIONAL NOTICE:
This system is designed exclusively for educational demonstration and for
monitoring authorized networks. It does not implement offensive or attacking
mechanisms; its sole purpose is defensive packet analysis and threat detection.
================================================================================
"""

import os
import threading
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_socketio import SocketIO
from config import Config
from backend.database import (
    db, init_db, User, SecurityAlert, NetworkTraffic,
    save_network_traffic, save_security_alert,
    get_recent_alerts, get_dashboard_statistics
)
from backend.detection_engine import DetectionEngine
from backend.packet_capture import PacketCaptureEngine
from backend.logger import security_logger

# ------------------------------------------------------------------------------
# 1. FLASK APPLICATION INITIALIZATION
# ------------------------------------------------------------------------------
# Create the Flask WSGI application instance.
app = Flask(__name__)

# Load centralized settings (Secret keys, database URI, detection thresholds)
app.config.from_object(Config)

# Ensure essential runtime directories exist (for database and logs)
os.makedirs(Config.DATABASE_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)

# ------------------------------------------------------------------------------
# 2. SQLITE DATABASE CONFIGURATION
# ------------------------------------------------------------------------------
# Config.SQLALCHEMY_DATABASE_URI points to 'sqlite:///database/intrusion.db'.
# init_db(app) binds SQLAlchemy to this app, creates tables (users, packet_logs,
# alerts), and creates a default 'admin' account if one does not exist.
init_db(app)

# ------------------------------------------------------------------------------
# 3. FLASK-SOCKETIO CONFIGURATION (REAL-TIME WEBSOCKETS)
# ------------------------------------------------------------------------------
# Flask-SocketIO enables full-duplex communication between server and client.
# This allows instant pushes of newly captured packets and threat alerts to
# the frontend dashboard without requiring continuous HTTP polling.
socketio = SocketIO(app, cors_allowed_origins="*")

# ------------------------------------------------------------------------------
# 4. INTRUSION DETECTION & PACKET CAPTURE SUBSYSTEMS
# ------------------------------------------------------------------------------
# DetectionEngine evaluates packets against port scan, brute force, and flood rules.
detection_engine = DetectionEngine(app=app, socketio=socketio)

# PacketCaptureEngine sniffs packets using Scapy or generates synthetic traffic
# for classroom and demonstration purposes when raw sockets are unavailable.
capture_engine = PacketCaptureEngine(
    detection_engine=detection_engine,
    interface=Config.NETWORK_INTERFACE
)

# ------------------------------------------------------------------------------
# APPLICATION STARTUP AUDIT LOG (logs/security_logs.txt)
# ------------------------------------------------------------------------------
security_logger.info("================================================================================")
security_logger.info("NIDS Application Startup: Real-Time Network Intrusion Detection System active.")
security_logger.info(f"Database Subsystem bound at: {Config.DATABASE_DIR}")
security_logger.info(f"Security Audit Log initialized at: {Config.LOG_FILE_PATH}")
security_logger.info(
    f"Active Thresholds: PortScan={Config.PORT_SCAN_THRESHOLD} ports/{Config.PORT_SCAN_WINDOW}s, "
    f"BruteForce={Config.BRUTE_FORCE_THRESHOLD} attempts/{Config.BRUTE_FORCE_WINDOW}s, "
    f"SuspiciousRate={Config.SUSPICIOUS_PACKET_RATE_THRESHOLD} pkts/{Config.SUSPICIOUS_PACKET_WINDOW}s"
)
security_logger.info("================================================================================")

# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# 5. USER AUTHENTICATION & ROUTE PROTECTION
# ------------------------------------------------------------------------------

def login_required(f):
    """
    Decorator to guard administrative web routes from unauthenticated access.
    Redirects unauthenticated visitors to /login and preserves the intended destination.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or not session.get('logged_in'):
            flash('Administrator authentication required. Please log in.', 'warning')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Administrator authentication portal.
    Validates analyst credentials against the SQLite 'users' table using
    cryptographic password hashing (Werkzeug).
    """
    # If already authenticated, redirect directly to dashboard
    if session.get('user_id') and session.get('logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        next_url = request.args.get('next') or request.form.get('next')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Session Fixation Defense: clear old session before storing authenticated user details
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['logged_in'] = True

            security_logger.info(f"Administrator login successful: '{username}' authenticated from {request.remote_addr}")
            flash(f"Welcome back, {user.username}! Administrator session authenticated.", 'success')

            # Validate next_url to protect against Open Redirect vulnerabilities
            if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            security_logger.warning(f"Failed administrator login attempt for '{username}' from {request.remote_addr}")
            flash('Authentication failed: Invalid username or password.', 'danger')

    return render_template('login.html', notice=Config.EDUCATIONAL_NOTICE)


@app.route('/logout')
def logout():
    """Terminate administrator session safely and redirect to login screen."""
    username = session.get('username', 'Analyst')
    session.clear()
    security_logger.info(f"Administrator '{username}' logged out.")
    flash('Logged out successfully. Administrator session terminated.', 'info')
    return redirect(url_for('login'))


# ------------------------------------------------------------------------------
# 6. WEB INTERFACE ROUTES
# ------------------------------------------------------------------------------

@app.route('/')
def index():
    """
    Root route:
    Redirects authenticated analysts to dashboard; unauthenticated users to login.
    """
    if session.get('user_id') and session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main SOC Operations Dashboard:
    Guarded by @login_required. Renders real-time statistics (total packets,
    normal traffic, brute force, port scans, suspicious traffic), Chart.js graphs,
    and the live packet stream.
    """
    stats = get_dashboard_statistics()
    capture_status = capture_engine.get_status()
    return render_template(
        'dashboard.html',
        stats=stats,
        capture_status=capture_status,
        notice=Config.EDUCATIONAL_NOTICE
    )


@app.route('/alerts')
@login_required
def alerts():
    """
    Alerts & Forensic Log View:
    Guarded by @login_required. Displays historical security alert records stored
    in SQLite, allowing analysts to filter by severity, search by IP, and export audit logs to CSV.
    """
    recent_alerts = get_recent_alerts(limit=100)
    stats = get_dashboard_statistics()
    return render_template(
        'alerts.html',
        alerts=[a.to_dict() for a in recent_alerts],
        stats=stats,
        notice=Config.EDUCATIONAL_NOTICE
    )


# ------------------------------------------------------------------------------
# 7. REST API ENDPOINTS
# ------------------------------------------------------------------------------

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """
    API Endpoint: GET /api/stats
    Returns current aggregate metrics in JSON format for the NIDS dashboard.

    Included statistics:
      - total_packets (int): Total inspected network frames
      - total_alerts (int): Total security alerts logged
      - brute_force_alerts (int): Detected authentication brute-force attacks
      - port_scan_alerts (int): Detected port scanning reconnaissance probes
      - suspicious_activity_alerts (int): Volumetric and rate flood anomalies
      - normal_traffic (int): Legitimate network frames
      - severity_breakdown (dict): Counts per severity (LOW, MEDIUM, HIGH, CRITICAL)
    """
    try:
        stats = get_dashboard_statistics()
        return jsonify(stats), 200
    except Exception as e:
        security_logger.error(f"Failed to retrieve system statistics: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve system statistics',
            'details': str(e)
        }), 500


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """
    API Endpoint: GET /api/alerts
    Returns JSON list of detected security incident alerts (newest first).

    Optional Query Parameters:
      - limit (int, default=100): Maximum number of alerts to return
      - severity (str): Filter by severity ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
      - type (str): Filter by attack type ('Port Scan', 'Brute Force', 'Suspicious Activity')
    """
    try:
        severity = request.args.get('severity')
        attack_type = request.args.get('type')

        # Safely parse limit parameter
        try:
            limit = int(request.args.get('limit', 100))
            if limit <= 0:
                limit = 100
        except (ValueError, TypeError):
            limit = 100

        alerts_list = get_recent_alerts(limit=limit, severity=severity, attack_type=attack_type)
        return jsonify([a.to_dict() for a in alerts_list]), 200
    except Exception as e:
        security_logger.error(f"Failed to retrieve security alerts: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve security alerts',
            'details': str(e)
        }), 500


@app.route('/api/traffic', methods=['GET'])
def api_traffic():
    """
    API Endpoint: GET /api/traffic
    Returns the most recent captured network packet metadata in JSON format.

    Optional Query Parameters:
      - limit (int, default=50): Number of recent packet records to retrieve
    """
    try:
        # Safely parse limit parameter
        try:
            limit = int(request.args.get('limit', 50))
            if limit <= 0:
                limit = 50
        except (ValueError, TypeError):
            limit = 50

        packets = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).limit(limit).all()
        return jsonify([p.to_dict() for p in reversed(packets)]), 200
    except Exception as e:
        security_logger.error(f"Failed to retrieve network traffic data: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve network traffic data',
            'details': str(e)
        }), 500


@app.route('/api/capture/start', methods=['POST'])
def api_start_capture():
    """
    API Endpoint: /api/capture/start
    Starts packet ingestion.
    JSON body parameter 'mode': 'live' (Scapy) or 'sim' (Synthetic simulator).
    """
    mode = request.json.get('mode', 'live') if request.is_json else 'live'
    security_logger.info(f"Packet capture start requested in mode: '{mode}'")
    if mode == 'live':
        capture_engine.start_live_capture()
    else:
        capture_engine.start_simulation()
    return jsonify({'status': 'success', 'capture_status': capture_engine.get_status()})


@app.route('/api/capture/stop', methods=['POST'])
def api_stop_capture():
    """
    API Endpoint: /api/capture/stop
    Halts the background packet capture thread.
    """
    security_logger.info("Packet capture stop requested.")
    capture_engine.stop_capture()
    return jsonify({'status': 'success', 'capture_status': capture_engine.get_status()})


@app.route('/api/capture/status', methods=['GET'])
def api_capture_status():
    """
    API Endpoint: /api/capture/status
    Returns the running state of the capture engine (is_capturing, simulation_mode).
    """
    return jsonify(capture_engine.get_status())


@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    """
    API Endpoint: POST /api/simulate
    Triggers an on-demand safe simulation scenario for educational demonstration.

    Request JSON payload:
      - scenario (str): 'normal', 'failed_auth', 'port_scan', 'high_volume', or 'all'

    Returns:
      JSON with execution status and scenario details.
    """
    try:
        data = request.get_json(silent=True) or {}
        scenario = data.get('scenario', 'normal')
        security_logger.info(f"Triggering safe simulation scenario: '{scenario}'")

        # Execute simulation in a background thread so the HTTP response is prompt
        # and SocketIO alerts / traffic updates broadcast in real time.
        def run_sim_task():
            capture_engine.run_simulation_scenario(scenario)

        sim_thread = threading.Thread(
            target=run_sim_task,
            name=f"SimScenario-{scenario}",
            daemon=True
        )
        sim_thread.start()

        return jsonify({
            'status': 'success',
            'message': f"Safe simulation scenario '{scenario}' initiated successfully.",
            'scenario': scenario
        }), 200
    except Exception as e:
        security_logger.error(f"Failed to execute simulation scenario '{scenario}': {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to execute simulation scenario',
            'details': str(e)
        }), 500


@app.route('/api/alerts/clear', methods=['POST'])
def api_clear_alerts():
    """
    API Endpoint: /api/alerts/clear
    Utility endpoint to reset packet logs and alerts for fresh project testing.
    """
    security_logger.info("Session reset requested: Clearing all security alerts and traffic logs.")
    SecurityAlert.query.delete()
    NetworkTraffic.query.delete()
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'All alerts and packet logs reset.'})


# ------------------------------------------------------------------------------
# 8. SOCKET.IO REAL-TIME EVENT HANDLERS
# ------------------------------------------------------------------------------

@socketio.on('connect')
def handle_connect():
    """
    Triggered whenever a browser client connects via WebSocket.
    Immediately pushes current dashboard statistics to the connecting client
    so counters and Chart.js charts synchronize without any delay.
    """
    security_logger.info("SOC Analyst client connected to live WebSocket intrusion stream.")
    try:
        current_stats = detection_engine.get_current_stats()
        socketio.emit('stats_update', current_stats)
    except Exception as e:
        security_logger.error(f"Error during WebSocket connection sync: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    """Triggered whenever a browser client disconnects."""
    print("[SocketIO] Web client disconnected.")


@socketio.on('request_stats')
def handle_request_stats():
    """Allow frontend client to request an on-demand metrics synchronization."""
    try:
        current_stats = detection_engine.get_current_stats(force_refresh=True)
        socketio.emit('stats_update', current_stats)
    except Exception as e:
        print(f"[SocketIO] Error servicing request_stats: {e}")


# ------------------------------------------------------------------------------
# 9. APPLICATION ENTRY POINT
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    print("=" * 70)
    print("Real-Time Network Intrusion Detection System (NIDS)")
    print("BCS Final Year Capstone Project")
    print("Starting Web Dashboard on: http://127.0.0.1:5000")
    print("=" * 70)

    # Automatically start the synthetic traffic generator so the project
    # immediately displays live packets, graphs, and attacks without requiring
    # elevated administrative privileges or external packet drivers on launch.
    capture_engine.start_simulation()

    # Run the Flask-SocketIO server
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)
