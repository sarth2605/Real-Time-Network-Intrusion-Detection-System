"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Central Detection Engine (backend/detection_engine.py)

PURPOSE:
Acts as the central coordination hub of the NIDS pipeline.
1. Receives normalized network packets and telemetry events.
2. Dispatches events to specialized, modular rule detectors:
   - Port Scan Detector
   - Suspicious Activity Detector
   - Brute Force Detector
3. Formulates standardized, structured alert objects upon confirmed threat hits.
4. Persists verified security alerts into the SQLite database.
5. Emits real-time WebSocket events to the frontend dashboard via Flask-SocketIO.

DESIGN:
Modular and configurable. All detection thresholds (sliding time windows,
rate limits, port thresholds) are parameterized rather than hardcoded.
================================================================================
"""

import os
from datetime import datetime
from config import Config
from backend.port_scan_detector import PortScanDetector
from backend.suspicious_activity_detector import SuspiciousActivityDetector
from backend.brute_force_detector import BruteForceDetector
from backend.database import (
    save_network_traffic,
    save_security_alert,
    get_dashboard_statistics
)
from backend.logger import get_logger

logger = get_logger("DetectionEngine")


class DetectionEngine:
    """
    Coordinates packet inspection across specialized heuristic detectors,
    manages alert formatting, persistence, and live dashboard communication.
    """

    def __init__(self, app=None, socketio=None,
                 port_scan_threshold=None,
                 port_scan_window=None,
                 suspicious_rate_threshold=None,
                 suspicious_window=None,
                 brute_force_threshold=None,
                 brute_force_window=None):
        """
        Initialize the Detection Engine with configurable thresholds.

        Parameters:
            app (Flask, optional): Flask application instance for context binding.
            socketio (SocketIO, optional): Flask-SocketIO instance for WebSocket broadcasting.
            port_scan_threshold (int, optional): Unique ports threshold for port scan.
            port_scan_window (int, optional): Time window in seconds for port scan.
            suspicious_rate_threshold (int, optional): Packets/sec limit before flagging suspicious flood.
            suspicious_window (int, optional): Observation window in seconds for rate anomalies.
            brute_force_threshold (int, optional): Failed attempt limit for brute force.
            brute_force_window (int, optional): Time window in seconds for brute force.
        """
        self.app = app
        self.socketio = socketio

        # ----------------------------------------------------------------------
        # Configurable Threshold Settings (Defaults pulled from Config)
        # ----------------------------------------------------------------------
        self.port_scan_threshold = port_scan_threshold or getattr(Config, 'PORT_SCAN_THRESHOLD', 10)
        self.port_scan_window = port_scan_window or getattr(Config, 'PORT_SCAN_WINDOW', 30)

        self.suspicious_rate_threshold = suspicious_rate_threshold or getattr(Config, 'SUSPICIOUS_PACKET_RATE_THRESHOLD', 40)
        self.suspicious_window = suspicious_window or getattr(Config, 'SUSPICIOUS_PACKET_WINDOW', 2)

        self.brute_force_threshold = brute_force_threshold or getattr(Config, 'BRUTE_FORCE_THRESHOLD', 5)
        self.brute_force_window = brute_force_window or getattr(Config, 'BRUTE_FORCE_WINDOW', 60)
        self.brute_force_ports = getattr(Config, 'BRUTE_FORCE_PORTS', [21, 22, 23, 80, 443, 3389, 8080])

        # ----------------------------------------------------------------------
        # Instantiate Modular Detectors
        # ----------------------------------------------------------------------
        # 1. Port Scan Detector: Identifies single source probing multiple distinct ports
        self.port_scan_detector = PortScanDetector(
            threshold=self.port_scan_threshold,
            window_seconds=self.port_scan_window
        )

        # 2. Suspicious Activity Detector: Identifies abnormal packet surges, SYN floods, jumbo frames
        self.suspicious_detector = SuspiciousActivityDetector(
            rate_threshold=self.suspicious_rate_threshold,
            window_seconds=self.suspicious_window
        )

        # 3. Brute Force Detector: Identifies rapid authentication bursts on auth services
        self.brute_force_detector = BruteForceDetector(
            threshold=self.brute_force_threshold,
            window_seconds=self.brute_force_window,
            target_ports=self.brute_force_ports
        )

        # ----------------------------------------------------------------------
        # In-Memory Statistics Cache (for low-latency Socket.IO broadcast)
        # ----------------------------------------------------------------------
        self._stats_cache = None
        self._stats_initialized = False

    def _init_stats_cache(self):
        """Seed the in-memory statistics cache from the SQLite database."""
        if not self._stats_initialized and self.app:
            try:
                with self.app.app_context():
                    self._stats_cache = get_dashboard_statistics()
                    self._stats_initialized = True
            except Exception as e:
                print(f"[DetectionEngine] Note: Initializing empty stats cache ({e})")
                self._stats_cache = {
                    'total_packets': 0,
                    'normal_traffic': 0,
                    'suspicious_count': 0,
                    'brute_force_count': 0,
                    'port_scan_count': 0,
                    'port_scan_alerts': 0,
                    'brute_force_count': 0,
                    'brute_force_alerts': 0,
                    'suspicious_count': 0,
                    'suspicious_activity_alerts': 0,
                    'total_alerts': 0,
                    'attack_breakdown': {
                        'Port Scan': 0,
                        'Brute Force': 0,
                        'Suspicious Activity': 0
                    },
                    'severity_breakdown': {
                        'LOW': 0,
                        'MEDIUM': 0,
                        'HIGH': 0,
                        'CRITICAL': 0
                    }
                }
                self._stats_initialized = True

    def get_current_stats(self, force_refresh=False):
        """
        Retrieve the latest aggregate dashboard statistics.
        Uses in-memory fast metrics with optional SQLite synchronization.
        """
        if force_refresh or not self._stats_initialized:
            if self.app:
                try:
                    with self.app.app_context():
                        self._stats_cache = get_dashboard_statistics()
                        self._stats_initialized = True
                except Exception:
                    pass

        if not self._stats_cache:
            self._init_stats_cache()

        return dict(self._stats_cache) if self._stats_cache else {}

    def init_app(self, app, socketio):
        """Bind Flask app and SocketIO dynamically if initialized separately."""
        self.app = app
        self.socketio = socketio
        self._init_stats_cache()

    # --------------------------------------------------------------------------
    # CORE PACKET & EVENT PROCESSING
    # --------------------------------------------------------------------------

    def process_packet(self, packet_info):
        """Convenience alias for process_event."""
        return self.process_event(packet_info)

    def process_event(self, event_data):
        """
        Process incoming normalized network event through all detection modules.

        Expected event_data keys:
        - source_ip / src_ip (str)
        - destination_ip / dst_ip (str)
        - protocol (str): 'TCP', 'UDP', 'ICMP', etc.
        - source_port / src_port (int, optional)
        - destination_port / dst_port (int, optional)
        - packet_size (int)
        - tcp_flags (str, optional)
        - timestamp (str, optional)
        """
        # Resolve normalized parameters safely
        src_ip = event_data.get('source_ip') or event_data.get('src_ip')
        dst_ip = event_data.get('destination_ip') or event_data.get('dst_ip')
        protocol = event_data.get('protocol', 'UNKNOWN')
        src_port = event_data.get('source_port') if event_data.get('source_port') is not None else event_data.get('src_port')
        dst_port = event_data.get('destination_port') if event_data.get('destination_port') is not None else event_data.get('dst_port')
        packet_size = event_data.get('packet_size', 0)
        tcp_flags = event_data.get('tcp_flags')
        timestamp = event_data.get('timestamp') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        raw_alert = None
        status = 'Normal'

        try:
            # 0. Log packet processing
            port_info = f":{dst_port}" if dst_port else ""
            logger.info(f"Packet processed: {src_ip} -> {dst_ip}{port_info} [{protocol}] ({packet_size} bytes)")

            # ----------------------------------------------------------------------
            # MODULE 1: PORT SCAN DETECTOR
            # ----------------------------------------------------------------------
            if dst_port:
                raw_alert = self.port_scan_detector.inspect(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
                if raw_alert:
                    logger.warning(
                        f"Port scan detection: Source IP {src_ip} probed destination {dst_ip} | "
                        f"{raw_alert.get('description')} | Severity: {raw_alert.get('severity', 'HIGH')}"
                    )

            # ----------------------------------------------------------------------
            # MODULE 2: SUSPICIOUS ACTIVITY DETECTOR
            # ----------------------------------------------------------------------
            if not raw_alert:
                raw_alert = self.suspicious_detector.inspect(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    packet_size=packet_size,
                    tcp_flags=tcp_flags
                )
                if raw_alert:
                    logger.warning(
                        f"Suspicious activity detection: Source IP {src_ip} | "
                        f"{raw_alert.get('description')} | Severity: {raw_alert.get('severity', 'HIGH')}"
                    )

            # ----------------------------------------------------------------------
            # MODULE 3: BRUTE FORCE DETECTOR
            # ----------------------------------------------------------------------
            if not raw_alert and dst_port:
                raw_alert = self.brute_force_detector.inspect(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    tcp_flags=tcp_flags
                )
                if raw_alert:
                    logger.warning(
                        f"Brute force detection: Source IP {src_ip} targeted {dst_ip}:{dst_port} | "
                        f"{raw_alert.get('description')} | Severity: {raw_alert.get('severity', 'HIGH')}"
                    )

        except Exception as e:
            logger.error(f"Error inspecting packet {src_ip} -> {dst_ip}: {e}", exc_info=True)
            return None

        # ----------------------------------------------------------------------
        # STRUCTURED ALERT FORMULATION
        # ----------------------------------------------------------------------
        structured_alert = None
        if raw_alert:
            status = raw_alert.get('attack_type', 'Suspicious Activity')
            structured_alert = self._build_structured_alert(raw_alert, timestamp)

        # ----------------------------------------------------------------------
        # DATABASE PERSISTENCE & WEBSOCKET DISPATCH
        # ----------------------------------------------------------------------
        try:
            self._persist_and_dispatch(
                event_data=event_data,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                packet_size=packet_size,
                status=status,
                structured_alert=structured_alert
            )
        except Exception as e:
            logger.error(f"Error persisting or dispatching alert: {e}", exc_info=True)

        return structured_alert

    def _build_structured_alert(self, raw_alert, timestamp):
        """
        Formulate a standardized, structured dictionary for confirmed threats.
        """
        return {
            'attack_type': raw_alert.get('attack_type', 'Security Incident'),
            'source_ip': raw_alert.get('source_ip', '0.0.0.0'),
            'destination_ip': raw_alert.get('destination_ip', '0.0.0.0'),
            'target_port': raw_alert.get('target_port'),
            'severity': raw_alert.get('severity', 'HIGH').upper(),
            'description': raw_alert.get('description', 'Suspicious pattern identified.'),
            'timestamp': timestamp,
            'status': 'Active'
        }

    def _persist_and_dispatch(self, event_data, src_ip, dst_ip, protocol,
                              src_port, dst_port, packet_size, status,
                              structured_alert):
        """
        Saves records into SQLite and broadcasts updates over SocketIO.
        """
        if not self.app:
            return

        with self.app.app_context():
            # 1. Persist traffic metadata into database
            traffic_record = save_network_traffic(
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=protocol,
                source_port=src_port,
                destination_port=dst_port,
                packet_size=packet_size,
                status=status
            )

            # 2. Persist confirmed alert if one was triggered
            saved_alert_dict = None
            if structured_alert:
                alert_record = save_security_alert(
                    attack_type=structured_alert['attack_type'],
                    source_ip=structured_alert['source_ip'],
                    destination_ip=structured_alert['destination_ip'],
                    target_port=structured_alert['target_port'],
                    severity=structured_alert['severity'],
                    description=structured_alert['description'],
                    status=structured_alert['status']
                )
                self._write_file_audit_log(structured_alert)

                if alert_record:
                    saved_alert_dict = alert_record.to_dict()
                else:
                    saved_alert_dict = structured_alert

            # 3. Update in-memory real-time metrics cache
            if not self._stats_initialized:
                self._init_stats_cache()

            if self._stats_cache is not None:
                self._stats_cache['total_packets'] += 1
                if status == 'Normal':
                    self._stats_cache['normal_traffic'] += 1

                if structured_alert:
                    self._stats_cache['total_alerts'] += 1
                    attack_name = structured_alert.get('attack_type', 'Suspicious Activity')
                    if attack_name == 'Port Scan':
                        self._stats_cache['port_scan_count'] += 1
                        self._stats_cache['port_scan_alerts'] = self._stats_cache['port_scan_count']
                        self._stats_cache['attack_breakdown']['Port Scan'] = self._stats_cache['attack_breakdown'].get('Port Scan', 0) + 1
                    elif attack_name == 'Brute Force':
                        self._stats_cache['brute_force_count'] += 1
                        self._stats_cache['brute_force_alerts'] = self._stats_cache['brute_force_count']
                        self._stats_cache['attack_breakdown']['Brute Force'] = self._stats_cache['attack_breakdown'].get('Brute Force', 0) + 1
                    else:
                        self._stats_cache['suspicious_count'] += 1
                        self._stats_cache['suspicious_activity_alerts'] = self._stats_cache['suspicious_count']
                        self._stats_cache['attack_breakdown']['Suspicious Activity'] = self._stats_cache['attack_breakdown'].get('Suspicious Activity', 0) + 1

                    sev_name = structured_alert.get('severity', 'HIGH').upper()
                    if sev_name in self._stats_cache['severity_breakdown']:
                        self._stats_cache['severity_breakdown'][sev_name] += 1

            # 4. Real-Time Broadcast via Flask-SocketIO
            if self.socketio:
                # Live packet payload for sniffer table & packet rate counters
                packet_payload = traffic_record.to_dict() if traffic_record else dict(event_data)
                packet_payload['status'] = status
                self.socketio.emit('live_packet', packet_payload)

                # Real-time alert push
                if saved_alert_dict:
                    self.socketio.emit('new_alert', saved_alert_dict)

                # Push updated dashboard counters to all connected SOC clients
                current_stats = self.get_current_stats()
                self.socketio.emit('stats_update', current_stats)

    def _write_file_audit_log(self, alert_info):
        """
        Record verified alert forensic entry via Python logging pipeline.
        """
        try:
            target_str = f"{alert_info.get('destination_ip', 'N/A')}:{alert_info.get('target_port') or 'N/A'}"
            logger.warning(
                f"[Threat Audit] Attack: {alert_info.get('attack_type')} | "
                f"Source: {alert_info.get('source_ip')} -> Target: {target_str} | "
                f"Severity: {alert_info.get('severity')} | {alert_info.get('description')}"
            )
        except Exception as e:
            logger.error(f"Could not record security audit log: {e}")
