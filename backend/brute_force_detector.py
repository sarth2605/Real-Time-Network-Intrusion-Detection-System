"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Brute Force Detection Module (backend/brute_force_detector.py)

PURPOSE:
Detects potential credential brute-force attacks by tracking repeated failed
authentication attempts or connection spikes targeting authentication services
originating from the same source IP address.

DETECTION RULE:
- Tracks failed login attempts / rapid auth attempts per Source IP.
- Triggers a HIGH severity alert if > 5 failed attempts occur within a
  configurable sliding time window (default: 60 seconds).
- Temporarily stores timestamps in memory and automatically evicts entries
  outside the sliding window.
- Employs a cooldown mechanism to prevent duplicate alert spamming.

DEFENSIVE / ETHICAL ASSURANCE:
This module contains NO password guessing, cracking, dictionary attacks,
or exploitation mechanisms. It only analyzes defensive telemetry and provides
a simulation helper for academic demonstration.
================================================================================
"""

import time
from datetime import datetime
from collections import defaultdict


class BruteForceDetector:
    """
    Stateful detector that monitors authentication events and flags repeated
    failed login attempts exceeding the threshold within a sliding time window.
    """

    def __init__(self, threshold=5, window_seconds=60, alert_cooldown=25, target_ports=None):
        """
        Initialize the Brute Force Detector.

        Parameters:
            threshold (int): Maximum allowable failed attempts before alerting (default: 5).
            window_seconds (int): Sliding time window in seconds (default: 60).
            alert_cooldown (int): Cooldown period in seconds to prevent duplicate alerts (default: 25).
            target_ports (list, optional): Sensitive authentication service ports to inspect.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.alert_cooldown = alert_cooldown

        # Default standard authentication ports: SSH (22), FTP (21), Telnet (23), HTTP/S (80/443), RDP (3389)
        self.target_ports = set(target_ports or [21, 22, 23, 80, 443, 3389, 8080])

        # Temporary in-memory state:
        # Mapping: source_ip -> list of epoch timestamps [t1, t2, t3, ...]
        self.failed_attempts = defaultdict(list)

        # Mapping: (source_ip, port) -> list of epoch timestamps
        self.port_attempts = defaultdict(list)

        # Alert cooldown tracker: source_ip -> last_alert_epoch_time
        self.last_alert_time = {}

    # --------------------------------------------------------------------------
    # 1. CORE DETECTION: RECORD FAILED AUTHENTICATION ATTEMPT
    # --------------------------------------------------------------------------

    def record_failed_attempt(self, source_ip, destination_ip=None, target_port=None,
                              username=None, service='auth'):
        """
        Record a failed authentication event from an authorized login audit log
        or simulated authentication source.

        Parameters:
            source_ip (str): IP address of the client attempting authentication.
            destination_ip (str, optional): Target server IP address.
            target_port (int, optional): Destination port.
            username (str, optional): Target username (anonymized/logged for context).
            service (str, optional): Authentication service name (e.g. 'SSH', 'Web-Portal').

        Returns:
            dict: Structured alert dictionary if the threshold is exceeded and
                  cooldown has elapsed; otherwise None.
        """
        if not source_ip:
            return None

        now = time.time()

        # Step 1: Evict attempts outside the sliding window for this IP
        self._cleanup_old_attempts(source_ip, now)

        # Step 2: Record current attempt timestamp
        self.failed_attempts[source_ip].append(now)

        attempt_count = len(self.failed_attempts[source_ip])

        # Step 3: Check detection rule (> threshold attempts within window_seconds)
        if attempt_count > self.threshold:
            # Step 4: Check alert cooldown to prevent duplicate alert spamming
            last_alert = self.last_alert_time.get(source_ip, 0)
            if now - last_alert > self.alert_cooldown:
                self.last_alert_time[source_ip] = now

                # Formulate structured alert
                user_context = f" targeting user '{username}'" if username else ""
                target_desc = f"{destination_ip}:{target_port}" if target_port else (destination_ip or "Local Host")

                return {
                    'attack_type': 'Brute Force',
                    'source_ip': source_ip,
                    'destination_ip': destination_ip or '0.0.0.0',
                    'target_port': target_port,
                    'severity': 'HIGH',
                    'description': (
                        f"Brute-force activity detected from {source_ip}: {attempt_count} failed login "
                        f"attempts on {service}{user_context} within {self.window_seconds}s "
                        f"(Target: {target_desc})."
                    ),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'attempt_count': attempt_count,
                    'status': 'Active'
                }

        return None

    # --------------------------------------------------------------------------
    # 2. NETWORK PACKET INSPECTOR (FOR SNIFFER PIPELINE)
    # --------------------------------------------------------------------------

    def inspect(self, src_ip, dst_ip, dst_port, tcp_flags=None):
        """
        Inspect live packet metadata targeting authentication-sensitive ports.
        Maintains compatibility with the DetectionEngine packet stream.

        Parameters:
            src_ip (str): Source IP of packet sender.
            dst_ip (str): Destination IP of server.
            dst_port (int): Target port.
            tcp_flags (str, optional): TCP flags (e.g. 'S' for SYN, 'PA' for PUSH-ACK).

        Returns:
            dict or None: Structured alert dictionary if brute-force criteria met.
        """
        if not dst_port or dst_port not in self.target_ports or not src_ip:
            return None

        # Delegate to record_failed_attempt using port-specific mapping
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP Auth",
            443: "HTTPS Auth",
            3389: "RDP",
            8080: "HTTP-Alt"
        }
        service_name = service_map.get(dst_port, f"Port {dst_port}")

        return self.record_failed_attempt(
            source_ip=src_ip,
            destination_ip=dst_ip,
            target_port=dst_port,
            service=service_name
        )

    # --------------------------------------------------------------------------
    # 3. INTERNAL CLEANUP & HOUSEKEEPING
    # --------------------------------------------------------------------------

    def _cleanup_old_attempts(self, source_ip, current_time):
        """
        Automatically purges timestamps older than the sliding time window.
        Keeps memory footprint bounded and lightweight.
        """
        self.failed_attempts[source_ip] = [
            ts for ts in self.failed_attempts[source_ip]
            if (current_time - ts) <= self.window_seconds
        ]

    def reset_ip(self, source_ip):
        """Reset history and alert cooldown for a specific IP."""
        if source_ip in self.failed_attempts:
            del self.failed_attempts[source_ip]
        if source_ip in self.last_alert_time:
            del self.last_alert_time[source_ip]

    def clear_all(self):
        """Clear all stored attempts and history."""
        self.failed_attempts.clear()
        self.port_attempts.clear()
        self.last_alert_time.clear()

    # --------------------------------------------------------------------------
    # 4. SIMULATION HELPER (EDUCATIONAL DEMONSTRATION)
    # --------------------------------------------------------------------------

    def simulate_failed_login_events(self, source_ip="192.168.1.99",
                                     destination_ip="192.168.1.1",
                                     target_port=22,
                                     service="SSH",
                                     count=6):
        """
        Simulation helper for classroom presentation and testing.
        Simulates a series of failed login events from a single IP to
        demonstrate the detection rule and verify alert generation.

        Returns:
            list of alerts generated during simulation.
        """
        alerts_generated = []
        print(f"[BruteForceSimulator] Simulating {count} failed login events from {source_ip} to {service}...")

        for attempt in range(1, count + 1):
            alert = self.record_failed_attempt(
                source_ip=source_ip,
                destination_ip=destination_ip,
                target_port=target_port,
                service=service,
                username=f"test_user_{attempt}"
            )
            if alert:
                alerts_generated.append(alert)
                print(f"[BruteForceSimulator] Attempt #{attempt}: ALERT TRIGGERED -> {alert['description']}")
            else:
                print(f"[BruteForceSimulator] Attempt #{attempt}: Logged ({attempt}/{self.threshold})")

        return alerts_generated
