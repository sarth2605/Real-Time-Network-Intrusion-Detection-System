"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Suspicious Activity Detection Module (backend/suspicious_activity_detector.py)

PURPOSE:
Applies defensive baseline heuristics to identify suspicious network behavior,
including:
1. Excessive connection attempts from a single source host.
2. Abnormally high packet rates (volumetric floods / DoS-like surges).
3. Excessive bandwidth / payload volume transferred in a short time window.

DETECTION RULES:
- Excessive Connections: > 100 connection attempts from 1 IP within 60 seconds (HIGH)
- Abnormally High Packet Rate: > Configurable packets per second (MEDIUM / HIGH)
- Excessive Traffic Volume: > Configurable byte volume within a short window (HIGH)

DEFENSIVE & ETHICAL ASSURANCE:
This module contains solely passive defensive inspection logic for authorized
networks. It does not generate or inject disruptive traffic.
================================================================================
"""

import time
from datetime import datetime
from collections import defaultdict


class SuspiciousActivityDetector:
    """
    Defensive behavioral detector that evaluates packet frequency, connection
    density, and volumetric metrics against configurable thresholds.
    """

    def __init__(self,
                 connection_threshold=100,
                 connection_window=60,
                 packet_rate_threshold=40,
                 packet_rate_window=2,
                 volume_threshold_bytes=500_000,
                 volume_window=10,
                 alert_cooldown=20,
                 rate_threshold=None,
                 window_seconds=None):
        """
        Initialize the Suspicious Activity Detector with configurable thresholds.
        """
        # Resolve parameter aliases
        resolved_rate_threshold = rate_threshold if rate_threshold is not None else packet_rate_threshold
        resolved_rate_window = window_seconds if window_seconds is not None else packet_rate_window

        # Configurable thresholds and sliding windows
        self.connection_threshold = connection_threshold
        self.connection_window = connection_window

        self.packet_rate_threshold = resolved_rate_threshold
        self.packet_rate_window = resolved_rate_window

        self.volume_threshold_bytes = volume_threshold_bytes
        self.volume_window = volume_window

        self.alert_cooldown = alert_cooldown

        # In-memory sliding window trackers
        # 1. Connection attempts: src_ip -> [ts1, ts2, ...]
        self.connection_history = defaultdict(list)

        # 2. Short-window packet rate: src_ip -> [ts1, ts2, ...]
        self.rate_history = defaultdict(list)

        # 3. Byte volume: src_ip -> [(ts1, bytes1), (ts2, bytes2), ...]
        self.volume_history = defaultdict(list)

        # 4. TCP SYN tracking: src_ip -> [ts1, ts2, ...]
        self.syn_history = defaultdict(list)

        # Alert cooldown tracker: (src_ip, alert_category) -> last_alert_timestamp
        self.last_alert_time = {}

    # --------------------------------------------------------------------------
    # 1. CORE INSPECTION METHOD
    # --------------------------------------------------------------------------

    def inspect(self, src_ip, dst_ip=None, protocol='TCP', packet_size=0, tcp_flags=None):
        """
        Inspect incoming network event metadata against defensive heuristic rules.

        Parameters:
            src_ip (str): Source IP of the transmitting host.
            dst_ip (str, optional): Target IP address.
            protocol (str): Protocol name ('TCP', 'UDP', 'ICMP', etc.).
            packet_size (int): Size of the packet frame in bytes.
            tcp_flags (str, optional): TCP control flags (e.g. 'S' for SYN).

        Returns:
            dict or None: Structured alert dictionary if a threshold is breached,
                          otherwise None.
        """
        if not src_ip:
            return None

        current_time = time.time()
        packet_bytes = int(packet_size or 0)

        # Evict stale records across all sliding windows
        self._cleanup_history(src_ip, current_time)

        # Record this event into history trackers
        self.connection_history[src_ip].append(current_time)
        self.rate_history[src_ip].append(current_time)
        self.volume_history[src_ip].append((current_time, packet_bytes))

        # ----------------------------------------------------------------------
        # RULE 1: EXCESSIVE CONNECTION ATTEMPTS FROM ONE SOURCE IP
        # (> 100 connection events in 60 seconds)
        # ----------------------------------------------------------------------
        connection_count = len(self.connection_history[src_ip])
        if connection_count > self.connection_threshold:
            alert = self._evaluate_and_build_alert(
                src_ip=src_ip,
                dst_ip=dst_ip,
                category='excessive_connections',
                severity='HIGH',
                description=(
                    f"Excessive connection attempts detected from {src_ip}: {connection_count} "
                    f"connections recorded within {self.connection_window} seconds "
                    f"(threshold: {self.connection_threshold})."
                ),
                current_time=current_time
            )
            if alert:
                return alert

        # ----------------------------------------------------------------------
        # RULE 2: ABNORMALLY HIGH PACKET RATE (VOLUMETRIC SURGE)
        # (> configurable packets per second in short window)
        # ----------------------------------------------------------------------
        packets_in_window = len(self.rate_history[src_ip])
        current_rate = packets_in_window / self.packet_rate_window

        if current_rate >= self.packet_rate_threshold:
            severity = 'HIGH' if current_rate >= (self.packet_rate_threshold * 2) else 'MEDIUM'
            alert = self._evaluate_and_build_alert(
                src_ip=src_ip,
                dst_ip=dst_ip,
                category='high_packet_rate',
                severity=severity,
                description=(
                    f"Abnormally high packet rate detected from {src_ip}: {int(current_rate)} "
                    f"packets/sec (exceeds baseline threshold of {self.packet_rate_threshold} pkt/s)."
                ),
                current_time=current_time
            )
            if alert:
                return alert

        # ----------------------------------------------------------------------
        # RULE 3: EXCESSIVE TRAFFIC VOLUME IN A SHORT PERIOD
        # (> configurable byte threshold in volume_window)
        # ----------------------------------------------------------------------
        total_volume_bytes = sum(b for _, b in self.volume_history[src_ip])
        if total_volume_bytes > self.volume_threshold_bytes:
            volume_kb = round(total_volume_bytes / 1024, 1)
            threshold_kb = round(self.volume_threshold_bytes / 1024, 1)
            alert = self._evaluate_and_build_alert(
                src_ip=src_ip,
                dst_ip=dst_ip,
                category='excessive_volume',
                severity='HIGH',
                description=(
                    f"Excessive traffic volume surge detected from {src_ip}: {volume_kb} KB "
                    f"transferred within {self.volume_window} seconds (threshold: {threshold_kb} KB)."
                ),
                current_time=current_time
            )
            if alert:
                return alert

        # ----------------------------------------------------------------------
        # RULE 4: TCP SYN FLOOD ANOMALY (SYN without ACK burst)
        # ----------------------------------------------------------------------
        if protocol == 'TCP' and tcp_flags == 'S':
            self.syn_history[src_ip].append(current_time)
            syn_count = len(self.syn_history[src_ip])
            if syn_count > 25:
                alert = self._evaluate_and_build_alert(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    category='syn_flood',
                    severity='HIGH',
                    description=(
                        f"Potential TCP SYN flood signature detected from {src_ip}: {syn_count} "
                        f"unacknowledged SYN frames within 5 seconds."
                    ),
                    current_time=current_time
                )
                if alert:
                    return alert

        return None

    # --------------------------------------------------------------------------
    # 2. ALERT BUILDER WITH DUPLICATE SUPPRESSION
    # --------------------------------------------------------------------------

    def _evaluate_and_build_alert(self, src_ip, dst_ip, category, severity, description, current_time):
        """
        Verifies cooldown to prevent duplicate alert flooding, then formats
        the structured alert dictionary.
        """
        cooldown_key = (src_ip, category)
        last_alert = self.last_alert_time.get(cooldown_key, 0)

        # Check if cooldown has elapsed
        if (current_time - last_alert) > self.alert_cooldown:
            self.last_alert_time[cooldown_key] = current_time

            return {
                'attack_type': 'Suspicious Activity',
                'source_ip': src_ip,
                'destination_ip': dst_ip or 'Multiple Targets',
                'target_port': None,
                'severity': severity,
                'description': description,
                'metric_type': category,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Active'
            }

        return None

    # --------------------------------------------------------------------------
    # 3. HOUSEKEEPING & MEMORY MANAGEMENT
    # --------------------------------------------------------------------------

    def _cleanup_history(self, src_ip, current_time):
        """
        Removes timestamps and volume records that fall outside their respective
        sliding windows, ensuring in-memory data structures remain lightweight.
        """
        # Clean connection history (60s window)
        self.connection_history[src_ip] = [
            ts for ts in self.connection_history[src_ip]
            if (current_time - ts) <= self.connection_window
        ]

        # Clean short packet rate history (2s window)
        self.rate_history[src_ip] = [
            ts for ts in self.rate_history[src_ip]
            if (current_time - ts) <= self.packet_rate_window
        ]

        # Clean byte volume history (10s window)
        self.volume_history[src_ip] = [
            (ts, b) for ts, b in self.volume_history[src_ip]
            if (current_time - ts) <= self.volume_window
        ]

        # Clean SYN history (5s window)
        if src_ip in self.syn_history:
            self.syn_history[src_ip] = [
                ts for ts in self.syn_history[src_ip]
                if (current_time - ts) <= 5
            ]

    def reset_ip(self, src_ip):
        """Reset historical monitoring metrics and cooldowns for a specific IP."""
        self.connection_history.pop(src_ip, None)
        self.rate_history.pop(src_ip, None)
        self.volume_history.pop(src_ip, None)
        self.syn_history.pop(src_ip, None)

        # Clean cooldowns for this IP
        keys_to_remove = [k for k in self.last_alert_time if k[0] == src_ip]
        for k in keys_to_remove:
            self.last_alert_time.pop(k, None)

    def clear_all(self):
        """Reset all in-memory history across all monitored hosts."""
        self.connection_history.clear()
        self.rate_history.clear()
        self.volume_history.clear()
        self.syn_history.clear()
        self.last_alert_time.clear()

    # --------------------------------------------------------------------------
    # 4. SIMULATION HELPER (EDUCATIONAL DEMONSTRATION)
    # --------------------------------------------------------------------------

    def simulate_suspicious_activity(self, src_ip="192.168.1.250", scenario="rate_flood"):
        """
        Beginner-friendly simulation helper to test detection rules.

        Scenarios:
        - 'rate_flood': Generates a rapid burst exceeding packet_rate_threshold.
        - 'connection_burst': Generates events exceeding connection_threshold.
        - 'volume_surge': Generates heavy packet payloads exceeding volume_threshold.

        Returns:
            list of alerts generated during simulation.
        """
        alerts = []
        print(f"[SuspiciousSimulator] Simulating '{scenario}' from {src_ip}...")

        if scenario == "rate_flood":
            for _ in range(int(self.packet_rate_threshold * self.packet_rate_window) + 5):
                alert = self.inspect(src_ip=src_ip, dst_ip="192.168.1.1", protocol="TCP", packet_size=64)
                if alert:
                    alerts.append(alert)

        elif scenario == "connection_burst":
            for _ in range(self.connection_threshold + 5):
                alert = self.inspect(src_ip=src_ip, dst_ip="192.168.1.1", protocol="TCP", packet_size=128)
                if alert:
                    alerts.append(alert)

        elif scenario == "volume_surge":
            # Send chunks totaling more than volume_threshold_bytes
            chunk_size = 50_000
            chunks_needed = int(self.volume_threshold_bytes / chunk_size) + 2
            for _ in range(chunks_needed):
                alert = self.inspect(src_ip=src_ip, dst_ip="192.168.1.1", protocol="TCP", packet_size=chunk_size)
                if alert:
                    alerts.append(alert)

        print(f"[SuspiciousSimulator] Simulation complete. Alerts generated: {len(alerts)}")
        return alerts
