"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Port Scan Detection Module (backend/port_scan_detector.py)

PURPOSE:
Identifies potential reconnaissance and port scanning behavior from observed
authorized network traffic flows.

DETECTION LOGIC:
1. Tracks all destination ports contacted by each unique Source IP address.
2. Maintains a configurable sliding time window (default: 30 seconds).
3. If a single Source IP contacts more than 10 unique destination ports within
   this window, a HIGH severity "Port Scan" alert is generated.
4. Employs an alert cooldown mechanism to prevent duplicate alerts from being
   emitted continuously during an ongoing scan burst.
5. Automatically purges expired connection records to keep memory bounded.

ALERT STRUCTURE:
- Attack Type ("Port Scan")
- Source IP
- Number of unique ports contacted
- Timestamp
- Severity ("HIGH")
- Description with summary of targeted ports
================================================================================
"""

import time
from datetime import datetime
from collections import defaultdict


class PortScanDetector:
    """
    Stateful detector that monitors destination ports contacted by source IPs
    and detects multi-port scanning reconnaissance activity.
    """

    def __init__(self, threshold=10, window_seconds=30, alert_cooldown=20):
        """
        Initialize the Port Scan Detector.

        Parameters:
            threshold (int): Maximum allowable unique destination ports before
                             alerting (default: 10).
            window_seconds (int): Sliding time window in seconds (default: 30).
            alert_cooldown (int): Cooldown duration in seconds to suppress
                                  duplicate alerts for the same scanning IP (default: 20).
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.alert_cooldown = alert_cooldown

        # In-memory history tracking:
        # Structure: source_ip -> list of tuples [(timestamp, destination_port), ...]
        self.port_history = defaultdict(list)

        # Cooldown tracker to prevent duplicate alert spamming:
        # Structure: source_ip -> timestamp of last emitted alert
        self.last_alert_time = {}

    # --------------------------------------------------------------------------
    # 1. CORE INSPECTION METHOD
    # --------------------------------------------------------------------------

    def inspect(self, src_ip, dst_ip=None, dst_port=None):
        """
        Inspect an observed network connection attempt.

        Parameters:
            src_ip (str): Source IP address of the client / sender.
            dst_ip (str, optional): Destination IP address being contacted.
            dst_port (int, optional): Destination port number contacted.

        Returns:
            dict: Structured alert dictionary if port scan criteria is met,
                  otherwise None.
        """
        # Ensure we have both a valid Source IP and a Destination Port
        if not src_ip or dst_port is None:
            return None

        current_time = time.time()

        # Step 1: Evict history entries outside the 30-second sliding window
        self._cleanup_expired_history(src_ip, current_time)

        # Step 2: Record this destination port access
        self.port_history[src_ip].append((current_time, int(dst_port)))

        # Step 3: Extract the set of unique destination ports within the window
        unique_ports = {port for _, port in self.port_history[src_ip]}
        unique_count = len(unique_ports)

        # Step 4: Check if unique ports contacted exceeds our threshold (> 10)
        if unique_count > self.threshold:
            # Step 5: Check cooldown to suppress continuous duplicate alerts
            last_alert = self.last_alert_time.get(src_ip, 0)
            if (current_time - last_alert) > self.alert_cooldown:
                # Update cooldown timestamp
                self.last_alert_time[src_ip] = current_time

                # Format a clean readable summary of targeted ports for analysts
                sorted_sample = sorted(list(unique_ports))[:10]
                ports_preview = ", ".join(map(str, sorted_sample))
                if unique_count > 10:
                    ports_preview += f" (+{unique_count - 10} more)"

                timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Step 6: Return structured alert data
                return {
                    'attack_type': 'Port Scan',
                    'source_ip': src_ip,
                    'destination_ip': dst_ip or 'Multiple Hosts',
                    'target_port': dst_port,
                    'unique_ports_count': unique_count,
                    'severity': 'HIGH',
                    'timestamp': timestamp_str,
                    'description': (
                        f"Port scan detected from {src_ip}: probed {unique_count} unique destination ports "
                        f"within {self.window_seconds} seconds (Ports: {ports_preview})."
                    ),
                    'status': 'Active'
                }

        return None

    # --------------------------------------------------------------------------
    # 2. HOUSEKEEPING & MEMORY MANAGEMENT
    # --------------------------------------------------------------------------

    def _cleanup_expired_history(self, src_ip, current_time):
        """
        Removes recorded connection entries older than the sliding window.
        Prevents unbounded in-memory growth during continuous operation.
        """
        self.port_history[src_ip] = [
            (ts, port) for ts, port in self.port_history[src_ip]
            if (current_time - ts) <= self.window_seconds
        ]

    def reset_ip(self, src_ip):
        """Reset historical connection tracking and alert cooldown for an IP."""
        if src_ip in self.port_history:
            del self.port_history[src_ip]
        if src_ip in self.last_alert_time:
            del self.last_alert_time[src_ip]

    def clear_all(self):
        """Clear all stored state across all IP addresses."""
        self.port_history.clear()
        self.last_alert_time.clear()

    # --------------------------------------------------------------------------
    # 3. SIMULATION & TESTING HELPER
    # --------------------------------------------------------------------------

    def simulate_port_scan(self, src_ip="192.168.1.185", dst_ip="192.168.1.1", port_count=12):
        """
        Beginner-friendly simulation helper.
        Simulates an IP accessing a sequential range of destination ports to test
        and demonstrate the port scan detection heuristic in educational settings.

        Returns:
            list of alerts generated during simulation.
        """
        alerts = []
        print(f"[PortScanSimulator] Simulating scan from {src_ip} across {port_count} ports...")

        for p in range(1, port_count + 1):
            target_port = 20 + p
            result = self.inspect(src_ip=src_ip, dst_ip=dst_ip, dst_port=target_port)
            if result:
                alerts.append(result)
                print(f"[PortScanSimulator] Port {target_port}: ALERT TRIGGERED -> {result['description']}")
            else:
                print(f"[PortScanSimulator] Port {target_port}: Logged ({p}/{self.threshold})")

        return alerts
