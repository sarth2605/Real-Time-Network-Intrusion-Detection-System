"""
Unit Tests for NIDS Detection Modules:
- PortScanDetector
- BruteForceDetector
- SuspiciousActivityDetector

Tests heuristic thresholds, sliding window evictions, cooldown deduplication,
and state isolation across source IP addresses.
"""

import time
import pytest
from backend.port_scan_detector import PortScanDetector
from backend.brute_force_detector import BruteForceDetector
from backend.suspicious_activity_detector import SuspiciousActivityDetector


# ==============================================================================
# SECTION 1: PORT SCAN DETECTOR TESTS
# ==============================================================================

class TestPortScanDetector:
    """Test suite verifying port scanning reconnaissance detection logic."""

    def test_sub_threshold_traffic_generates_no_alert(self, fresh_port_scan_detector):
        """Probing fewer than threshold (10) unique ports should not trigger an alert."""
        detector = fresh_port_scan_detector
        src_ip = "192.168.1.50"
        dst_ip = "192.168.1.1"

        alerts = []
        for port in [80, 443, 8080, 22, 21]:
            alert = detector.inspect(src_ip, dst_ip, port)
            if alert:
                alerts.append(alert)

        assert len(alerts) == 0, "Sub-threshold port probes should return None"

    def test_threshold_breach_triggers_high_severity_alert(self, fresh_port_scan_detector):
        """Probing > 10 unique ports within sliding window must trigger an alert."""
        detector = fresh_port_scan_detector
        src_ip = "10.0.0.99"
        dst_ip = "10.0.0.1"

        alert = None
        # Probe 12 unique ports
        for port in range(1000, 1012):
            result = detector.inspect(src_ip, dst_ip, port)
            if result:
                alert = result

        assert alert is not None, "Port scan threshold breach must trigger an alert"
        assert alert['attack_type'] == 'Port Scan'
        assert alert['source_ip'] == src_ip
        assert alert['severity'] == 'HIGH'
        assert 'Port scan detected' in alert['description']
        assert alert['unique_ports_count'] > 10

    def test_alert_cooldown_prevents_duplicate_spam(self, fresh_port_scan_detector):
        """Additional probes during active cooldown must be suppressed."""
        detector = fresh_port_scan_detector
        src_ip = "10.0.0.88"
        dst_ip = "10.0.0.1"

        first_alert = None
        for port in range(2000, 2012):
            res = detector.inspect(src_ip, dst_ip, port)
            if res:
                first_alert = res

        assert first_alert is not None

        # Send more probes from the same IP immediately (within 20s cooldown)
        duplicate_alert = detector.inspect(src_ip, dst_ip, 2013)
        assert duplicate_alert is None, "Cooldown must suppress duplicate alert within 20s"

    def test_ip_isolation_in_tracking(self, fresh_port_scan_detector):
        """Probing ports from IP A must not pollute or trigger alerts for IP B."""
        detector = fresh_port_scan_detector
        ip_a = "192.168.1.10"
        ip_b = "192.168.1.20"

        # IP A probes 7 ports (under threshold)
        for p in range(100, 107):
            detector.inspect(ip_a, "192.168.1.1", p)

        # IP B probes 7 ports (under threshold)
        for p in range(200, 207):
            alert_b = detector.inspect(ip_b, "192.168.1.1", p)
            assert alert_b is None, "IP B probes should remain isolated from IP A"

    def test_invalid_packet_inputs_handled_safely(self, fresh_port_scan_detector):
        """Missing or malformed inputs must return None without raising unhandled exceptions."""
        detector = fresh_port_scan_detector
        assert detector.inspect(None, "192.168.1.1", 80) is None
        assert detector.inspect("192.168.1.1", "192.168.1.2", None) is None


# ==============================================================================
# SECTION 2: BRUTE-FORCE DETECTOR TESTS
# ==============================================================================

class TestBruteForceDetector:
    """Test suite verifying repeated failed authentication detection."""

    def test_sub_threshold_attempts_generate_no_alert(self, fresh_brute_force_detector):
        """≤ 5 failed authentication attempts must not trigger an alert."""
        detector = fresh_brute_force_detector
        src_ip = "172.16.0.45"

        alerts = []
        for i in range(5):
            alert = detector.record_failed_attempt(
                source_ip=src_ip,
                destination_ip="172.16.0.1",
                username="root",
                service="SSH",
                target_port=22
            )
            if alert:
                alerts.append(alert)

        assert len(alerts) == 0, "5 or fewer failed attempts should not trigger alert"

    def test_threshold_breach_triggers_brute_force_alert(self, fresh_brute_force_detector):
        """Exceeding 5 failed attempts within 60s triggers HIGH severity alert."""
        detector = fresh_brute_force_detector
        src_ip = "172.16.0.90"

        alert = None
        for i in range(6):
            res = detector.record_failed_attempt(
                source_ip=src_ip,
                destination_ip="172.16.0.1",
                username="admin",
                service="SSH",
                target_port=22
            )
            if res:
                alert = res

        assert alert is not None, "6th failed attempt must trigger Brute Force alert"
        assert alert['attack_type'] == 'Brute Force'
        assert alert['source_ip'] == src_ip
        assert alert['severity'] == 'HIGH'
        assert alert['attempt_count'] == 6
        assert 'SSH' in alert['description']

    def test_network_packet_inspector_ignores_non_auth_ports(self, fresh_brute_force_detector):
        """Network packet inspector must ignore non-auth ports like DNS (53)."""
        detector = fresh_brute_force_detector
        src_ip = "192.168.1.33"

        for _ in range(10):
            alert = detector.inspect(src_ip=src_ip, dst_ip="8.8.8.8", dst_port=53)
            assert alert is None, "Non-auth ports must be ignored by brute-force inspector"

    def test_brute_force_cooldown_deduplication(self, fresh_brute_force_detector):
        """Subsequent failed attempts within cooldown window must not flood alerts."""
        detector = fresh_brute_force_detector
        src_ip = "10.10.10.50"

        first_alert = None
        for _ in range(6):
            res = detector.record_failed_attempt(src_ip, "10.10.10.1", "root", "SSH", 22)
            if res:
                first_alert = res

        assert first_alert is not None

        # 7th attempt immediately after
        dup = detector.record_failed_attempt(src_ip, "10.10.10.1", "root", "SSH", 22)
        assert dup is None, "Cooldown must suppress duplicate alert"

    def test_reset_ip_clears_history(self, fresh_brute_force_detector):
        """Calling reset_ip must clear failed attempt history for that IP."""
        detector = fresh_brute_force_detector
        src_ip = "10.10.10.77"

        for _ in range(4):
            detector.record_failed_attempt(src_ip, "10.10.10.1", "user", "FTP", 21)

        assert len(detector.failed_attempts[src_ip]) == 4
        detector.reset_ip(src_ip)
        assert len(detector.failed_attempts[src_ip]) == 0


# ==============================================================================
# SECTION 3: SUSPICIOUS ACTIVITY DETECTOR TESTS
# ==============================================================================

class TestSuspiciousActivityDetector:
    """Test suite verifying anomaly detection (connection flood, rate surge, SYN flood)."""

    def test_normal_routine_traffic_generates_no_alert(self, fresh_suspicious_detector):
        """Routine HTTP packets within reasonable volume should return None."""
        detector = fresh_suspicious_detector
        src_ip = "192.168.1.75"

        for _ in range(10):
            alert = detector.inspect(
                src_ip=src_ip,
                dst_ip="192.168.1.1",
                protocol='TCP',
                packet_size=1200,
                tcp_flags='PA'
            )
            assert alert is None, "Routine traffic should not trigger suspicious activity alert"

    def test_connection_flood_threshold_breach(self, fresh_suspicious_detector):
        """More than 100 connection attempts in 60s triggers HIGH severity alert."""
        detector = fresh_suspicious_detector
        src_ip = "192.168.1.199"

        alert = None
        # Send 102 connection attempts
        for _ in range(102):
            res = detector.inspect(
                src_ip=src_ip,
                dst_ip="192.168.1.1",
                protocol='TCP',
                packet_size=64,
                tcp_flags='S'
            )
            if res and 'Excessive connection attempts' in res['description']:
                alert = res

        assert alert is not None, "Connection flood > 100 must trigger alert"
        assert alert['attack_type'] == 'Suspicious Activity'
        assert alert['severity'] == 'HIGH'
        assert alert['source_ip'] == src_ip

    def test_high_packet_rate_surge_detection(self, fresh_suspicious_detector):
        """Surging past 40 packets in a short 1-second burst triggers rate alert."""
        detector = fresh_suspicious_detector
        src_ip = "192.168.1.188"

        alert = None
        # 85 packets over 2s window gives rate = 42.5 pkts/s (> 40 threshold)
        for _ in range(85):
            res = detector.inspect(
                src_ip=src_ip,
                dst_ip="192.168.1.1",
                protocol='UDP',
                packet_size=512
            )
            if res and 'Abnormally high packet rate' in res['description']:
                alert = res

        assert alert is not None, "High packet rate surge (>40 pkts/s) must trigger alert"
        assert alert['attack_type'] == 'Suspicious Activity'
        assert alert['severity'] == 'MEDIUM'

    def test_tcp_syn_flood_signature_detection(self, fresh_suspicious_detector):
        """Surge of TCP SYN packets without ACK responses triggers SYN flood alert."""
        detector = fresh_suspicious_detector
        src_ip = "192.168.1.177"

        alert = None
        # Send 30 SYN packets (> 25 threshold)
        for _ in range(30):
            res = detector.inspect(
                src_ip=src_ip,
                dst_ip="192.168.1.1",
                protocol='TCP',
                packet_size=60,
                tcp_flags='S'
            )
            if res and 'SYN flood' in res['description']:
                alert = res

        assert alert is not None, "TCP SYN flood signature must trigger alert"
        assert alert['attack_type'] == 'Suspicious Activity'
        assert alert['severity'] == 'HIGH'

    def test_tracker_inspection_and_reset_ip(self, fresh_suspicious_detector):
        """Historical trackers record entries correctly and reset_ip clears them."""
        detector = fresh_suspicious_detector
        src_ip = "192.168.1.155"

        for _ in range(15):
            detector.inspect(src_ip=src_ip, dst_ip="192.168.1.1", packet_size=100)

        assert len(detector.connection_history[src_ip]) == 15
        assert len(detector.rate_history[src_ip]) == 15
        assert sum(b for _, b in detector.volume_history[src_ip]) == 1500

        # Verify reset_ip
        detector.reset_ip(src_ip)
        assert src_ip not in detector.connection_history
        assert src_ip not in detector.rate_history
        assert src_ip not in detector.volume_history
