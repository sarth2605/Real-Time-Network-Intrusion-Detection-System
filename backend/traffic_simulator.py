"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Safe Synthetic Traffic Simulator (backend/traffic_simulator.py)

PURPOSE:
Generates synthetic, in-memory network telemetry events for educational
demonstration and testing of defensive intrusion detection capabilities.

SIMULATED SCENARIOS:
1. Normal Network Traffic (HTTP, HTTPS, DNS, ICMP, standard payload sizes)
2. Multiple Failed Authentication Events (Repeated auth attempts on port 22/80/443)
3. Source Contacting Many Unique Destination Ports (Multi-port sweep)
4. High-Volume Connection Activity (Excessive connections / rate floods)

DEFENSIVE & ETHICAL ASSURANCE:
This module operates exclusively within Python process memory. It does NOT
perform real network probing, packet injection, port scanning, credential
cracking, or exploitation against any system or network interface.
================================================================================
"""

import time
import random
from datetime import datetime


class SafeTrafficSimulator:
    """
    Synthesizes fictional network packet events and dispatches them into
    the NIDS DetectionEngine to demonstrate real-time defensive monitoring.
    """

    def __init__(self, detection_engine):
        """
        Initialize the simulator with a reference to the central DetectionEngine.

        Parameters:
            detection_engine: Instance of DetectionEngine to process events.
        """
        self.detection_engine = detection_engine

        # Fictional demonstration network hosts
        self.sample_clients = [
            "192.168.1.15",
            "192.168.1.22",
            "192.168.1.45",
            "192.168.1.80"
        ]
        self.sample_servers = [
            "192.168.1.1",     # Default Gateway / Router
            "142.250.190.46",  # External Web Server
            "1.1.1.1",         # Cloudflare DNS
            "8.8.8.8"          # Google DNS
        ]

        # Common destination ports for legitimate traffic
        self.standard_services = [80, 443, 53, 22, 123, 8080]

        # Designated synthetic source IPs for demonstration
        self.demo_scanner_ip = "192.168.1.188"
        self.demo_bruteforce_ip = "192.168.1.205"
        self.demo_spiker_ip = "192.168.1.240"

    # --------------------------------------------------------------------------
    # SCENARIO 1: NORMAL NETWORK TRAFFIC
    # --------------------------------------------------------------------------

    def generate_normal_packet(self):
        """
        Generate a single realistic, legitimate network packet dictionary.
        Covers HTTP, HTTPS, DNS, and ICMP protocols.
        """
        proto = random.choices(['TCP', 'UDP', 'ICMP'], weights=[0.75, 0.20, 0.05])[0]
        s_ip = random.choice(self.sample_clients)
        d_ip = random.choice(self.sample_servers)
        s_port = random.randint(32768, 61000)
        d_port = random.choice(self.standard_services) if proto in ['TCP', 'UDP'] else None
        size = random.randint(64, 1480)

        return {
            'source_ip': s_ip,
            'destination_ip': d_ip,
            'src_ip': s_ip,
            'dst_ip': d_ip,
            'protocol': proto,
            'source_port': s_port,
            'destination_port': d_port,
            'src_port': s_port,
            'dst_port': d_port,
            'packet_size': size,
            'tcp_flags': 'A' if proto == 'TCP' else None,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'Normal'
        }

    def simulate_normal_traffic(self, count=10, delay=0.15):
        """
        Simulate a sequence of routine, non-malicious network frames.

        Parameters:
            count (int): Number of normal packets to simulate.
            delay (float): Inter-packet delay in seconds.

        Returns:
            list: Generated packet dictionaries.
        """
        generated = []
        for _ in range(count):
            pkt = self.generate_normal_packet()
            if self.detection_engine:
                self.detection_engine.process_packet(pkt)
            generated.append(pkt)
            if delay > 0:
                time.sleep(delay)
        return generated

    # --------------------------------------------------------------------------
    # SCENARIO 2: MULTIPLE FAILED AUTHENTICATION EVENTS (BRUTE FORCE)
    # --------------------------------------------------------------------------

    def simulate_failed_authentication(self, source_ip=None, destination_ip=None,
                                      target_port=22, attempts=7, delay=0.08):
        """
        Simulate a rapid succession of failed authentication attempts from a
        single source IP targeting an authentication port (default: SSH port 22).

        Exceeds the threshold of 5 failed attempts within 60s, naturally
        triggering the BruteForceDetector.

        Parameters:
            source_ip (str, optional): Fictional attacker source IP.
            destination_ip (str, optional): Target server IP.
            target_port (int): Authentication service port (21, 22, 23, 80, 443, 3389).
            attempts (int): Number of failed attempts (threshold is >5).
            delay (float): Inter-packet interval in seconds.

        Returns:
            list: Generated packet dictionaries.
        """
        src = source_ip or self.demo_bruteforce_ip
        dst = destination_ip or "192.168.1.5"

        print(f"[SafeSimulator] Generating {attempts} simulated failed authentication events from {src} -> {dst}:{target_port}...")

        generated = []
        for i in range(attempts):
            pkt = {
                'source_ip': src,
                'destination_ip': dst,
                'src_ip': src,
                'dst_ip': dst,
                'protocol': 'TCP',
                'source_port': random.randint(45000, 65000),
                'destination_port': target_port,
                'src_port': random.randint(45000, 65000),
                'dst_port': target_port,
                'packet_size': 120,
                'tcp_flags': 'PA',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': f"Simulated failed auth attempt #{i+1}"
            }
            if self.detection_engine:
                self.detection_engine.process_packet(pkt)
            generated.append(pkt)
            if delay > 0:
                time.sleep(delay)

        return generated

    # --------------------------------------------------------------------------
    # SCENARIO 3: SOURCE CONTACTING MANY UNIQUE DESTINATION PORTS (PORT SCAN)
    # --------------------------------------------------------------------------

    def simulate_port_scan(self, source_ip=None, destination_ip=None, port_count=14, delay=0.05):
        """
        Simulate a single source IP contacting many distinct destination ports
        within a short time window.

        Exceeds the threshold of >10 unique ports within 30s, naturally
        triggering the PortScanDetector.

        Parameters:
            source_ip (str, optional): Fictional scanner IP address.
            destination_ip (str, optional): Target IP address.
            port_count (int): Number of distinct ports probed (threshold is >10).
            delay (float): Delay between port probe frames in seconds.

        Returns:
            list: Generated packet dictionaries.
        """
        src = source_ip or self.demo_scanner_ip
        dst = destination_ip or "192.168.1.1"

        # Curate distinct target ports
        candidate_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
        if port_count <= len(candidate_ports):
            probed_ports = candidate_ports[:port_count]
        else:
            probed_ports = candidate_ports + random.sample(range(1024, 65535), port_count - len(candidate_ports))

        print(f"[SafeSimulator] Generating simulated port scan: {src} probing {len(probed_ports)} distinct ports on {dst}...")

        generated = []
        for port in probed_ports:
            pkt = {
                'source_ip': src,
                'destination_ip': dst,
                'src_ip': src,
                'dst_ip': dst,
                'protocol': 'TCP',
                'source_port': random.randint(45000, 65000),
                'destination_port': port,
                'src_port': random.randint(45000, 65000),
                'dst_port': port,
                'packet_size': 64,
                'tcp_flags': 'S',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            if self.detection_engine:
                self.detection_engine.process_packet(pkt)
            generated.append(pkt)
            if delay > 0:
                time.sleep(delay)

        return generated

    # --------------------------------------------------------------------------
    # SCENARIO 4: HIGH-VOLUME CONNECTION ACTIVITY (SUSPICIOUS ACTIVITY)
    # --------------------------------------------------------------------------

    def simulate_high_volume_activity(self, source_ip=None, destination_ip=None,
                                     packet_count=105, delay=0.01):
        """
        Simulate an abnormally high-rate packet surge from a single source host.

        Exceeds the threshold of >100 connections in 60s or >40 pkts/s,
        naturally triggering the SuspiciousActivityDetector.

        Parameters:
            source_ip (str, optional): Fictional high-rate sender IP.
            destination_ip (str, optional): Target IP.
            packet_count (int): Number of rapid frames to emit (threshold is >100).
            delay (float): Inter-packet delay in seconds.

        Returns:
            list: Generated packet dictionaries.
        """
        src = source_ip or self.demo_spiker_ip
        dst = destination_ip or "192.168.1.1"

        print(f"[SafeSimulator] Generating high-volume traffic surge ({packet_count} frames) from {src} -> {dst}...")

        generated = []
        for i in range(packet_count):
            pkt = {
                'source_ip': src,
                'destination_ip': dst,
                'src_ip': src,
                'dst_ip': dst,
                'protocol': 'TCP',
                'source_port': random.randint(45000, 65000),
                'destination_port': 80,
                'src_port': random.randint(45000, 65000),
                'dst_port': 80,
                'packet_size': 1400,
                'tcp_flags': 'S',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            if self.detection_engine:
                self.detection_engine.process_packet(pkt)
            generated.append(pkt)
            if delay > 0:
                time.sleep(delay)

        return generated

    # --------------------------------------------------------------------------
    # ON-DEMAND SCENARIO DISPATCHER
    # --------------------------------------------------------------------------

    def run_scenario(self, scenario_name):
        """
        Dispatch a specific simulation scenario on demand.

        Parameters:
            scenario_name (str): 'normal', 'failed_auth', 'port_scan',
                                 'high_volume', or 'all'.

        Returns:
            dict: Summary of executed scenario and packets generated.
        """
        name = str(scenario_name).lower().strip()

        if name in ['normal', 'traffic', 'legitimate']:
            pkts = self.simulate_normal_traffic(count=15, delay=0.1)
            return {'status': 'success', 'scenario': 'normal', 'packets_sent': len(pkts)}

        elif name in ['failed_auth', 'brute_force', 'auth']:
            pkts = self.simulate_failed_authentication(attempts=7, delay=0.06)
            return {'status': 'success', 'scenario': 'failed_auth', 'packets_sent': len(pkts)}

        elif name in ['port_scan', 'scan']:
            pkts = self.simulate_port_scan(port_count=14, delay=0.04)
            return {'status': 'success', 'scenario': 'port_scan', 'packets_sent': len(pkts)}

        elif name in ['high_volume', 'flood', 'dos', 'surge']:
            pkts = self.simulate_high_volume_activity(packet_count=105, delay=0.01)
            return {'status': 'success', 'scenario': 'high_volume', 'packets_sent': len(pkts)}

        elif name in ['all', 'full_demo']:
            pkts_norm = self.simulate_normal_traffic(count=10, delay=0.05)
            pkts_scan = self.simulate_port_scan(port_count=12, delay=0.04)
            pkts_norm2 = self.simulate_normal_traffic(count=5, delay=0.05)
            pkts_auth = self.simulate_failed_authentication(attempts=7, delay=0.05)
            pkts_surge = self.simulate_high_volume_activity(packet_count=105, delay=0.01)
            total = len(pkts_norm) + len(pkts_scan) + len(pkts_norm2) + len(pkts_auth) + len(pkts_surge)
            return {'status': 'success', 'scenario': 'all', 'packets_sent': total}

        else:
            return {'status': 'error', 'message': f"Unknown scenario: '{scenario_name}'. Options: normal, failed_auth, port_scan, high_volume, all"}

    # --------------------------------------------------------------------------
    # CONTINUOUS BACKGROUND SIMULATION LOOP
    # --------------------------------------------------------------------------

    def run_continuous(self, stop_event):
        """
        Continuous background generator that steadily produces normal traffic
        and periodically injects safe demonstration scenarios.

        Parameters:
            stop_event (threading.Event): Event flag to halt execution.
        """
        print("[SafeSimulator] Starting continuous background simulation loop.")
        counter = 0

        while not stop_event.is_set():
            counter += 1
            time.sleep(random.uniform(0.15, 0.40))

            # Periodic Scenario 1: Port Scan (every ~45 packets)
            if counter % 45 == 0:
                self.simulate_port_scan(port_count=14, delay=0.04)
                continue

            # Periodic Scenario 2: Brute Force Failed Auth (every ~35 packets)
            if counter % 35 == 0:
                self.simulate_failed_authentication(attempts=7, delay=0.06)
                continue

            # Periodic Scenario 3: High-Volume surge (every ~75 packets)
            if counter % 75 == 0:
                self.simulate_high_volume_activity(packet_count=105, delay=0.01)
                continue

            # Standard routine background traffic
            pkt = self.generate_normal_packet()
            if self.detection_engine:
                self.detection_engine.process_packet(pkt)
