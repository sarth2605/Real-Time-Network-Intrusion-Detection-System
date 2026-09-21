"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Passive Packet Capture & Traffic Simulation Engine (backend/packet_capture.py)

PURPOSE:
Passively captures and inspects network packets on authorized network interfaces
using Scapy, safely extracting flow metadata (IP addresses, protocols, ports,
payload sizes, and timestamps) and forwarding it to the central Detection Engine.

DEFENSIVE / EDUCATIONAL ASSURANCE:
This module operates exclusively in passive promiscuous/sniffing mode. It DOES
NOT inject packets, alter network flows, intercept sensitive credentials, or
execute offensive attacks. When raw capture permissions (such as Npcap or root/
admin privileges) are unavailable, it seamlessly falls back to a realistic
Traffic Simulator to enable safe demonstration and student evaluation.
================================================================================
"""

import time
import random
import threading
from datetime import datetime

# Attempt to import Scapy for live passive network sniffing.
# If Scapy or system capture drivers (Npcap/WinPcap) are not installed,
# the module gracefully falls back to simulation mode without crashing.
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from backend.traffic_simulator import SafeTrafficSimulator
from backend.logger import get_logger

logger = get_logger("PacketCapture")


class PacketCaptureEngine:
    """
    Manages passive network packet acquisition and synthetic demonstration traffic.
    Runs on a dedicated background thread to prevent blocking the Flask server.
    """

    def __init__(self, detection_engine, interface=None):
        """
        Initialize the packet capture subsystem.

        Parameters:
            detection_engine (DetectionEngine): The downstream engine that inspects
                                               packets for malicious patterns.
            interface (str, optional): Network interface to bind to (e.g. 'eth0',
                                       'Wi-Fi', or None for default interface).
        """
        self.detection_engine = detection_engine
        self.interface = interface

        # Instantiate safe simulation subsystem
        self.simulator = SafeTrafficSimulator(detection_engine)

        # State flags
        self.is_capturing = False
        self.simulation_mode = False

        # Background threads and termination event
        self.capture_thread = None
        self.sim_thread = None
        self._stop_event = threading.Event()

    # --------------------------------------------------------------------------
    # 1. PACKET DISSECTION & EXTRACTION (PASSIVE MONITORING)
    # --------------------------------------------------------------------------

    def _packet_callback(self, packet):
        """
        Callback invoked by Scapy for every network packet received.
        Extracts metadata safely and passes it to the detection engine.
        """
        if self._stop_event.is_set():
            return

        try:
            # Safely dissect packet fields
            packet_info = self._dissect_packet(packet)

            # If valid packet metadata was extracted, forward to detection engine
            if packet_info and self.detection_engine:
                self.detection_engine.process_packet(packet_info)

        except Exception as e:
            # Robust defensive handling: never allow an unhandled malformed packet
            # or dissector exception to terminate the background sniffer thread.
            pass

    def _dissect_packet(self, packet):
        """
        Safely extract header attributes from a raw network frame.
        Safely handles missing fields, optional protocols, and edge cases.

        Fields Extracted:
        - Source IP (IPv4 / IPv6 / ARP sender)
        - Destination IP (IPv4 / IPv6 / ARP target)
        - Protocol ('TCP', 'UDP', 'ICMP', 'ARP')
        - Source Port (for TCP / UDP)
        - Destination Port (for TCP / UDP)
        - Packet Size (in bytes)
        - Timestamp (ISO standard format)

        Returns:
            dict containing normalized packet attributes, or None if non-routable.
        """
        # Ensure packet has a recognizable network layer
        has_ipv4 = packet.haslayer(IP)
        has_ipv6 = packet.haslayer(IPv6)
        has_arp = packet.haslayer(ARP)

        if not (has_ipv4 or has_ipv6 or has_arp):
            return None

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        packet_size = len(packet)

        # Default field initializations
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        protocol = "UNKNOWN"
        src_port = None
        dst_port = None
        tcp_flags = None

        # 1. Dissect IPv4 Packets
        if has_ipv4:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if packet.haslayer(TCP):
                protocol = 'TCP'
                src_port = int(packet[TCP].sport) if hasattr(packet[TCP], 'sport') else None
                dst_port = int(packet[TCP].dport) if hasattr(packet[TCP], 'dport') else None
                tcp_flags = str(packet[TCP].flags) if hasattr(packet[TCP], 'flags') else None

            elif packet.haslayer(UDP):
                protocol = 'UDP'
                src_port = int(packet[UDP].sport) if hasattr(packet[UDP], 'sport') else None
                dst_port = int(packet[UDP].dport) if hasattr(packet[UDP], 'dport') else None

            elif packet.haslayer(ICMP):
                protocol = 'ICMP'

            else:
                proto_id = packet[IP].proto
                protocol = f"IP-{proto_id}"

        # 2. Dissect IPv6 Packets
        elif has_ipv6:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

            if packet.haslayer(TCP):
                protocol = 'TCP'
                src_port = int(packet[TCP].sport) if hasattr(packet[TCP], 'sport') else None
                dst_port = int(packet[TCP].dport) if hasattr(packet[TCP], 'dport') else None
                tcp_flags = str(packet[TCP].flags) if hasattr(packet[TCP], 'flags') else None
            elif packet.haslayer(UDP):
                protocol = 'UDP'
                src_port = int(packet[UDP].sport) if hasattr(packet[UDP], 'sport') else None
                dst_port = int(packet[UDP].dport) if hasattr(packet[UDP], 'dport') else None
            else:
                protocol = 'IPv6'

        # 3. Dissect Address Resolution Protocol (ARP) Packets
        elif has_arp:
            protocol = 'ARP'
            src_ip = packet[ARP].psrc if hasattr(packet[ARP], 'psrc') else "0.0.0.0"
            dst_ip = packet[ARP].pdst if hasattr(packet[ARP], 'pdst') else "0.0.0.0"

        # Return standardized, complete metadata dictionary
        return {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'source_port': src_port,
            'destination_port': dst_port,
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_size': packet_size,
            'tcp_flags': tcp_flags,
            'timestamp': now_str
        }

    # --------------------------------------------------------------------------
    # 2. PASSIVE LIVE CAPTURE WORKER
    # --------------------------------------------------------------------------

    def _live_capture_worker(self):
        """
        Background worker thread that runs Scapy's passive packet sniffer.
        Uses store=False to ensure minimal RAM usage during extended sessions.
        """
        logger.info(f"Starting passive sniffer on interface: {self.interface or 'default'}")

        try:
            # Execute passive sniff loop
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Live capture failed or driver missing: {e}")
            logger.info("Automatically activating Traffic Simulator for demonstration...")
            self.start_simulation()
        finally:
            self.is_capturing = False

    # --------------------------------------------------------------------------
    # 3. SYNTHETIC TRAFFIC SIMULATOR (DEMONSTRATION MODE)
    # --------------------------------------------------------------------------

    def _simulation_worker(self):
        """
        Synthetic Traffic Simulator background worker.
        Delegates to SafeTrafficSimulator to steadily stream realistic packets
        and periodically demonstrate intrusion detection scenarios safely.
        """
        logger.info("Starting SafeTrafficSimulator continuous worker.")
        try:
            self.simulator.run_continuous(self._stop_event)
        except Exception as e:
            logger.error(f"Simulator worker encountered error: {e}", exc_info=True)
        finally:
            self.simulation_mode = False

    def run_simulation_scenario(self, scenario_name):
        """
        Trigger an on-demand safe simulation scenario.

        Parameters:
            scenario_name (str): 'normal', 'failed_auth', 'port_scan',
                                 'high_volume', or 'all'.

        Returns:
            dict: Outcome summary and number of packets dispatched.
        """
        if self.simulator:
            return self.simulator.run_scenario(scenario_name)
        return {'status': 'error', 'message': 'Traffic simulator not initialized'}

    # --------------------------------------------------------------------------
    # 4. CAPTURE LIFECYCLE CONTROLS
    # --------------------------------------------------------------------------

    def start_live_capture(self):
        """
        Start live passive packet sniffing on the configured network interface.
        If a capture session or simulation is already running, stops it first.
        """
        if self.is_capturing or self.simulation_mode:
            self.stop_capture()

        self._stop_event.clear()
        self.is_capturing = True
        self.simulation_mode = False

        self.capture_thread = threading.Thread(
            target=self._live_capture_worker,
            name="NIDS-LiveSnifferThread",
            daemon=True
        )
        self.capture_thread.start()

    def start_simulation(self):
        """
        Start the synthetic network traffic generator.
        Ideal for classroom demonstrations or when raw socket drivers are not present.
        """
        if self.is_capturing or self.simulation_mode:
            self.stop_capture()

        self._stop_event.clear()
        self.simulation_mode = True
        self.is_capturing = False

        self.sim_thread = threading.Thread(
            target=self._simulation_worker,
            name="NIDS-TrafficSimulatorThread",
            daemon=True
        )
        self.sim_thread.start()

    def stop_capture(self):
        """
        Signal the background thread to safely halt packet ingestion.
        """
        self._stop_event.set()
        self.is_capturing = False
        self.simulation_mode = False

    def get_status(self):
        """
        Retrieve current engine state for dashboard status badges and API responses.

        Returns:
            dict with 'is_capturing', 'simulation_mode', and 'scapy_available'.
        """
        return {
            'is_capturing': self.is_capturing,
            'simulation_mode': self.simulation_mode,
            'scapy_available': SCAPY_AVAILABLE
        }
