"""
Configuration settings for the Real-Time Network Intrusion Detection System (NIDS).
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Flask Security & Session Hardening
    SECRET_KEY = os.environ.get('SECRET_KEY', 'nids-super-secret-key-2026-bcs-project')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Administrator Account Credentials (Environment variables with safe defaults)
    DEFAULT_ADMIN_USER = os.environ.get('NIDS_ADMIN_USER', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('NIDS_ADMIN_PASSWORD', 'admin123')

    # SQLite Database Configuration
    DATABASE_DIR = os.path.join(BASE_DIR, 'database')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(DATABASE_DIR, 'intrusion.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Security Log File
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILE_PATH = os.path.join(LOGS_DIR, 'security_logs.txt')

    # Intrusion Detection Thresholds (Configurable per requirements)
    # 1. Port Scanning: > 10 ports scanned within 30 seconds
    PORT_SCAN_THRESHOLD = 10
    PORT_SCAN_WINDOW = 30  # seconds

    # 2. Brute Force: > 5 attempts on authentication services within 60 seconds
    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW = 60  # seconds
    BRUTE_FORCE_PORTS = [21, 22, 23, 80, 443, 3389, 8080]  # FTP, SSH, Telnet, HTTP(S), RDP

    # 3. Suspicious Traffic: High packet rate per IP or abnormally large payloads
    SUSPICIOUS_PACKET_RATE_THRESHOLD = 40  # packets/sec from single host
    SUSPICIOUS_PACKET_WINDOW = 2  # seconds

    # Network Sniffer Configuration
    NETWORK_INTERFACE = None  # None for default/all interfaces
    DEFAULT_CAPTURE_PACKET_LIMIT = 50000

    # Educational / Authorization Disclaimer
    EDUCATIONAL_NOTICE = (
        "Educational Notice: This system is designed solely for monitoring authorized networks "
        "and legitimate security research."
    )
