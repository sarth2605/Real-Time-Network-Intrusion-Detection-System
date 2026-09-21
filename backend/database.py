"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Database Management & SQLAlchemy Models (backend/database.py)

Database Engine: SQLite (stored in database/intrusion.db)
ORM: Flask-SQLAlchemy

MODELS:
1. SecurityAlert - Stores detected intrusions (Port Scans, Brute Force, Floods).
2. NetworkTraffic - Stores captured packet frame metadata for analysis.
3. User - Stores authenticated analyst credentials.

FUNCTIONS:
- save_network_traffic()
- save_security_alert()
- get_recent_alerts()
- get_dashboard_statistics()
================================================================================
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

# Initialize SQLAlchemy instance
db = SQLAlchemy()

# ------------------------------------------------------------------------------
# 1. SECURITY ALERT MODEL
# ------------------------------------------------------------------------------
class SecurityAlert(db.Model):
    """
    Represents a detected security threat or anomaly flagged by the detection engine.
    """
    __tablename__ = 'security_alerts'

    id = db.Column(db.Integer, primary_key=True)
    attack_type = db.Column(db.String(50), nullable=False)       # e.g., 'Port Scan', 'Brute Force'
    source_ip = db.Column(db.String(45), nullable=False, index=True) # Attacker / Suspicious IP
    destination_ip = db.Column(db.String(45), nullable=True)     # Target IP
    severity = db.Column(db.String(20), nullable=False)          # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description = db.Column(db.Text, nullable=False)             # Human-readable investigation detail
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default='Active')          # 'Active', 'Acknowledged', 'Resolved'

    # Optional port metadata for alert detail
    target_port = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        """Serialize alert instance to JSON-compatible dictionary."""
        return {
            'id': self.id,
            'attack_type': self.attack_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip or '-',
            'target_port': self.target_port or '-',
            'severity': self.severity,
            'description': self.description,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status
        }


# ------------------------------------------------------------------------------
# 2. NETWORK TRAFFIC MODEL
# ------------------------------------------------------------------------------
class NetworkTraffic(db.Model):
    """
    Represents an individual packet frame captured and inspected by the sniffer.
    """
    __tablename__ = 'network_traffic'

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)          # 'TCP', 'UDP', 'ICMP', 'ARP'
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    packet_size = db.Column(db.Integer, nullable=False)          # Packet size in bytes
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default='Normal')          # 'Normal', 'Port Scan', 'Brute Force'

    # Compatibility properties for code using shorthand notations
    @property
    def src_ip(self):
        return self.source_ip

    @property
    def dst_ip(self):
        return self.destination_ip

    @property
    def src_port(self):
        return self.source_port

    @property
    def dst_port(self):
        return self.destination_port

    def to_dict(self):
        """Serialize packet record to JSON-compatible dictionary."""
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'src_ip': self.source_ip,
            'dst_ip': self.destination_ip,
            'protocol': self.protocol,
            'source_port': self.source_port or '-',
            'destination_port': self.destination_port or '-',
            'src_port': self.source_port or '-',
            'dst_port': self.destination_port or '-',
            'packet_size': self.packet_size,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status
        }


# ------------------------------------------------------------------------------
# 3. USER AUTHENTICATION MODEL
# ------------------------------------------------------------------------------
class User(db.Model):
    """
    Represents a SOC analyst account allowed to access the dashboard.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='analyst')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Hash plain text password for safe storage."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify candidate password against stored cryptographic hash."""
        return check_password_hash(self.password_hash, password)


# ------------------------------------------------------------------------------
# 4. DATABASE INITIALIZATION & SEEDING
# ------------------------------------------------------------------------------

def create_or_update_user(username, password, role='admin'):
    """
    Create a new user account or update an existing user's password and role.
    Uses cryptographically secure Werkzeug password hashing.

    Parameters:
        username (str): Unique username identifier.
        password (str): Plain-text password (will be hashed).
        role (str): Account role ('admin' or 'analyst').

    Returns:
        tuple: (User instance, bool created)
    """
    user = User.query.filter_by(username=username).first()
    created = False

    if not user:
        user = User(username=username, role=role)
        db.session.add(user)
        created = True
    else:
        user.role = role

    user.set_password(password)
    db.session.commit()
    return user, created


def init_db(app):
    """
    Idempotent database initialization:
    - Binds SQLAlchemy extension to the Flask application.
    - Creates all database tables if they do not already exist.
    - Seeds an initial administrator account using Config settings or environment variables
      (NIDS_ADMIN_USER and NIDS_ADMIN_PASSWORD).
    """
    if 'sqlalchemy' not in app.extensions:
        db.init_app(app)

    with app.app_context():
        db.create_all()

        # Seed default administrator account if no users exist
        if User.query.count() == 0:
            admin_user = getattr(Config, 'DEFAULT_ADMIN_USER', 'admin')
            admin_pass = getattr(Config, 'DEFAULT_ADMIN_PASSWORD', 'admin123')
            user, _ = create_or_update_user(username=admin_user, password=admin_pass, role='admin')
            print(f"[Database] Default administrator account provisioned: '{admin_user}' (credentials configurable via env vars)")


# ------------------------------------------------------------------------------
# 5. CORE DATABASE FUNCTIONS
# ------------------------------------------------------------------------------

def save_network_traffic(source_ip, destination_ip, protocol, source_port=None,
                         destination_port=None, packet_size=0, status='Normal',
                         src_ip=None, dst_ip=None, src_port=None, dst_port=None):
    """
    Save captured network packet metadata into the database.

    Parameters:
        source_ip (str): Source IP address.
        destination_ip (str): Target IP address.
        protocol (str): Transport/Network layer protocol (TCP, UDP, ICMP, ARP).
        source_port (int, optional): Source port number.
        destination_port (int, optional): Target port number.
        packet_size (int): Size of the packet in bytes.
        status (str): Classification ('Normal', 'Port Scan', 'Brute Force', etc.)

    Returns:
        NetworkTraffic instance if successfully persisted, None otherwise.
    """
    # Accommodate shorthand parameter names
    resolved_src_ip = source_ip or src_ip
    resolved_dst_ip = destination_ip or dst_ip
    resolved_src_port = source_port if source_port is not None else src_port
    resolved_dst_port = destination_port if destination_port is not None else dst_port

    try:
        traffic_record = NetworkTraffic(
            source_ip=resolved_src_ip,
            destination_ip=resolved_dst_ip,
            protocol=protocol,
            source_port=resolved_src_port,
            destination_port=resolved_dst_port,
            packet_size=packet_size,
            status=status
        )
        db.session.add(traffic_record)
        db.session.commit()
        return traffic_record
    except Exception as e:
        db.session.rollback()
        print(f"[Database Error] save_network_traffic failed: {e}")
        return None


def save_security_alert(attack_type, source_ip, destination_ip=None, severity='HIGH',
                        description='', status='Active', target_port=None):
    """
    Save a detected intrusion alert into the database.

    Parameters:
        attack_type (str): Type of attack (e.g. 'Port Scan', 'Brute Force').
        source_ip (str): Source IP of suspected attacker.
        destination_ip (str, optional): Target victim IP.
        severity (str): 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.
        description (str): Human-readable forensic summary of detection.
        status (str): Current status ('Active', 'Acknowledged', 'Resolved').
        target_port (int, optional): Port attacked.

    Returns:
        SecurityAlert instance if successfully persisted, None otherwise.
    """
    try:
        alert_record = SecurityAlert(
            attack_type=attack_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            severity=severity,
            description=description,
            status=status,
            target_port=target_port
        )
        db.session.add(alert_record)
        db.session.commit()
        return alert_record
    except Exception as e:
        db.session.rollback()
        print(f"[Database Error] save_security_alert failed: {e}")
        return None


def get_recent_alerts(limit=50, severity=None, attack_type=None):
    """
    Retrieve recently logged security alerts, sorted newest first.

    Parameters:
        limit (int): Maximum number of alerts to retrieve (default: 50).
        severity (str, optional): Filter by severity ('CRITICAL', 'HIGH', etc.).
        attack_type (str, optional): Filter by attack type ('Port Scan', etc.).

    Returns:
        list of SecurityAlert objects.
    """
    query = SecurityAlert.query

    if severity and severity.upper() != 'ALL':
        query = query.filter_by(severity=severity.upper())
    if attack_type and attack_type != 'ALL':
        query = query.filter_by(attack_type=attack_type)

    return query.order_by(SecurityAlert.timestamp.desc()).limit(limit).all()


def get_dashboard_statistics():
    """
    Calculate and aggregate real-time metrics for SOC dashboard KPI cards.

    Returns:
        dict: {
            'total_packets': int,
            'normal_traffic': int,
            'suspicious_count': int,
            'brute_force_count': int,
            'port_scan_count': int,
            'total_alerts': int
        }
    """
    total_packets = NetworkTraffic.query.count()
    normal_traffic = NetworkTraffic.query.filter_by(status='Normal').count()
    suspicious_count = SecurityAlert.query.filter_by(attack_type='Suspicious Activity').count()
    brute_force_count = SecurityAlert.query.filter_by(attack_type='Brute Force').count()
    port_scan_count = SecurityAlert.query.filter_by(attack_type='Port Scan').count()
    total_alerts = SecurityAlert.query.count()

    # Attack distribution breakdown for charts
    attack_breakdown = {
        'Port Scan': port_scan_count,
        'Brute Force': brute_force_count,
        'Suspicious Activity': suspicious_count
    }

    # Severity distribution breakdown for charts
    severity_breakdown = {
        'LOW': SecurityAlert.query.filter_by(severity='LOW').count(),
        'MEDIUM': SecurityAlert.query.filter_by(severity='MEDIUM').count(),
        'HIGH': SecurityAlert.query.filter_by(severity='HIGH').count(),
        'CRITICAL': SecurityAlert.query.filter_by(severity='CRITICAL').count(),
    }

    return {
        'total_packets': total_packets,
        'total_alerts': total_alerts,
        'brute_force_alerts': brute_force_count,
        'port_scan_alerts': port_scan_count,
        'suspicious_activity_alerts': suspicious_count,
        # Internal & backward compatibility aliases:
        'normal_traffic': normal_traffic,
        'suspicious_count': suspicious_count,
        'brute_force_count': brute_force_count,
        'port_scan_count': port_scan_count,
        'attack_breakdown': attack_breakdown,
        'severity_breakdown': severity_breakdown
    }


# ------------------------------------------------------------------------------
# 6. BACKWARD-COMPATIBILITY ALIASES
# ------------------------------------------------------------------------------
# These aliases ensure existing code written with earlier nomenclature
# continues to function seamlessly without modifications.
Alert = SecurityAlert
PacketLog = NetworkTraffic
log_packet = save_network_traffic
log_alert = save_security_alert
get_dashboard_stats = get_dashboard_statistics
