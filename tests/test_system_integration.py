"""
System Integration Tests for Real-Time NIDS:
- Application Startup & Configuration
- Database ORM Operations & Statistics Aggregation
- REST API Endpoints & Route Security
- Real-Time Socket.IO WebSocket Broadcasting
"""

import json
import pytest
from app import app, socketio
from config import Config
from backend.database import (
    db, User, SecurityAlert, NetworkTraffic,
    save_network_traffic, save_security_alert,
    get_recent_alerts, get_dashboard_statistics
)


# ==============================================================================
# SECTION 1: APPLICATION STARTUP & CONFIGURATION
# ==============================================================================

class TestApplicationStartup:
    """Verifies WSGI app startup and configuration integrity."""

    def test_app_instance_and_config(self, app):
        """Flask app should initialize with required configurations."""
        assert app is not None
        assert app.config['TESTING'] is True
        assert hasattr(Config, 'SQLALCHEMY_DATABASE_URI')
        assert hasattr(Config, 'PORT_SCAN_THRESHOLD')
        assert hasattr(Config, 'BRUTE_FORCE_THRESHOLD')

    def test_login_page_renders_successfully(self, client):
        """Unauthenticated user visiting /login gets 200 with login form."""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'SOC Security Gateway' in response.data or b'Login' in response.data

    def test_root_route_redirects_to_login(self, client):
        """Visiting / without session redirects to /login."""
        response = client.get('/', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']


# ==============================================================================
# SECTION 2: DATABASE OPERATIONS
# ==============================================================================

class TestDatabaseOperations:
    """Verifies SQLite database read/write/aggregate operations."""

    def test_save_and_retrieve_network_traffic(self, app):
        """save_network_traffic must persist packet metadata correctly."""
        with app.app_context():
            packet = save_network_traffic(
                source_ip="192.168.1.10",
                destination_ip="192.168.1.1",
                protocol="TCP",
                source_port=54321,
                destination_port=80,
                packet_size=512,
                status="Normal"
            )
            assert packet is not None
            assert packet.id is not None
            assert packet.source_ip == "192.168.1.10"
            assert packet.destination_port == 80

            # Query back from database
            retrieved = NetworkTraffic.query.filter_by(id=packet.id).first()
            assert retrieved is not None
            assert retrieved.protocol == "TCP"

    def test_save_and_retrieve_security_alert(self, app):
        """save_security_alert must persist alert metadata correctly."""
        with app.app_context():
            alert = save_security_alert(
                attack_type="Port Scan",
                source_ip="10.0.0.99",
                destination_ip="10.0.0.1",
                severity="HIGH",
                description="Automated unit test port scan alert",
                status="Active"
            )
            assert alert is not None
            assert alert.id is not None
            assert alert.attack_type == "Port Scan"
            assert alert.severity == "HIGH"

            # Query via helper
            alerts = get_recent_alerts(limit=5, severity="HIGH")
            assert len(alerts) > 0
            matching = [a for a in alerts if a.id == alert.id]
            assert len(matching) == 1

    def test_get_dashboard_statistics_structure(self, app):
        """get_dashboard_statistics must return all required summary fields."""
        with app.app_context():
            stats = get_dashboard_statistics()
            assert 'total_packets' in stats
            assert 'total_alerts' in stats
            assert 'port_scan_alerts' in stats
            assert 'brute_force_alerts' in stats
            assert 'suspicious_activity_alerts' in stats
            assert 'severity_breakdown' in stats
            assert isinstance(stats['severity_breakdown'], dict)

    def test_user_password_hashing(self, app):
        """User model should securely hash and verify passwords."""
        with app.app_context():
            user = User(username="test_analyst", role="analyst")
            user.set_password("SecurePass123!")
            assert user.password_hash != "SecurePass123!"
            assert user.check_password("SecurePass123!") is True
            assert user.check_password("WrongPassword") is False


# ==============================================================================
# SECTION 3: REST API ENDPOINTS & ROUTE SECURITY
# ==============================================================================

class TestApiEndpointsAndRouteSecurity:
    """Verifies REST API responses and session-based route security."""

    def test_get_stats_endpoint(self, client):
        """GET /api/stats returns 200 and JSON dictionary of stats."""
        response = client.get('/api/stats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_packets' in data
        assert 'total_alerts' in data
        assert 'severity_breakdown' in data

    def test_get_alerts_endpoint(self, client):
        """GET /api/alerts returns 200 and JSON array of alerts."""
        response = client.get('/api/alerts')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_get_alerts_with_filters(self, client):
        """GET /api/alerts supports severity and type query parameters."""
        response = client.get('/api/alerts?severity=HIGH&type=Port+Scan&limit=10')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        for alert in data:
            assert alert['severity'] == 'HIGH'
            assert alert['attack_type'] == 'Port Scan'

    def test_get_traffic_endpoint(self, client):
        """GET /api/traffic returns 200 and recent packet list."""
        response = client.get('/api/traffic?limit=10')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_post_simulate_scenario_endpoint(self, client):
        """POST /api/simulate accepts valid scenario and returns 200."""
        payload = {'scenario': 'normal'}
        response = client.post(
            '/api/simulate',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['scenario'] == 'normal'

    def test_protected_routes_require_authentication(self, client):
        """Unauthenticated requests to /dashboard and /alerts must redirect to /login."""
        dash_res = client.get('/dashboard', follow_redirects=False)
        assert dash_res.status_code == 302
        assert '/login' in dash_res.headers['Location']

        alerts_res = client.get('/alerts', follow_redirects=False)
        assert alerts_res.status_code == 302
        assert '/login' in alerts_res.headers['Location']

    def test_authenticated_user_accesses_dashboard(self, auth_client):
        """Authenticated client can successfully view /dashboard and /alerts."""
        dash_res = auth_client.get('/dashboard')
        assert dash_res.status_code == 200
        assert b'Cybersecurity Operations Center' in dash_res.data or b'Dashboard' in dash_res.data

        alerts_res = auth_client.get('/alerts')
        assert alerts_res.status_code == 200
        assert b'Security Alerts' in alerts_res.data or b'Alerts' in alerts_res.data


# ==============================================================================
# SECTION 4: REAL-TIME ALERT UPDATES (SOCKET.IO)
# ==============================================================================

class TestRealTimeSocketIO:
    """Verifies WebSocket connection and event synchronization."""

    def test_socket_connection_and_stats_update(self, socket_client):
        """Client connection should trigger an immediate stats_update broadcast."""
        assert socket_client.is_connected()
        received = socket_client.get_received()

        # Check if stats_update was emitted upon connection
        event_names = [event['name'] for event in received]
        assert 'stats_update' in event_names, "Connecting client must receive 'stats_update' event"

    def test_socket_request_stats_event(self, socket_client):
        """Sending 'request_stats' must trigger a 'stats_update' response."""
        socket_client.get_received()  # Flush previous events
        socket_client.emit('request_stats')
        received = socket_client.get_received()

        event_names = [event['name'] for event in received]
        assert 'stats_update' in event_names, "Server must respond with 'stats_update'"
