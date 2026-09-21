"""
Pytest configuration and test fixtures for Real-Time NIDS.
Provides fixtures for Flask application, database sessions, test clients,
SocketIO test clients, and fresh instances of detection modules.
"""

import pytest
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app, socketio as flask_socketio
from backend.database import db as flask_db, User, SecurityAlert, NetworkTraffic
from backend.port_scan_detector import PortScanDetector
from backend.brute_force_detector import BruteForceDetector
from backend.suspicious_activity_detector import SuspiciousActivityDetector


@pytest.fixture(scope='session')
def app():
    """Create and configure a Flask application instance for testing."""
    flask_app.config.update({
        'TESTING': True,
        'DEBUG': False,
        'SECRET_KEY': 'test-secret-key-soc-nids'
    })
    yield flask_app


@pytest.fixture(scope='function')
def client(app):
    """A test client for unauthenticated HTTP requests."""
    return app.test_client()


@pytest.fixture(scope='function')
def auth_client(app):
    """A test client with an authenticated administrator session."""
    test_client = app.test_client()
    with test_client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'admin'
        sess['logged_in'] = True
    return test_client


@pytest.fixture(scope='function')
def socket_client(app):
    """A Flask-SocketIO test client for testing real-time WebSocket events."""
    test_client = flask_socketio.test_client(app)
    yield test_client
    if test_client.is_connected():
        test_client.disconnect()


@pytest.fixture(scope='function')
def fresh_port_scan_detector():
    """Returns an isolated, freshly initialized PortScanDetector."""
    return PortScanDetector(threshold=10, window_seconds=30, alert_cooldown=20)


@pytest.fixture(scope='function')
def fresh_brute_force_detector():
    """Returns an isolated, freshly initialized BruteForceDetector."""
    return BruteForceDetector(threshold=5, window_seconds=60, alert_cooldown=25)


@pytest.fixture(scope='function')
def fresh_suspicious_detector():
    """Returns an isolated, freshly initialized SuspiciousActivityDetector."""
    return SuspiciousActivityDetector(
        connection_threshold=100,
        packet_rate_threshold=40,
        alert_cooldown=20
    )
