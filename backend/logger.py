"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Security Logging Subsystem (backend/logger.py)

PURPOSE:
Provides a unified, professional Python logging pipeline for the NIDS.
All significant security events, application lifecycle milestones, network
telemetry processing, and system errors are persisted to disk and streamed
to the console with standard timestamps and severity levels (INFO, WARNING, ERROR).

DESTINATION:
- File: logs/security_logs.txt (UTF-8 encoding, persistent append)
- Stream: sys.stdout (Live console output)

LOG LEVELS:
- INFO: Application startup, capture start/stop, packet processing, simulation events
- WARNING: Detected security intrusions (Port Scans, Brute Force, Suspicious Activity)
- ERROR: System exceptions, driver/socket failures, dissection errors
================================================================================
"""

import os
import sys
import logging
from config import Config

# Ensure logs directory exists
os.makedirs(Config.LOGS_DIR, exist_ok=True)

# Standardized timestamp and format
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_security_logger(logger_name="NIDS_Security"):
    """
    Configure and return a Python logging instance bound to both
    logs/security_logs.txt and the terminal stream.

    Parameters:
        logger_name (str): The namespace identifier for the logger component.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(logger_name)

    # Avoid duplicate handlers if setup is invoked repeatedly
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # 1. File Handler (Persistent Security Log)
    try:
        file_handler = logging.FileHandler(Config.LOG_FILE_PATH, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"[LoggerSetup] Warning: Failed to initialize file handler for {Config.LOG_FILE_PATH}: {e}")

    # 2. Console Stream Handler (Live Console Mirror)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


# Pre-instantiated central security logger
security_logger = setup_security_logger("NIDS_Security")


def get_logger(component_name):
    """
    Helper function to obtain a named logger for a specific module or detector.

    Parameters:
        component_name (str): Name of the subsystem (e.g. 'DetectionEngine', 'PortScanDetector')

    Returns:
        logging.Logger: Child logger configured with the central formatters and handlers.
    """
    return setup_security_logger(f"NIDS_{component_name}")
