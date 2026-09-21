"""
================================================================================
Real-Time Network Intrusion Detection System (NIDS)
Administrator Account Setup Utility (setup_admin.py)

PURPOSE:
Provides a safe CLI setup script to provision or reset administrator credentials
without storing hardcoded passwords in source code.
Uses environment variables (NIDS_ADMIN_USER, NIDS_ADMIN_PASSWORD), command-line
arguments, or interactive prompts with masked password inputs.

USAGE EXAMPLES:
1. Using environment variables:
   $env:NIDS_ADMIN_USER="secadmin"; $env:NIDS_ADMIN_PASSWORD="SecurePass2026!"; python setup_admin.py

2. Using CLI arguments:
   python setup_admin.py --username secadmin --password "SecurePass2026!"

3. Interactive mode:
   python setup_admin.py
================================================================================
"""

import os
import sys
import argparse
import getpass

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import Config
from app import app
from backend.database import db, User, create_or_update_user


def main():
    parser = argparse.ArgumentParser(
        description="NIDS Administrator Account Provisioning Utility"
    )
    parser.add_argument(
        "-u", "--username",
        help="Administrator username (or set env NIDS_ADMIN_USER)",
        default=None
    )
    parser.add_argument(
        "-p", "--password",
        help="Administrator password (or set env NIDS_ADMIN_PASSWORD)",
        default=None
    )
    parser.add_argument(
        "-r", "--role",
        help="User role (default: admin)",
        default="admin"
    )

    args = parser.parse_args()

    # 1. Resolve Username
    username = args.username or os.environ.get('NIDS_ADMIN_USER')
    if not username:
        if sys.stdin.isatty():
            username = input("Enter administrator username [admin]: ").strip() or "admin"
        else:
            username = Config.DEFAULT_ADMIN_USER

    # 2. Resolve Password
    password = args.password or os.environ.get('NIDS_ADMIN_PASSWORD')
    if not password:
        if sys.stdin.isatty():
            password = getpass.getpass(f"Enter password for '{username}': ").strip()
            if not password:
                print("Error: Password cannot be empty.")
                sys.exit(1)
            confirm = getpass.getpass("Confirm password: ").strip()
            if password != confirm:
                print("Error: Passwords do not match.")
                sys.exit(1)
        else:
            password = Config.DEFAULT_ADMIN_PASSWORD

    # 3. Create or Update Account in Database
    print("\n========================================================")
    print("NIDS SECURITY: Provisioning Administrator Account")
    print("========================================================")
    print(f"Target Database: {Config.SQLALCHEMY_DATABASE_URI}")
    print(f"Username       : {username}")
    print(f"Role           : {args.role}")

    with app.app_context():
        user, created = create_or_update_user(
            username=username,
            password=password,
            role=args.role
        )

        action = "Created new" if created else "Updated existing"
        print(f"\n[SUCCESS] {action} administrator account '{user.username}' successfully.")
        print(f"[STATUS] Password securely hashed using: {user.password_hash.split('$')[0]}")
        print("========================================================\n")


if __name__ == '__main__':
    main()
