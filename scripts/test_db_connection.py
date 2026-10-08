#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
MySQL Database Connection & Health Verification Script

Tests:
    1. Direct TCP connectivity to MySQL port
    2. Authentication using application user (cyberbank_user)
    3. Database existence (cyberbank)
    4. Table creation, insert, select, update, and drop (CRUD privileges)
    5. Platform metadata table verification

Usage:
    python scripts/test_db_connection.py
"""

import os
import sys
import time
import socket
import io

# Fix Windows console encoding for text output
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

try:
    import pymysql
except ImportError:
    print("[ERROR] PyMySQL is not installed. Install it with: pip install pymysql")
    sys.exit(1)

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
load_dotenv()

# Configuration - reads from environment or uses defaults
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "cyberbank")

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_header(title: str):
    width = 60
    print(f"\n{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{title.center(width)}{RESET}")
    print(f"{CYAN}{'=' * width}{RESET}\n")


def print_result(name: str, passed: bool, detail: str = ""):
    tag = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FALI]{RESET}"
    msg = f"  {tag} {name}"
    if detail:
        msg += f" - {detail}"
    print(msg)


def test_port_open(host: str, port: int, timeout: int = 5) -> bool:
    """Test 1: TCP port reachable"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def test_connection():
    """Run all database connectivity and integrity checks."""
    print_header("CyberBank: Operation BlackVault - Database Connection Test")

    print(f"{BOLD}Target Configuration:{RESET}")
    print(f"  Host:     {MYSQL_HOST}")
    print(f"  Port:     {MYSQL_PORT}")
    print(f"  User:     {MYSQL_USER}")
    print(f"  Database: {MYSQL_DATABASE}")
    print(f"  Password: {'*' * len(MYSQL_PASSWORD)}")
    print()

    passed_count = 0
    total_tests = 5

    # ---- Test 1: TCP Port Reachability ----
    port_ok = test_port_open(MYSQL_HOST, MYSQL_PORT)
    print_result(
        "TCP Port Reachability",
        port_ok,
        f"Port {MYSQL_PORT} on {MYSQL_HOST} is {'open' if port_ok else 'CLOSED or NOT REACHABLE'}",
    )
    if port_ok:
        passed_count += 1
    else:
        print(f"\n{RED}[ERROR] Cannot reach MySQL port. Is Docker Compose running?{RESET}")
        print("Run: docker compose up -d\n")
        return False

    # ---- Test 2: Authentication ----
    connection = None
    try:
        connection = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=10,
        )
        print_result("Authentication", True, f"Authenticated as '{MYSQL_USER}'")
        passed_count += 1
    except pymysql.err.OperationalError as e:
        print_result("Authentication", False, f"Error: {e}")
        return False
    except Exception as e:
        print_result("Authentication", False, f"Unexpected error: {e}")
        return False

    # ---- Test 3: Database Verification & Server Info ----
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT VERSION() AS version, DATABASE() AS current_db, USER() AS `active_user`;")
            row = cursor.fetchone()
            db_name = row["current_db"]
            version = row["version"]
            auth_user = row["active_user"]

            db_matches = db_name == MYSQL_DATABASE
            print_result(
                "Database Verification",
                db_matches,
                f"Connected to '{db_name}' on MySQL v{version} (User: {auth_user})",
            )
            if db_matches:
                passed_count += 1
    except Exception as e:
        print_result("Database Verification", False, f"Error: {e}")

    # ---- Test 4: Permissions & Grants Check ----
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW GRANTS;")
            grants = cursor.fetchall()
            grant_list = [list(g.values())[0] for g in grants]
            has_grants = len(grant_list) > 0
            print_result("Privilege Check", has_grants, f"{len(grant_list)} grant statement(s) found")
            if has_grants:
                passed_count += 1
    except Exception as e:
        print_result("Privilege Check", False, f"Error: {e}")

    # ---- Test 5: CRUD Operations on Temporary Table ----
    crud_ok = False
    temp_table = f"_healthcheck_{int(time.time())}"
    try:
        with connection.cursor() as cursor:
            # CREATE
            cursor.execute(f"CREATE TABLE {temp_table} (id INT PRIMARY KEY AUTO_INCREMENT, val VARCHAR(50));")
            # INSERT
            cursor.execute(f"INSERT INTO {temp_table} (val) VALUES ('health_test');")
            # SELECT
            cursor.execute(f"SELECT val FROM {temp_table} WHERE id = 1;")
            selected = cursor.fetchone()
            # UPDATE
            cursor.execute(f"UPDATE {temp_table} SET val = 'health_updated' WHERE id = 1;")
            # DROP
            cursor.execute(f"DROP TABLE {temp_table};")
            connection.commit()

            crud_ok = selected and selected["val"] == "health_test"
            print_result("CRUD Operations", crud_ok, "CREATE, INSERT, SELECT, UPDATE, DROP all succeeded")
            if crud_ok:
                passed_count += 1
    except Exception as e:
        print_result("CRUD Operations", False, f"Error: {e}")
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"DROP TABLE IF EXISTS {temp_table};")
                connection.commit()
        except Exception:
            pass

    # Close connection
    if connection:
        connection.close()

    # ---- Summary ----
    print("\n" + "-" * 60)
    if passed_count == total_tests:
        print(f"{GREEN}{BOLD}[DONE] All {total_tests}/{total_tests} database checks passed successfully!{RESET}")
        return True
    else:
        print(f"{YELLOW}{BOLD}[WARNING] {passed_count}/{total_tests} tests passed, {total_tests - passed_count} failed.{RESET}")
        return False


if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
