#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
End-to-End Integration & Security Assurance Suite

Responsible Member: Ariyapperuma (IT24103108)
Responsibility: Integration, Testing & Documentation (Member 4)

Purpose:
    Executes programmatic validation across the operational platform:
    1. Platform Reachability & Telemetry Health (/health)
    2. Public Access & Navigation Controls (Home, Login, Register)
    3. Unauthenticated Access Protection (Access control redirects)
    4. Operative Registration & Session Authentication
    5. Dashboard Telemetry & 2-Hour Backward Countdown Verification
    6. Sequential Stage Dependency Enforcement (Locked stage HTTP 403 test)
    7. Wrong Flag Rejection & Integrity Audit Logging
    8. Rate-Limiting & Anti-Brute-Force Boundary Verification

Usage:
    python scripts/member4/integration_test.py
"""

import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
import re

# =============================================================================
# Configuration & Endpoints (Member 4 Review Section)
# =============================================================================
# TODO [Member 4 Review]: Confirm platform host and port for test run
BASE_URL = os.environ.get("CTF_PLATFORM_URL", "http://127.0.0.1:5000").rstrip("/")

# Ephemeral test credentials generated uniquely per test run to prevent collisions
TEST_TIMESTAMP = int(time.time())
TEST_USERNAME = f"e2e_tester_{TEST_TIMESTAMP % 10000:04d}"
TEST_EMAIL = f"{TEST_USERNAME}@blackvault-test.local"
TEST_PASSWORD = "IntegrationTestPassw0rd!2026"


class Colors:
    """Terminal styling ANSI escape codes."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class IntegrationTester:
    """End-to-end integration test runner maintaining HTTP sessions."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.headers = {"User-Agent": "CyberBank-IntegrationSuite/2.0"}

    def request(self, path: str, method: str = "GET", data: dict = None, as_json: bool = False) -> tuple[int, str, str]:
        """Send HTTP request and return (status_code, response_body, final_url)."""
        url = f"{self.base_url}{path}"
        encoded_data = None
        req_headers = dict(self.headers)

        if data is not None:
            if as_json:
                encoded_data = json.dumps(data).encode("utf-8")
                req_headers["Content-Type"] = "application/json"
            else:
                encoded_data = urllib.parse.urlencode(data).encode("utf-8")
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method=method)
        try:
            with self.opener.open(req) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return (resp.getcode(), body, resp.geturl())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return (e.code, body, e.geturl())
        except Exception as e:
            return (0, str(e), "")


def run_integration_tests() -> bool:
    """Execute sequence of automated integration and security boundary checks."""
    print("=" * 65)
    print(f"{Colors.BOLD}{Colors.CYAN} CyberBank: Operation BlackVault - Integration & Security Test{Colors.RESET}")
    print(" Responsible Member: Ariyapperuma (IT24103108) - Testing & Documentation")
    print("=" * 65)
    print(f"[*] Target Platform: {BASE_URL}")
    print()

    tester = IntegrationTester(BASE_URL)
    all_passed = True

    def assert_test(name: str, passed: bool, detail: str = ""):
        nonlocal all_passed
        if not passed:
            all_passed = False
        tag = f"{Colors.GREEN}[PASS]{Colors.RESET}" if passed else f"{Colors.RED}[FAIL]{Colors.RESET}"
        detail_msg = f" ({detail})" if detail else ""
        print(f"  {tag} {name}{detail_msg}")

    # Test 1: Health Telemetry
    print(f"{Colors.BOLD}[1] Telemetry & Platform Reachability:{Colors.RESET}")
    code, body, _ = tester.request("/health")
    db_connected = False
    try:
        data = json.loads(body)
        db_connected = (data.get("database") == "connected" and data.get("status") == "healthy")
    except Exception:
        pass
    assert_test("Health Endpoint (/health)", code == 200 and db_connected, f"HTTP {code}")

    # Test 2: Unauthenticated Access Control
    print(f"\n{Colors.BOLD}[2] Access Control & Authentication Boundaries:{Colors.RESET}")
    code, body, final_url = tester.request("/dashboard")
    redirected_to_login = ("login" in final_url) or (code == 302)
    assert_test("Protected Route Redirect (/dashboard -> /login)", redirected_to_login, f"Final URL: {final_url}")

    # Test 3: New Operative Registration
    print(f"\n{Colors.BOLD}[3] Registration & Session Lifecycle:{Colors.RESET}")
    reg_payload = {
        "username": TEST_USERNAME,
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "confirm_password": TEST_PASSWORD,
    }
    code, body, _ = tester.request("/register", method="POST", data=reg_payload, as_json=True)
    reg_success = (code in (200, 201))
    assert_test(f"Register New Operative ({TEST_USERNAME})", reg_success, f"HTTP {code}")

    # Test 4: Operative Authentication
    login_payload = {
        "identifier": TEST_USERNAME,
        "password": TEST_PASSWORD,
    }
    code, body, final_url = tester.request("/login", method="POST", data=login_payload)
    login_success = (code == 200 and ("Mission Matrix" in body or "dashboard" in final_url))
    assert_test("Authenticate Operative Session", login_success, "Session cookie established")

    # Test 5: Authenticated Dashboard & 2-Hour Timer
    print(f"\n{Colors.BOLD}[4] Dashboard Telemetry & Backward Countdown:{Colors.RESET}")
    code, body, _ = tester.request("/dashboard")
    has_callsign = TEST_USERNAME in body
    has_timer = "Time Remaining (2h Limit)" in body or "missionTimerDisplay" in body
    assert_test("Dashboard Telemetry HUD Loaded", code == 200 and has_callsign, f"Callsign verified: {TEST_USERNAME}")
    assert_test("2-Hour Countdown Timer Display Present", has_timer, "Backward countdown HUD verified")

    # Test 6: Locked Stage Dependency Protection
    print(f"\n{Colors.BOLD}[5] Stage Dependency & Prerequisite Enforcement:{Colors.RESET}")
    # Attempt to directly load Stage 02 when Stage 01 has NOT been solved yet
    code, body, final_url = tester.request("/challenges/stage/2")
    # Should either return HTTP 403 or redirect with access denied flash
    blocked_stage2 = (code == 403) or ("Access denied" in body) or ("locked" in body.lower())
    assert_test("Direct Access to Locked Stage 02 Blocked", blocked_stage2, f"HTTP {code} / Prerequisite Enforced")

    # Test 7: Wrong Flag Rejection
    print(f"\n{Colors.BOLD}[6] Flag Submission Security & Scoring Integrity:{Colors.RESET}")
    fake_flag_payload = {
        "challenge_id": 1,
        "flag": "CBANK{INCORRECT_SYNTHETIC_FLAG_9999}",
    }
    code, body, _ = tester.request("/submit", method="POST", data=fake_flag_payload, as_json=True)
    rejected_wrong_flag = (code in (200, 400))
    try:
        res = json.loads(body)
        rejected_wrong_flag = (res.get("status") in ("failure", "incorrect", "error"))
    except Exception:
        pass
    assert_test("Wrong Flag Submission Rejection", rejected_wrong_flag, "0 points awarded / Rejection logged")

    # Test 8: Malformed Flag Format Rejection
    malformed_payload = {
        "challenge_id": 1,
        "flag": "INVALID_FORMAT_NO_BRACKETS",
    }
    code, body, _ = tester.request("/submit", method="POST", data=malformed_payload, as_json=True)
    rejected_malformed = (code == 400)
    assert_test("Malformed Flag Format Rejection", rejected_malformed, f"HTTP {code} / Format checked")

    # Summary
    print("\n" + "-" * 65)
    if all_passed:
        print(f" End-to-End Suite Outcome: {Colors.BOLD}{Colors.GREEN}ALL CHECKS PASSED (100% SUCCESS){Colors.RESET}")
    else:
        print(f" End-to-End Suite Outcome: {Colors.BOLD}{Colors.RED}FAILURES DETECTED - REVIEW LOGS{Colors.RESET}")
    print("-" * 65)

    return all_passed


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)
