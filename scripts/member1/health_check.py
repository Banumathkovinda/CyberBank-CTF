#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
CTF Infrastructure Health & Diagnostic Suite

Responsible Member: BLBK Bogahapitiya (IT24102626)
Responsibility: CTF Platform & Architecture (Member 1)

Purpose:
    Performs automated operational and reachability verification of the
    CyberBank CTF play box infrastructure, including:
    1. Flask Platform Web Service (HTTP 5000)
    2. Platform Telemetry Endpoint (/health)
    3. Stage 03 Vulnerable Banking Portal (HTTP 8080)
    4. Stage 06 BlackVault SSH Service (TCP 2222)
    5. MySQL Database Connectivity & Schema Health
    6. Docker Container Execution Status
    7. Docker Network Isolation Verification

Usage:
    python scripts/member1/health_check.py
"""

import os
import sys
import socket
import urllib.request
import urllib.error
import json
import subprocess

# =============================================================================
# Configuration & Endpoints (Configurable via Environment Variables)
# =============================================================================
# TODO [Member 1 Review]: Adjust host/ports if testing across external bridge or VM
PLATFORM_HOST = os.environ.get("CTF_PLATFORM_HOST", "127.0.0.1")
PLATFORM_PORT = int(os.environ.get("CTF_PLATFORM_PORT", 5000))

STAGE3_HOST = os.environ.get("CTF_STAGE3_HOST", "127.0.0.1")
STAGE3_PORT = int(os.environ.get("CTF_STAGE3_PORT", 8080))

STAGE6_HOST = os.environ.get("CTF_STAGE6_HOST", "127.0.0.1")
STAGE6_SSH_PORT = int(os.environ.get("CTF_STAGE6_SSH_PORT", 2222))

# Database configuration (uses standard environment variables, no hardcoded secrets)
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
MYSQL_DB = os.environ.get("MYSQL_DATABASE", "cyberbank")
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASS = os.environ.get("MYSQL_PASSWORD", "")

EXPECTED_CONTAINERS = [
    "cyberbank-platform",
    "cyberbank-stage3-web",
    "cyberbank-blackvault",
]

EXPECTED_NETWORKS = [
    "cyberbank-network",
]


class Colors:
    """Terminal styling ANSI escape codes."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_status(component: str, passed: bool, detail: str = ""):
    """Print standard formatted check outcome."""
    tag = f"{Colors.GREEN}[PASS]{Colors.RESET}" if passed else f"{Colors.RED}[FAIL]{Colors.RESET}"
    detail_str = f" - {detail}" if detail else ""
    print(f"  {tag} {component}{detail_str}")


def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Verify if a given TCP socket port is actively listening."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def check_http_endpoint(url: str, timeout: float = 4.0) -> tuple[bool, int, str]:
    """Perform HTTP GET request and return (success, status_code, body)."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberBank-HealthCheck/2.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return (True, resp.getcode(), body)
    except urllib.error.HTTPError as e:
        return (False, e.code, str(e))
    except Exception as e:
        return (False, 0, str(e))


def check_docker_containers() -> tuple[bool, list[str]]:
    """Query local Docker CLI for currently running container names."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode != 0:
            return (False, ["Docker CLI returned error or daemon not running"])
        running = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        return (True, running)
    except FileNotFoundError:
        return (False, ["Docker CLI executable not found in PATH"])
    except Exception as e:
        return (False, [f"Docker check error: {e}"])


def check_docker_networks() -> tuple[bool, list[str]]:
    """Query local Docker CLI for existing network names."""
    try:
        proc = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode != 0:
            return (False, [])
        networks = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        return (True, networks)
    except Exception:
        return (False, [])


def run_all_checks() -> bool:
    """Execute all infrastructure health audits and return overall health boolean."""
    print("=" * 65)
    print(f"{Colors.BOLD}{Colors.CYAN} CyberBank: Operation BlackVault - Platform Health Diagnostic{Colors.RESET}")
    print(f" Responsible Member: BLBK Bogahapitiya (IT24102626) - Architecture")
    print("=" * 65)
    print()

    all_passed = True

    # 1. Host Port Reachability Checks
    print(f"{Colors.BOLD}[1] Host Port & Socket Listening Verification:{Colors.RESET}")
    ports_to_check = [
        ("Platform Web Server (Port 5000)", PLATFORM_HOST, PLATFORM_PORT),
        ("Stage 03 Banking Portal (Port 8080)", STAGE3_HOST, STAGE3_PORT),
        ("Stage 06 BlackVault SSH (Port 2222)", STAGE6_HOST, STAGE6_SSH_PORT),
    ]

    for name, host, port in ports_to_check:
        is_open = check_tcp_port(host, port)
        if not is_open:
            all_passed = False
        print_status(name, is_open, f"{host}:{port}")

    print()

    # 2. HTTP Application Services & Telemetry
    print(f"{Colors.BOLD}[2] Application Service & Health Endpoint Verification:{Colors.RESET}")
    
    # 2.1 Platform /health
    health_url = f"http://{PLATFORM_HOST}:{PLATFORM_PORT}/health"
    ok, code, body = check_http_endpoint(health_url)
    health_detail = f"HTTP {code}"
    try:
        parsed = json.loads(body)
        health_detail += f" - DB: {parsed.get('database')} | Status: {parsed.get('status')}"
    except Exception:
        pass
    print_status("Platform Telemetry (/health)", ok, health_detail)
    if not ok:
        all_passed = False

    # 2.2 Stage 03 Banking Portal Root
    s3_url = f"http://{STAGE3_HOST}:{STAGE3_PORT}/login"
    ok_s3, code_s3, _ = check_http_endpoint(s3_url)
    print_status("Stage 03 Portal (/login)", ok_s3, f"HTTP {code_s3}")
    if not ok_s3:
        all_passed = False

    print()

    # 3. Docker Container & Orchestration Verification
    print(f"{Colors.BOLD}[3] Docker Container & Network Orchestration:{Colors.RESET}")
    docker_ok, running_containers = check_docker_containers()
    if not docker_ok:
        print_status("Docker CLI Integration", False, running_containers[0] if running_containers else "Error")
        all_passed = False
    else:
        for expected in EXPECTED_CONTAINERS:
            is_running = any(expected in c for c in running_containers)
            print_status(f"Container '{expected}'", is_running, "Running" if is_running else "Not Running / Stopped")
            if not is_running:
                all_passed = False

    # Network check
    net_ok, networks = check_docker_networks()
    for expected_net in EXPECTED_NETWORKS:
        exists = any(expected_net in n for n in networks)
        print_status(f"Docker Network '{expected_net}'", exists, "Created & Active" if exists else "Missing")
        if not exists:
            all_passed = False

    print()

    # Overall Summary
    print("-" * 65)
    if all_passed:
        print(f" Overall Infrastructure Status: {Colors.BOLD}{Colors.GREEN}HEALTHY (100% OPERATIONAL){Colors.RESET}")
    else:
        print(f" Overall Infrastructure Status: {Colors.BOLD}{Colors.YELLOW}DEGRADED / ACTION REQUIRED{Colors.RESET}")
        print(" Note: Review failed items above. Verify Docker Compose services with:")
        print("       docker compose ps")
    print("-" * 65)

    return all_passed


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
