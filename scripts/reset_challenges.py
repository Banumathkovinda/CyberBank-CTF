#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Group Infrastructure: Challenge Reset & Environment Recovery Suite

Course / Module: IE3132 Penetration Testing — Assignment 02
Role: Shared Group Infrastructure Support Script (Not counted as individual script)

Modes of Operation:
    1. Challenge-Only Reset (--challenges-only or default):
       - Regenerates all local challenge artifacts and evidence files (Stages 1, 2, 4, 5).
       - Restarts vulnerable challenge containers (stage3-web, blackvault).
       - Preserves participant database records, registered accounts, and scores!

    2. Full Development Reset (--full-reset):
       - Regenerates all challenge artifacts.
       - Rebuilds and restarts all Docker containers.
       - WARNING: Cleans and re-seeds database challenges and hint records.
       - Requires explicit confirmation (--confirm) to avoid accidental progress loss.

Usage:
    python scripts/reset_challenges.py                    # Challenge-only reset
    python scripts/reset_challenges.py --challenges-only  # Explicit challenge reset
    python scripts/reset_challenges.py --full-reset       # Full reset with prompt
    python scripts/reset_challenges.py --full-reset --confirm
"""

import os
import sys
import subprocess
import argparse

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def run_cmd(cmd: list[str], desc: str, cwd: str = REPO_ROOT) -> bool:
    """Execute a shell command with status logging."""
    print(f"[*] {desc}...", end=" ", flush=True)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=45
        )
        if proc.returncode == 0:
            print(f"{Colors.GREEN}[OK]{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[FAILED]{Colors.RESET}")
            if proc.stderr:
                print(f"    Error: {proc.stderr.strip()[:200]}")
            return False
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET}: {e}")
        return False


def reset_stage1_osint() -> bool:
    """Regenerate Stage 01 OSINT evidence dossier files."""
    script_path = os.path.join(REPO_ROOT, "challenges", "stage1_osint", "build_dossier.py")
    if os.path.exists(script_path):
        return run_cmd([sys.executable, script_path], "Rebuilding Stage 01 OSINT Dossier")
    return True


def reset_stage2_stego() -> bool:
    """Regenerate Stage 02 Steganography PNG artifact."""
    script_path = os.path.join(REPO_ROOT, "challenges", "stage2_stego", "generate_artifact.py")
    if os.path.exists(script_path):
        return run_cmd([sys.executable, script_path], "Rebuilding Stage 02 Stego PNG Asset")
    return True


def reset_stage4_crypto() -> bool:
    """Regenerate Stage 04 Cryptographic encoded file."""
    script_path = os.path.join(REPO_ROOT, "scripts", "build_stage04_challenge.py")
    if os.path.exists(script_path):
        return run_cmd([sys.executable, script_path], "Rebuilding Stage 04 Banker Cipher File")
    return True


def reset_stage5_forensics() -> bool:
    """Regenerate Stage 05 Forensics PCAP and log archive."""
    script_path = os.path.join(REPO_ROOT, "scripts", "generate_stage05_evidence.py")
    if os.path.exists(script_path):
        return run_cmd([sys.executable, script_path], "Rebuilding Stage 05 Forensic Evidence Package")
    return True


def restart_challenge_containers() -> bool:
    """Restart vulnerable microservice containers (Stage 3 web portal and Stage 6 Linux)."""
    return run_cmd(
        ["docker", "compose", "restart", "stage3-web", "blackvault"],
        "Restarting Challenge Docker Containers (stage3-web, blackvault)"
    )


def full_docker_rebuild() -> bool:
    """Rebuild all Docker containers from scratch."""
    return run_cmd(
        ["docker", "compose", "up", "-d", "--build"],
        "Rebuilding & Restarting All Docker Services"
    )


def reseed_database() -> bool:
    """Reseed challenge definitions and hints in platform database."""
    script_path = os.path.join(REPO_ROOT, "platform", "seed.py")
    if os.path.exists(script_path):
        return run_cmd([sys.executable, script_path], "Re-seeding Platform Challenge Database")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="CyberBank: Operation BlackVault - Challenge Reset Utility"
    )
    parser.add_argument(
        "--challenges-only",
        action="store_true",
        default=True,
        help="Reset challenge files and restart vulnerable containers (preserves user data)"
    )
    parser.add_argument(
        "--full-reset",
        action="store_true",
        help="Full development reset: rebuilds all containers and reseeds database"
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Bypass interactive confirmation for full reset"
    )
    args = parser.parse_args()

    print("=" * 65)
    print(f"{Colors.BOLD}{Colors.CYAN} CyberBank: Operation BlackVault - Reset & Recovery Suite{Colors.RESET}")
    print("=" * 65)

    if args.full_reset:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[!] WARNING: FULL DEVELOPMENT RESET REQUESTED [!]{Colors.RESET}")
        print("This action will:")
        print("  - Re-generate all challenge files")
        print("  - Rebuild all Docker containers")
        print("  - Re-seed challenge tables in database")
        print("Unsaved active session tokens may be disrupted.\n")

        if not args.confirm:
            try:
                reply = input("Are you sure you want to proceed with FULL reset? [y/N]: ").strip().lower()
                if reply not in ("y", "yes"):
                    print("[-] Full reset aborted by user.")
                    sys.exit(0)
            except (KeyboardInterrupt, EOFError):
                print("\n[-] Aborted.")
                sys.exit(0)

        # Execute Full Reset
        print(f"\n{Colors.BOLD}[Executing Full Development Reset]{Colors.RESET}")
        reset_stage1_osint()
        reset_stage2_stego()
        reset_stage4_crypto()
        reset_stage5_forensics()
        full_docker_rebuild()
        reseed_database()
        print(f"\n{Colors.BOLD}{Colors.GREEN}[DONE] Full Development Reset Complete!{Colors.RESET}\n")

    else:
        # Execute Challenge-Only Reset
        print(f"\n{Colors.BOLD}[Executing Challenge-Only Reset (User Data Preserved)]{Colors.RESET}")
        s1 = reset_stage1_osint()
        s2 = reset_stage2_stego()
        s4 = reset_stage4_crypto()
        s5 = reset_stage5_forensics()
        c_res = restart_challenge_containers()

        print("-" * 65)
        if all([s1, s2, s4, s5, c_res]):
            print(f"{Colors.BOLD}{Colors.GREEN}[DONE] Challenge Environment Restored Successfully!{Colors.RESET}")
            print("Note: Participant database records, registered accounts, and scores are preserved.")
        else:
            print(f"{Colors.BOLD}{Colors.YELLOW}[!] Challenge Reset completed with warnings. Verify logs above.{Colors.RESET}")
        print("-" * 65 + "\n")


if __name__ == "__main__":
    main()
