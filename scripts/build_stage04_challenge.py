#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Stage 04 — The Banker's Secret Code
Challenge Artefact Builder (Developer Only)

Builds the encoded evidence file: platform/static/downloads/stage04_banker_message.txt

Encoding chain (applied in this order):
    1. ROT13 — classical letter substitution (A↔N, B↔O, …)
    2. Hex   — each byte of the ROT13'd text is converted to two hex digits

The participant must reverse these steps:
    1. Hex decode the file contents
    2. Apply ROT13 to recover the original plaintext and flag

Usage:
    python scripts/generate_stage04.py

DO NOT expose this script or its output logic to CTF participants.
"""

import codecs
import os
import sys

# ============================================================
# Original Plaintext Message (contains the flag)
# ============================================================
PLAINTEXT_MESSAGE = """============================================================
  CYBERBANK INTERNAL — CLASSIFIED COMMUNICATION INTERCEPT
  INCIDENT RESPONSE CASE: CB-IR-2026-0447
  CLASSIFICATION: RESTRICTED / EYES ONLY
============================================================

FROM: Director Marcus Holloway <m.holloway@cyberbank-internal.local>
TO:   Director Elena Voss <e.voss@cyberbank-internal.local>
DATE: 2026-08-14 03:42 UTC
SUBJECT: Re: Offshore Authorization Override

Elena,

The authorization transfer codes for the Cayman trust
relay have been rotated as of midnight. The new master
override sequence is embedded below for your offline
vault terminal.

Do NOT transmit this over the standard SWIFT messaging
channel. Use the air-gapped terminal in Sub-Level 3.

Authorization Code:
    CBANK{CRYPTO_b4nk3r_c1ph3r_br34k_3310}

Destroy this message after memorizing the code. If
internal audit flags the rotation, attribute it to the
quarterly key ceremony schedule.

— M. Holloway
   Chief Financial Operations Director
   CyberBank Holdings AG

============================================================
  END OF INTERCEPTED COMMUNICATION
  RECOVERED BY: INCIDENT RESPONSE UNIT ALPHA
  INTEGRITY HASH: SHA256 — [REDACTED]
============================================================
"""


def apply_rot13(text: str) -> str:
    """Apply ROT13 substitution cipher to the input text."""
    return codecs.encode(text, "rot_13")


def apply_hex_encode(text: str) -> str:
    """Encode text as a continuous hex string (lowercase)."""
    return text.encode("utf-8").hex()


def format_hex_output(hex_string: str, width: int = 64) -> str:
    """Break a long hex string into fixed-width lines for readability."""
    lines = [hex_string[i:i + width] for i in range(0, len(hex_string), width)]
    return "\n".join(lines)


def generate_challenge_file(output_path: str) -> None:
    """Generate the Stage 04 challenge artefact."""
    # Step 1: ROT13
    rot13_text = apply_rot13(PLAINTEXT_MESSAGE)

    # Step 2: Hex encode
    hex_encoded = apply_hex_encode(rot13_text)

    # Format for the evidence file
    file_content = (
        "# CYBERBANK INCIDENT RESPONSE — RECOVERED DATA FRAGMENT\n"
        "# Case: CB-IR-2026-0447\n"
        "# Source: Network tap on Director-level VPN tunnel\n"
        "# Status: Encoded / Obfuscated — analysis required\n"
        "# Analyst Notes: Multiple transformation layers detected.\n"
        "#                Raw intercepted byte stream follows.\n"
        "#\n"
        "# ========================================================\n\n"
        + format_hex_output(hex_encoded)
        + "\n"
    )

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(file_content)

    print(f"[+] Stage 04 challenge artefact generated: {output_path}")
    print(f"    Plaintext size : {len(PLAINTEXT_MESSAGE)} bytes")
    print(f"    ROT13 size     : {len(rot13_text)} bytes")
    print(f"    Hex output size: {len(hex_encoded)} hex chars")


def main():
    # Resolve output path relative to project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    output_path = os.path.join(
        project_root, "platform", "static", "downloads", "stage04_banker_message.txt"
    )

    generate_challenge_file(output_path)

    # Verification: decode and check flag is recoverable
    print("\n[*] Verification — decoding generated artefact...")
    with open(output_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Strip comment/header lines
    hex_data = "".join(
        line.strip() for line in lines if line.strip() and not line.startswith("#")
    )

    # Reverse: hex decode → ROT13
    decoded_bytes = bytes.fromhex(hex_data).decode("utf-8")
    recovered = codecs.decode(decoded_bytes, "rot_13")

    flag = "CBANK{CRYPTO_b4nk3r_c1ph3r_br34k_3310}"
    if flag in recovered:
        print(f"[+] PASS: Flag '{flag}' successfully recovered from artefact.")
    else:
        print(f"[-] FAIL: Flag not found in recovered plaintext!")
        sys.exit(1)


if __name__ == "__main__":
    main()
