#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Stage 04 (The Banker's Secret Code) - Automated Solution & Decryption Suite

Responsible Member: Kumarasinghe KWTP (IT24102485)
Responsibility: Challenge Design B - Stages 4-6 (Member 3)

Challenge Domain:
    Cryptography & Data Obfuscation Analysis (Moderate - 150 Points)

Target Challenge File:
    platform/static/downloads/stage04_banker_message.txt

Encoding Layers Applied in Challenge:
    Plaintext Message
      --> Layer 1: ROT13 (Classical Alphabetical Caesar Substitution)
      --> Layer 2: Hex Encoding (Byte representation to hexadecimal stream)

Solver Decryption Pipeline:
    1. Read intercepted artifact file and filter out comment/header metadata.
    2. Normalize continuous hexadecimal byte stream.
    3. Decode hexadecimal string to intermediate byte stream.
    4. Decode intermediate UTF-8 text and apply ROT13 decryption.
    5. Search for canonical flag format (CBANK{...}) and display decrypted dispatch.

Usage:
    python scripts/member3/stage4_solver.py
"""

import os
import sys
import re
import codecs

# =============================================================================
# Configuration & File Paths (Member 3 Review Section)
# =============================================================================
# TODO [Member 3 Review]: Verify relative path to challenge artifact file
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_FILE_PATH = os.path.join(
    REPO_ROOT, "platform", "static", "downloads", "stage04_banker_message.txt"
)


class Stage4Solver:
    """Automated cryptographic analyzer and solver for Stage 04."""

    def __init__(self, file_path: str):
        self.file_path = file_path

    def load_hex_data(self) -> str:
        """Read challenge file, strip commentary and whitespace, and concatenate hex."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Challenge artifact not found at: {self.file_path}")

        hex_lines = []
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                # Skip comments and header section dividers
                if not stripped or stripped.startswith("#"):
                    continue
                hex_lines.append(stripped)

        return "".join(hex_lines)

    def decode_hex(self, hex_string: str) -> str:
        """Transform hex string into intermediate decoded text."""
        try:
            raw_bytes = bytes.fromhex(hex_string)
            return raw_bytes.decode("utf-8", errors="replace")
        except ValueError as e:
            raise ValueError(f"Hexadecimal parsing error: {e}")

    def decrypt_rot13(self, text: str) -> str:
        """Apply ROT13 decryption transformation."""
        return codecs.decode(text, "rot_13")

    def solve(self) -> tuple[str, str]:
        """Execute full decryption pipeline and extract clearance flag."""
        print(f"[*] Step 1: Loading raw intercepted data from: {os.path.basename(self.file_path)}")
        raw_hex = self.load_hex_data()
        print(f"[+] Loaded {len(raw_hex)} hexadecimal characters.")

        print("[*] Step 2: Decoding Layer 1 (Hexadecimal stream)...")
        rot13_intermediate = self.decode_hex(raw_hex)

        print("[*] Step 3: Decrypting Layer 2 (ROT13 Substitution Cipher)...")
        plaintext_message = self.decrypt_rot13(rot13_intermediate)

        # Extract flag matching CBANK{...}
        match = re.search(r"CBANK\{[a-zA-Z0-9_\-]+\}", plaintext_message)
        flag = match.group(0) if match else "FLAG_NOT_FOUND"

        return plaintext_message, flag


def main():
    print("=" * 65)
    print(" CyberBank Stage 04 (The Banker's Secret Code) - Local Solver")
    print(" Responsible Member: Kumarasinghe KWTP (IT24102485) - Stages 4-6")
    print(" Cryptographic Layers: Hexadecimal -> ROT13")
    print("=" * 65)

    target_path = os.environ.get("STAGE4_FILE_PATH", DEFAULT_FILE_PATH)
    solver = Stage4Solver(target_path)

    try:
        decrypted_text, recovered_flag = solver.solve()
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("[+] SUCCESS: Cryptographic Decryption Complete!")
    print("=" * 65)
    print(f"[+] Recovered Stage 04 Flag: {recovered_flag}\n")

    print("[*] Decrypted Message Dispatch Preview:")
    print("-" * 50)
    # Print preview lines
    for line in decrypted_text.strip().splitlines()[:15]:
        print(f"    {line}")
    print("    [... message continues ...]")
    print("-" * 50)

    print("\n[NOTE] Member 3 Verification Complete:")
    print("Submit this flag at http://localhost:5000 to advance to Stage 05.")
    sys.exit(0)


if __name__ == "__main__":
    main()
