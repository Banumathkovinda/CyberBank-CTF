#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Stage 1 Dossier Packaging Script

Bundles fictional OSINT evidence files into platform/static/downloads/stage1_digital_footprint_dossier.zip.
"""

import os
import zipfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
OUTPUT_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "platform", "static", "downloads"))
OUTPUT_ZIP = os.path.join(OUTPUT_DIR, "stage1_digital_footprint_dossier.zip")


def build_zip():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(EVIDENCE_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, EVIDENCE_DIR)
                zf.write(file_path, arcname)
                print(f"  Added: {arcname}")

    print(f"\n[OK] Dossier archive created at: {OUTPUT_ZIP} ({os.path.getsize(OUTPUT_ZIP)} bytes)")


if __name__ == "__main__":
    build_zip()
