#!/usr/bin/env python3
"""
CyberBank: Operation BlackVault
Stage 2: Steganography Artifact Generator

Generates a valid, harmless PNG graphic with:
    1. Visual promotional content ("CyberBank BlackVault High-Yield Promo")
    2. Embedded PNG text chunk / EXIF Comment: "ARCHIVE_KEY: spectrum_vault_4491"
    3. Concatenated / appended ZIP archive containing secret_ledger.txt with CBANK{STEGO_h1dd3n_sp3ctrum_4491}
"""

import os
import io
import struct
import zlib
import zipfile


def create_base_png(width=800, height=450):
    """
    Generate raw binary PNG without external heavy dependencies.
    Creates a styled 800x450 dark copper/emerald branded graphic.
    """
    def chunk(tag, data):
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return length + tag + data + crc

    # PNG Magic Header
    header = b"\x89PNG\r\n\x1a\n"

    # IHDR Chunk
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))

    # Text Chunk (tEXt metadata)
    text_data = b"Comment\x00ARCHIVE_KEY: spectrum_vault_4491\x00Description\x00CyberBank Promotional Media Asset #4491"
    text_chunk = chunk(b"tEXt", text_data)

    # Pixel Data (Dark metallic gradient with neon green accent border)
    raw_pixels = bytearray()
    for y in range(height):
        raw_pixels.append(0)  # Filter type 0 (None)
        for x in range(width):
            # Gradient copper to dark charcoal
            r = min(255, int(15 + (x / width) * 45))
            g = min(255, int(18 + (y / height) * 35))
            b = min(255, int(22 + ((x + y) / (width + height)) * 30))

            # Border effect
            if x < 4 or x >= width - 4 or y < 4 or y >= height - 4:
                r, g, b = 57, 255, 20  # Neon green accent border

            raw_pixels.extend([r, g, b])

    compressed_data = zlib.compress(bytes(raw_pixels), 9)
    idat = chunk(b"IDAT", compressed_data)

    # IEND Chunk
    iend = chunk(b"IEND", b"")

    return header + ihdr + text_chunk + idat + iend


def create_secret_zip():
    """
    Generate an embedded zip archive with secret_ledger.txt.
    Uses ZIP_STORED so standard carving, binwalk, and strings can extract it cleanly.
    """
    ledger_content = (
        "================================================================\n"
        "CYBERBANK CONFIDENTIAL WIRE TRANSACTION LEDGER\n"
        "INTERNAL AUDIT IDENTIFIER: #BK-4491-STEGO\n"
        "STATUS: COMPROMISED INTERNAL TRANSFER\n"
        "ACCOUNT: 9941-002-881\n"
        "ROUTING: CB-GLOBAL-WIRE-884\n"
        "AUTHORIZATION KEY: spectrum_vault_4491\n\n"
        "CLEARANCE FLAG: CBANK{STEGO_h1dd3n_sp3ctrum_4491}\n"
        "================================================================\n"
    ).encode("utf-8")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("secret_ledger.txt", ledger_content)

    return zip_buffer.getvalue()


def build_stego_asset():
    """
    Assemble the final polyglot PNG + ZIP artifact.
    """
    base_png = create_base_png()
    secret_zip = create_secret_zip()

    # Append ZIP directly after PNG IEND chunk
    polyglot_asset = base_png + secret_zip

    # Save to challenge artifacts and platform static downloads
    base_dir = os.path.dirname(os.path.abspath(__file__))
    artifacts_dir = os.path.join(base_dir, "artifacts")
    downloads_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "platform", "static", "downloads"))

    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)

    art_file = os.path.join(artifacts_dir, "cyberbank_promo_asset.png")
    dl_file = os.path.join(downloads_dir, "cyberbank_promo_asset.png")

    with open(art_file, "wb") as f:
        f.write(polyglot_asset)
    with open(dl_file, "wb") as f:
        f.write(polyglot_asset)

    print(f"[OK] Generated Stage 2 Stego artifact:")
    print(f"     Artifact: {art_file} ({len(polyglot_asset)} bytes)")
    print(f"     Platform Download: {dl_file}")


if __name__ == "__main__":
    build_stego_asset()
