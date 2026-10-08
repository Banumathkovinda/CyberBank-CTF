"""
CyberBank: Operation BlackVault
Stage 2 — Hidden in Plain Sight (Steganography) End-to-End Test Suite

Tests:
    1. Steganographic PNG artifact exists, has valid magic bytes, and has appended zip
    2. Metadata comment and embedded secret_ledger.txt contain the Stage 2 flag
    3. The recovered flag matches Stage 2 flag_hash in database
    4. Stage 2 is locked (HTTP 403) until Stage 1 is completed
    5. Solving Stage 1 unlocks Stage 2 (HTTP 200)
    6. Submitting recovered Stage 2 flag awards +100 PTS and unlocks Stage 3
"""

import os
import io
import sys
import zipfile
import re
import pytest

# Ensure platform module is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app
from extensions import db
from models import User, Challenge, Submission, Score, Log
from seed import seed_challenges
from flag_service import verify_flag


@pytest.fixture
def app():
    """Create test application configured with in-memory database."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        seed_challenges()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def player_user(app):
    """Create an authenticated test player."""
    with app.app_context():
        user = User(
            username="stego_analyst",
            email="stego@blackvault.local",
            role="player",
        )
        user.set_password("StegoSecPass2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_user(client, username="stego_analyst", password="StegoSecPass2026!"):
    """Helper to log in player."""
    return client.post("/login", json={"identifier": username, "password": password})


# =========================================================================
# 1. Steganography Artifact Integrity Tests
# =========================================================================

def test_stego_artifact_file_integrity():
    """Verify the carrier PNG exists, has valid PNG magic bytes, and embedded ZIP."""
    png_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads", "cyberbank_promo_asset.png"
    ))
    assert os.path.exists(png_path), f"Stego asset missing at {png_path}"
    assert os.path.getsize(png_path) > 5000

    with open(png_path, "rb") as f:
        data = f.read()

    # 1. Verify PNG header
    assert data.startswith(b"\x89PNG\r\n\x1a\n")

    # 2. Verify metadata comment
    assert b"ARCHIVE_KEY: spectrum_vault_4491" in data

    # 3. Locate ZIP magic bytes PK\x03\x04
    zip_offset = data.find(b"PK\x03\x04")
    assert zip_offset > 0

    # 4. Extract embedded zip
    zip_bytes = data[zip_offset:]
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "secret_ledger.txt" in namelist
        ledger_text = zf.read("secret_ledger.txt").decode("utf-8")
        assert "CBANK{STEGO_h1dd3n_sp3ctrum_4491}" in ledger_text


# =========================================================================
# 2. Progressive Access Control & Solve Flow Tests
# =========================================================================

def test_stage2_locked_before_stage1_solved(client, player_user):
    """Direct access to Stage 2 must be rejected (HTTP 403) before Stage 1 is solved."""
    login_user(client)

    # API JSON access
    resp = client.get("/challenges/2", headers={"Accept": "application/json"})
    assert resp.status_code == 403
    assert "locked" in resp.get_json()["message"].lower()

    # Submission attempt to locked Stage 2 is rejected
    sub_resp = client.post(
        "/challenges/2/submit",
        json={"flag": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}"}
    )
    assert sub_resp.status_code == 403


def test_stage2_end_to_end_solve_and_unlock_stage3(client, player_user, app):
    """
    Test complete Stage 2 workflow:
        1. Solve Stage 1 -> Unlocks Stage 2
        2. Access Stage 2 -> Retrieves briefing and asset download link
        3. Carve flag from cyberbank_promo_asset.png
        4. Submit Stage 2 flag -> Awards +100 PTS
        5. Stage 3 (Broken Banking Portal) is unlocked
    """
    login_user(client)

    # 1. Solve Stage 1
    s1_resp = client.post("/challenges/1/submit", json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"})
    assert s1_resp.status_code == 200

    # 2. Stage 2 is now available
    view_resp = client.get("/challenges/2")
    assert view_resp.status_code == 200
    html = view_resp.get_data(as_text=True)
    assert "Hidden in Plain Sight" in html
    assert "cyberbank_promo_asset.png" in html
    assert "Download Stego Media" in html

    # 3. Extract flag from static download file
    png_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads", "cyberbank_promo_asset.png"
    ))
    with open(png_path, "rb") as f:
        content = f.read()
    flag_match = re.search(r"CBANK\{STEGO_[A-Za-z0-9_-]+\}", content.decode("latin1"))
    assert flag_match is not None
    recovered_flag = flag_match.group(0)

    # 4. Verify against DB
    with app.app_context():
        c2 = Challenge.query.filter_by(stage_number=2).first()
        assert verify_flag(recovered_flag, c2.flag_hash) is True

    # 5. Submit Stage 2 flag
    s2_resp = client.post("/challenges/2/submit", json={"flag": recovered_flag})
    assert s2_resp.status_code == 200
    s2_data = s2_resp.get_json()
    assert s2_data["status"] == "success"
    assert s2_data["points_awarded"] == 100
    # Total score: 100 (Stage 1) + 100 (Stage 2) = 200
    assert s2_data["new_total_score"] == 200

    # 6. Verify Stage 3 is now unlocked
    c3_resp = client.get("/challenges/3", headers={"Accept": "application/json"})
    assert c3_resp.status_code == 200
    assert c3_resp.get_json()["challenge"]["status"] == "available"
    assert c3_resp.get_json()["challenge"]["title"] == "Broken Banking Portal"
