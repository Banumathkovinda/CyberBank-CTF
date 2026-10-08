"""
CyberBank: Operation BlackVault
Stage 1 — Digital Footprint (OSINT) End-to-End Test Suite

Tests:
    1. Intelligence dossier archive exists and contains all required artifacts
    2. Evidence files contain valid fictional OSINT intelligence structures
    3. The recovered flag in 04_leaked_debug_paste.txt matches Stage 1 flag_hash
    4. End-to-end player solve flow:
        - View Stage 1 briefing
        - Download dossier artifact
        - Submit extracted token
        - Award 100 points
        - Automatically unlock Stage 2
"""

import os
import sys
import csv
import json
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
            username="osint_investigator",
            email="osint@blackvault.local",
            role="player",
        )
        user.set_password("InvestigatorPass2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_user(client, username="osint_investigator", password="InvestigatorPass2026!"):
    """Helper to log in player."""
    return client.post("/login", json={"identifier": username, "password": password})


# =========================================================================
# 1. Evidence Files & Packaging Tests
# =========================================================================

def test_stage1_dossier_zip_integrity():
    """Verify the generated dossier zip exists and has all 5 required evidence files."""
    zip_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "platform", "static", "downloads", "stage1_digital_footprint_dossier.zip"
    ))
    assert os.path.exists(zip_path), f"Dossier ZIP missing at {zip_path}"
    assert os.path.getsize(zip_path) > 1000

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        assert "01_employee_roster.csv" in namelist
        assert "02_git_commit_history.log" in namelist
        assert "03_dev_chat_archive.json" in namelist
        assert "04_leaked_debug_paste.txt" in namelist
        assert "README_MISSION_BRIEFING.txt" in namelist


def test_stage1_evidence_data_integrity():
    """Validate structure of fictional OSINT evidence files."""
    evidence_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "challenges", "stage1_osint", "evidence"
    ))

    # 1. Check CSV
    csv_path = os.path.join(evidence_dir, "01_employee_roster.csv")
    assert os.path.exists(csv_path)
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) >= 5
        # Verify target engineer exists
        target = next((r for r in reader if r["github_handle"] == "j_banker_dev"), None)
        assert target is not None
        assert target["first_name"] == "Jonathan"
        assert target["last_name"] == "Mercer"
        assert "j.mercer@cyberbank-internal.net" == target["email"]

    # 2. Check Git Log
    git_path = os.path.join(evidence_dir, "02_git_commit_history.log")
    with open(git_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Jonathan Mercer <j.mercer@cyberbank-internal.net>" in content
        assert "7f8a92d1" in content
        assert "#BK-9821-DUMP" in content

    # 3. Check Chat JSON
    chat_path = os.path.join(evidence_dir, "03_dev_chat_archive.json")
    with open(chat_path, "r", encoding="utf-8") as f:
        chat_data = json.load(f)
        assert "messages" in chat_data
        assert any("BK-9821-DUMP" in m["text"] for m in chat_data["messages"])

    # 4. Check Leaked Paste Flag
    paste_path = os.path.join(evidence_dir, "04_leaked_debug_paste.txt")
    with open(paste_path, "r", encoding="utf-8") as f:
        paste_content = f.read()
        match = re.search(r"CBANK\{[A-Za-z0-9_-]+\}", paste_content)
        assert match is not None
        recovered_flag = match.group(0)
        assert recovered_flag == "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"


# =========================================================================
# 2. End-to-End Investigation Flow Tests
# =========================================================================

def test_stage1_end_to_end_solve_flow(client, player_user, app):
    """
    Test complete Stage 1 player journey:
        1. Player navigates to /challenges/1 -> Sees Briefing and Dossier Link (HTTP 200)
        2. Player downloads dossier -> Recovers flag from evidence
        3. Player submits flag -> Receives +100 PTS and Clearance Granted
        4. Player dashboard updates: Stage 1 = Completed, Stage 2 = Available
    """
    login_user(client)

    # 1. View Stage 1 Briefing
    view_resp = client.get("/challenges/1")
    assert view_resp.status_code == 200
    html = view_resp.get_data(as_text=True)
    assert "Digital Footprint" in html
    assert "stage1_digital_footprint_dossier.zip" in html
    assert "ANALYSIS TOOLS:" in html

    # 2. Extract Flag from Evidence
    paste_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "challenges", "stage1_osint", "evidence", "04_leaked_debug_paste.txt"
    ))
    with open(paste_path, "r", encoding="utf-8") as f:
        flag = re.search(r"CBANK\{[A-Za-z0-9_-]+\}", f.read()).group(0)

    # 3. Verify flag against DB hash
    with app.app_context():
        c1 = Challenge.query.filter_by(stage_number=1).first()
        assert verify_flag(flag, c1.flag_hash) is True

    # 4. Submit Flag to Platform
    sub_resp = client.post("/challenges/1/submit", json={"flag": flag})
    assert sub_resp.status_code == 200
    sub_data = sub_resp.get_json()
    assert sub_data["status"] == "success"
    assert sub_data["points_awarded"] == 100
    assert sub_data["new_total_score"] == 100

    # 5. Verify Stage 2 is unlocked
    c2_resp = client.get("/challenges/2", headers={"Accept": "application/json"})
    assert c2_resp.status_code == 200
    assert c2_resp.get_json()["challenge"]["status"] == "available"
    assert c2_resp.get_json()["challenge"]["title"] == "Hidden in Plain Sight"
