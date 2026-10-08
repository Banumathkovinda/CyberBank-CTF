"""
CyberBank: Operation BlackVault
Stage 3 — Broken Banking Portal (Web Security / IDOR) End-to-End Test Suite

Tests:
    1. Vulnerable banking app initializes and starts cleanly
    2. Standard authentication with customer_user / Password123!
    3. Normal authorized access to own account (#1002)
    4. Insecure Direct Object Reference (IDOR) on /transactions?account_id=7721
    5. Insecure Direct Object Reference (IDOR) on /api/account/7721
    6. Recovery of flag matches Stage 3 flag_hash in database
    7. Stage 3 is locked (HTTP 403) until Stage 1 & 2 are solved
    8. Progressive unlocking and solve of Stage 3 awards +150 PTS and unlocks Stage 4
"""

import os
import sys
import importlib.util
import pytest

# Add platform to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app as create_platform_app
from extensions import db
from models import User, Challenge, Submission, Score, Log
from seed import seed_challenges
from flag_service import verify_flag

# Load Stage 3 banking app explicitly
stage3_app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "challenges", "stage3_web", "app", "app.py"))
spec = importlib.util.spec_from_file_location("stage3_banking_app", stage3_app_path)
banking_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(banking_module)


@pytest.fixture
def platform_app():
    """Create test application for main CTF platform."""
    test_app = create_platform_app("testing")
    with test_app.app_context():
        db.create_all()
        seed_challenges()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def platform_client(platform_app):
    return platform_app.test_client()


@pytest.fixture
def banking_client(tmp_path, monkeypatch):
    """Create test client for isolated vulnerable banking portal."""
    db_file = tmp_path / "test_banking.db"
    monkeypatch.setattr(banking_module, "DB_PATH", str(db_file))
    banking_module.init_db()
    banking_module.app.config["TESTING"] = True
    return banking_module.app.test_client()


@pytest.fixture
def player_user(platform_app):
    """Create an authenticated player on the CTF platform."""
    with platform_app.app_context():
        user = User(
            username="web_app_pentester",
            email="pentest@blackvault.local",
            role="player",
        )
        user.set_password("WebSecPass2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_platform_user(client, username="web_app_pentester", password="WebSecPass2026!"):
    return client.post("/login", json={"identifier": username, "password": password})


# =========================================================================
# 1. Isolated Vulnerable Banking Portal Tests
# =========================================================================

def test_banking_portal_login_and_normal_access(banking_client):
    """Verify login and standard account access."""
    # 1. Login with provided credentials
    resp = banking_client.post(
        "/login",
        data={"username": "customer_user", "password": "Password123!"},
        follow_redirects=True
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Alice Smith" in html
    assert "CB-SAV-1002" in html

    # 2. Normal access to account 1002
    acc_resp = banking_client.get("/account?account_id=1002")
    assert acc_resp.status_code == 200
    assert "Standard Personal Savings" in acc_resp.get_data(as_text=True)


def test_banking_portal_idor_vulnerability(banking_client):
    """Verify that tampering account_id exposes the target BlackVault Master Account and Flag."""
    # 1. Login as standard customer
    banking_client.post(
        "/login",
        data={"username": "customer_user", "password": "Password123!"},
        follow_redirects=True
    )

    # 2. IDOR on /transactions?account_id=7721
    tx_resp = banking_client.get("/transactions?account_id=7721")
    assert tx_resp.status_code == 200
    tx_html = tx_resp.get_data(as_text=True)
    assert "BlackVault Master Liquidity Reserve" in tx_html
    assert "CBANK{WEB_sqli_byp4ss_v4ult_7721}" in tx_html

    # 3. IDOR on /api/account/7721
    api_resp = banking_client.get("/api/account/7721")
    assert api_resp.status_code == 200
    api_data = api_resp.get_json()
    assert api_data["account_id"] == 7721
    assert api_data["balance"] == 942500000.0
    assert any("CBANK{WEB_sqli_byp4ss_v4ult_7721}" in t["notes"] for t in api_data["transactions"])


# =========================================================================
# 2. CTF Platform Integration & Progressive Solve Flow Tests
# =========================================================================

def test_stage3_locked_until_stage1_and_2_solved(platform_client, player_user):
    """Direct access to Stage 3 must be rejected (HTTP 403) before Stage 2 is solved."""
    login_platform_user(platform_client)

    # Stage 3 is locked initially
    resp = platform_client.get("/challenges/3", headers={"Accept": "application/json"})
    assert resp.status_code == 403

    # Solve Stage 1 only -> Stage 3 remains locked
    platform_client.post("/challenges/1/submit", json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"})
    resp_after_s1 = platform_client.get("/challenges/3", headers={"Accept": "application/json"})
    assert resp_after_s1.status_code == 403


def test_stage3_end_to_end_solve_and_unlock_stage4(platform_client, player_user, platform_app):
    """
    Test complete Stage 3 workflow:
        1. Solve Stage 1 & Stage 2 -> Unlocks Stage 3
        2. Access Stage 3 -> Retrieves briefing & target URL
        3. Submit Stage 3 flag -> Awards +150 PTS
        4. Stage 4 (The Banker's Secret Code) is unlocked
    """
    login_platform_user(platform_client)

    # 1. Solve Stage 1 and Stage 2
    platform_client.post("/challenges/1/submit", json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"})
    platform_client.post("/challenges/2/submit", json={"flag": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}"})

    # 2. Stage 3 is now available
    view_resp = platform_client.get("/challenges/3")
    assert view_resp.status_code == 200
    html = view_resp.get_data(as_text=True)
    assert "Broken Banking Portal" in html
    assert ("HTTP://LOCALHOST:5001" in html) or ("HTTP://LOCALHOST:8080" in html)
    assert "customer_user" in html

    # 3. Submit Stage 3 flag
    flag = "CBANK{WEB_sqli_byp4ss_v4ult_7721}"
    with platform_app.app_context():
        c3 = Challenge.query.filter_by(stage_number=3).first()
        assert verify_flag(flag, c3.flag_hash) is True

    s3_resp = platform_client.post("/challenges/3/submit", json={"flag": flag})
    assert s3_resp.status_code == 200
    s3_data = s3_resp.get_json()
    assert s3_data["status"] == "success"
    assert s3_data["points_awarded"] == 150
    # Total score: 100 (S1) + 100 (S2) + 150 (S3) = 350
    assert s3_data["new_total_score"] == 350

    # 4. Verify Stage 4 is now unlocked
    c4_resp = platform_client.get("/challenges/4", headers={"Accept": "application/json"})
    assert c4_resp.status_code == 200
    assert c4_resp.get_json()["challenge"]["status"] == "available"
    assert c4_resp.get_json()["challenge"]["title"] == "The Banker's Secret Code"
