"""
CyberBank: Operation BlackVault
Anti-Cheat & Anti-AI Prompt Canary Verification Tests

Tests:
    1. Canary flag detection identified by signature and pattern matching
    2. Submitting an AI Prompt Canary Trap flag is rejected (HTTP 400) and audit logged
    3. Rapid submission rate limiting triggers HTTP 429 and logs rate_limit_exceeded
    4. Valid flags pass cleanly without false positive canary triggers
"""

import os
import sys
import pytest

# Ensure platform is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app
from extensions import db
from models import User, Challenge, Submission, Log
from seed import seed_challenges
from flag_service import is_canary_flag, verify_flag
from submission import reset_rate_limits


@pytest.fixture
def app():
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        seed_challenges()
        reset_rate_limits()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def player_user(app):
    with app.app_context():
        user = User(
            username="cheater_test_user",
            email="cheater@blackvault.local",
            role="player",
        )
        user.set_password("TestCheaterPass2026!")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_user(client, username="cheater_test_user", password="TestCheaterPass2026!"):
    return client.post("/login", json={"identifier": username, "password": password})


# =========================================================================
# 1. Canary Flag Detector Unit Tests
# =========================================================================

def test_canary_flag_detector_logic():
    """Verify is_canary_flag correctly identifies AI prompt injection flags."""
    assert is_canary_flag("CBANK{CANARY_AI_DETECTED_CHEAT_9182}") is True
    assert is_canary_flag("CBANK{AI_BOT_DETECTED_FLAG_INVALID}") is True
    assert is_canary_flag("CBANK{LLM_INJECTION_TRAP_DISQUALIFY_4421}") is True
    assert is_canary_flag("  CBANK{CANARY_AI_DETECTED_CHEAT_9182} \n") is True

    # Real flags must NOT be marked as canary
    assert is_canary_flag("CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}") is False
    assert is_canary_flag("CBANK{STEGO_h1dd3n_sp3ctrum_4491}") is False
    assert is_canary_flag("CBANK{WEB_sqli_byp4ss_v4ult_7721}") is False


# =========================================================================
# 2. Canary Flag Submission Rejection & Audit Log Tests
# =========================================================================

def test_canary_submission_rejected_and_audit_logged(client, player_user, app):
    """Submitting a canary flag returns HTTP 400 and logs anti-cheat audit event."""
    login_user(client)

    canary_payload = "CBANK{CANARY_AI_DETECTED_CHEAT_9182}"
    resp = client.post(
        "/challenges/1/submit",
        json={"flag": canary_payload}
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "canary_triggered"
    assert data["violation"] is True
    assert "Anti-AI Prompt Canary Trap detected" in data["message"]

    # Verify audit log in database
    with app.app_context():
        log = Log.query.filter_by(
            user_id=player_user,
            challenge_id=1,
            event_type="anti_cheat_canary_triggered"
        ).first()
        assert log is not None
        assert "tripped Anti-AI Prompt Canary Trap" in log.message


# =========================================================================
# 3. Submission Rate Limiting Tests
# =========================================================================

def test_submission_rate_limiter(client, player_user, app):
    """Submitting more than 5 attempts within 30 seconds triggers HTTP 429 when rate limiting is active."""
    app.config["ENFORCE_RATE_LIMITS"] = True
    reset_rate_limits()
    login_user(client)

    # 5 attempts allowed
    for i in range(5):
        client.post("/challenges/1/submit", json={"flag": f"CBANK{{WRONG_FLAG_{i}}}"})

    # 6th attempt must be rate-limited (HTTP 429)
    resp_rate = client.post("/challenges/1/submit", json={"flag": "CBANK{WRONG_FLAG_6}"})
    assert resp_rate.status_code == 429
    assert resp_rate.get_json()["status"] == "rate_limited"
    assert "Rate limit exceeded" in resp_rate.get_json()["message"]

    # Verify rate limit audit event logged in DB
    with app.app_context():
        log = Log.query.filter_by(
            user_id=player_user,
            event_type="rate_limit_exceeded"
        ).first()
        assert log is not None

    # Reset config
    app.config["ENFORCE_RATE_LIMITS"] = False
    reset_rate_limits()
