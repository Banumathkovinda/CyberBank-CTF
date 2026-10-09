"""
CyberBank: Operation BlackVault
Flag Submission & Scoring Unit and Integration Tests

Tests:
    1. Correct flag submission awards points and records success
    2. Wrong flag submission awards 0 points and records failure
    3. Repeated / duplicate correct flag submission prevented (no duplicate points)
    4. Multi-stage score accumulation and unlock progression
    5. Flag normalization (whitespace, trailing carriage returns)
    6. Locked stage submission rejection (prerequisite enforcement)
    7. Malformed flag format rejection
    8. HTML form-based submission and flash redirect
    9. Unauthenticated submission access control
"""

import os
import sys
import pytest

# Ensure platform module is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app
from extensions import db
from models import User, Challenge, Submission, Score, Log
from seed import seed_challenges
from flag_service import hash_flag, normalize_flag, validate_flag_format


@pytest.fixture
def test_app():
    """Create test application configured with in-memory SQLite database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        seed_challenges()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def test_client(test_app):
    """Test client fixture."""
    return test_app.test_client()


@pytest.fixture
def test_user(test_app):
    """Create a standard test player operative."""
    with test_app.app_context():
        user = User(
            username="operative_zero",
            email="operative_zero@blackvault.local",
            role="player",
        )
        user.set_password("TargetP@ssw0rd!2026")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_user(client, username="operative_zero", password="TargetP@ssw0rd!2026"):
    """Helper to log in a user session."""
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


# =========================================================================
# Unit Tests: Flag Service & Formatting
# =========================================================================

def test_flag_format_validation():
    """Verify flag format regex enforcement."""
    assert validate_flag_format("CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}") is True
    assert validate_flag_format("CBANK{STEGO_h1dd3n_sp3ctrum_4491}") is True
    assert validate_flag_format("CBANK{LINUX_r00t_bl4ckv4ult_m4st3r_5519}") is True
    assert validate_flag_format("FLAG{invalid_prefix}") is False
    assert validate_flag_format("CBANK{}") is False
    assert validate_flag_format("CBANK{has spaces inside}") is False
    assert validate_flag_format("") is False


def test_flag_normalization():
    """Verify whitespace and newline stripping."""
    raw = "   \n\rCBANK{OSINT_f00tpr1nt_d1g1t4l_9821}\t  \n"
    normalized = normalize_flag(raw)
    assert normalized == "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"


# =========================================================================
# Integration Tests: Flag Submission Endpoint
# =========================================================================

def test_unauthenticated_submission_rejected(test_client):
    """Unauthenticated users cannot submit flags."""
    resp = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    # Redirects to login or returns 401
    assert resp.status_code in (302, 401)


def test_correct_flag_submission(test_app, test_client, test_user):
    """Submitting correct flag for Stage 1 awards 100 points and updates score."""
    login_user(test_client)

    resp = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["points_awarded"] == 100
    assert data["new_total_score"] == 100
    assert data["stage_number"] == 1

    # Verify Database state
    with test_app.app_context():
        sub = Submission.query.filter_by(user_id=test_user, challenge_id=1).first()
        assert sub is not None
        assert sub.success is True
        assert sub.score_awarded == 100

        score = Score.query.filter_by(user_id=test_user).first()
        assert score is not None
        assert score.total_score == 100


def test_wrong_flag_submission(test_app, test_client, test_user):
    """Submitting wrong flag awards 0 points and logs failure."""
    login_user(test_client)

    resp = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{WRONG_INCORRECT_FLAG_0000}"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["status"] == "incorrect"

    with test_app.app_context():
        sub = Submission.query.filter_by(user_id=test_user, challenge_id=1).first()
        assert sub is not None
        assert sub.success is False
        assert sub.score_awarded == 0

        score = Score.query.filter_by(user_id=test_user).first()
        assert score is None or score.total_score == 0


def test_repeated_correct_flag_no_duplicate_points(test_app, test_client, test_user):
    """Submitting the correct flag a second time does not double points."""
    login_user(test_client)

    # First attempt: SUCCESS
    resp1 = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp1.status_code == 200
    assert resp1.get_json()["new_total_score"] == 100

    # Second attempt: DUPLICATE (409 Conflict)
    resp2 = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp2.status_code == 409
    data2 = resp2.get_json()
    assert data2["status"] == "duplicate"

    with test_app.app_context():
        score = Score.query.filter_by(user_id=test_user).first()
        # Score must remain 100, not 200
        assert score.total_score == 100


def test_locked_stage_submission_rejected(test_client, test_user):
    """Submitting flag for Stage 2 before solving Stage 1 returns 403 Forbidden."""
    login_user(test_client)

    resp = test_client.post(
        "/submit",
        json={"challenge_id": 2, "flag": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["status"] == "locked"


def test_multi_stage_progression_and_score_calculation(test_app, test_client, test_user):
    """
    Test sequential progression:
        Stage 1 (100 pts) -> Total: 100
        Stage 2 (100 pts) -> Total: 200
        Stage 3 (150 pts) -> Total: 350
        Stage 4 (150 pts) -> Total: 500
        Stage 5 (200 pts) -> Total: 700
        Stage 6 (300 pts) -> Total: 1000
    """
    login_user(test_client)

    stages_flags = [
        (1, "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}", 100, 100),
        (2, "CBANK{STEGO_h1dd3n_sp3ctrum_4491}", 100, 200),
        (3, "CBANK{WEB_sqli_byp4ss_v4ult_7721}", 150, 350),
        (4, "CBANK{CRYPTO_b4nk3r_c1ph3r_br34k_3310}", 150, 500),
        (5, "CBANK{FORENSICS_dchen_9f88c2_exf1l_8443}", 200, 700),
        (6, "CBANK{LINUX_r00t_bl4ckv4ult_m4st3r_5519}", 300, 1000),
    ]

    for chal_id, flag, pts, expected_total in stages_flags:
        resp = test_client.post(
            f"/challenges/{chal_id}/submit",
            json={"flag": flag},
        )
        assert resp.status_code == 200, f"Failed at Stage {chal_id}: {resp.get_data(as_text=True)}"
        data = resp.get_json()
        assert data["points_awarded"] == pts
        assert data["new_total_score"] == expected_total

    # Verify final dashboard telemetry
    dash_resp = test_client.get("/dashboard")
    assert dash_resp.status_code == 200
    html = dash_resp.get_data(as_text=True)
    assert "1000" in html
    assert "100% BREACHED" in html


def test_flag_normalization_with_whitespace(test_client, test_user):
    """Whitespace around candidate flag is trimmed automatically."""
    login_user(test_client)

    resp = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "   \nCBANK{OSINT_f00tpr1nt_d1g1t4l_9821}  \t"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "success"


def test_html_form_submission_redirect_and_flash(test_client, test_user):
    """Submitting via standard HTML form redirects to dashboard with flash message."""
    login_user(test_client)

    resp = test_client.post(
        "/challenges/1/submit",
        data={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Clearance Granted!" in html
    assert "Stage 01" in html


def test_expired_mission_submission_rejected(test_app, test_client, test_user):
    """Submissions after 2 hours (7200s) are strictly rejected with HTTP 403."""
    import datetime

    # Set user created_at to 2 hours and 15 minutes ago
    with test_app.app_context():
        user = db.session.get(User, test_user)
        user.created_at = datetime.datetime.utcnow() - datetime.timedelta(hours=2, minutes=15)
        db.session.commit()

    login_user(test_client)

    resp = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["status"] == "expired"
    assert data["time_expired"] is True
    assert "Mission window expired" in data["message"]


def test_player_cannot_reset_expired_mission_timer(test_app, test_client, test_user):
    """In live competition conditions, players cannot reset their expired mission clock."""
    import datetime

    # Expire user timer
    with test_app.app_context():
        user = db.session.get(User, test_user)
        user.created_at = datetime.datetime.utcnow() - datetime.timedelta(hours=3)
        db.session.commit()

    login_user(test_client)

    # Attempt player reset
    reset_resp = test_client.get("/mission/reset-timer", follow_redirects=True)
    assert reset_resp.status_code == 200

    # Submission must remain expired and locked
    resp = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 403
    assert resp.get_json()["status"] == "expired"


def test_wrong_flag_penalty_deducts_10_points(test_app, test_client, test_user):
    """Submitting wrong or malformed flags deducts 10 points from total score, clamped at 0."""
    login_user(test_client)

    # Solve Stage 1 first to earn 100 points
    resp1 = test_client.post(
        "/submit",
        json={"challenge_id": 1, "flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp1.status_code == 200
    assert resp1.get_json()["new_total_score"] == 100

    # Submit an incorrect flag for Stage 2 -> score decreases from 100 to 90
    resp_wrong = test_client.post(
        "/submit",
        json={"challenge_id": 2, "flag": "CBANK{STEGO_WRONG_GUESS_9999}"},
    )
    assert resp_wrong.status_code == 400
    data_wrong = resp_wrong.get_json()
    assert data_wrong["status"] == "incorrect"
    assert data_wrong["penalty_points"] == 10
    assert data_wrong["new_total_score"] == 90

    with test_app.app_context():
        score = Score.query.filter_by(user_id=test_user).first()
        assert score.total_score == 90

    # Submit a malformed flag -> also deducts 10 points (90 -> 80)
    resp_malformed = test_client.post(
        "/submit",
        json={"challenge_id": 2, "flag": "INVALID_FLAG_FORMAT"},
    )
    assert resp_malformed.status_code == 400
    data_mal = resp_malformed.get_json()
    assert data_mal["penalty_points"] == 10
    assert data_mal["new_total_score"] == 80

    with test_app.app_context():
        score = Score.query.filter_by(user_id=test_user).first()
        assert score.total_score == 80

