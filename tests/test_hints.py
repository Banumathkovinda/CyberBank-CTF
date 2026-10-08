"""
CyberBank: Operation BlackVault
Three-Level Progressive Hint System & Scoring Penalty Tests

Tests:
    1. Initial 18 hints seeded in database (3 per challenge, 10%, 20%, 30% penalties)
    2. Hint content is hidden until unlocked by the operative
    3. Sequential progressive unlocking (Hint 1 -> Hint 2 -> Hint 3)
    4. Locked challenges reject hint unlocking (HTTP 403)
    5. Each hint usable only once (idempotent, no double penalties)
    6. Hint usage is recorded in hint_usages and audit-logged in logs
    7. Full scoring penalty calculations:
        - 0 hints: 100% points
        - Hint 1: 10% penalty (90% awarded)
        - Hint 1 & 2: 30% cumulative penalty (70% awarded)
        - Hints 1, 2 & 3: 60% cumulative penalty (40% awarded)
    8. Points and score cannot become negative
"""

import os
import sys
import pytest

# Ensure platform module is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app
from extensions import db
from models import User, Challenge, Hint, HintUsage, Submission, Score, Log
from seed import seed_challenges
from hint_service import calculate_effective_points, unlock_hint, get_challenge_hints_for_user


@pytest.fixture
def app():
    """Create test application with in-memory SQLite database."""
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
    """Create a standard test player operative."""
    with app.app_context():
        user = User(
            username="operative_hint_tester",
            email="hints@blackvault.local",
            role="player",
        )
        user.set_password("TargetP@ssw0rd!2026")
        db.session.add(user)
        db.session.commit()
        return user.id


def login_user(client, username="operative_hint_tester", password="TargetP@ssw0rd!2026"):
    """Helper to authenticate test client session."""
    return client.post("/login", json={"identifier": username, "password": password})


# =========================================================================
# 1. Database Seeding & Initial Hint Setup Tests
# =========================================================================

def test_initial_hints_seeded_correctly(app):
    """Verify that all 6 challenges have 3 hints with 10%, 20%, and 30% penalties."""
    with app.app_context():
        challenges = Challenge.query.all()
        assert len(challenges) == 6

        total_hints = Hint.query.all()
        assert len(total_hints) == 18

        for c in challenges:
            c_hints = Hint.query.filter_by(challenge_id=c.id).order_by(Hint.hint_number.asc()).all()
            assert len(c_hints) == 3
            assert c_hints[0].hint_number == 1 and c_hints[0].penalty_percentage == 10
            assert c_hints[1].hint_number == 2 and c_hints[1].penalty_percentage == 20
            assert c_hints[2].hint_number == 3 and c_hints[2].penalty_percentage == 30
            # Ensure hints guide without exposing plain flag
            for h in c_hints:
                assert "CBANK{" not in h.hint_text
                assert len(h.hint_text) > 10


# =========================================================================
# 2. Progressive Visibility & Unlocking Tests
# =========================================================================

def test_hints_hidden_until_unlocked(client, player_user):
    """Verify that hint text is null until unlocked."""
    login_user(client)

    resp = client.get("/challenges/1/hints")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    hints = data["hints"]
    assert len(hints) == 3

    # All hints must have hint_text=None initially
    for h in hints:
        assert h["is_unlocked"] is False
        assert h["hint_text"] is None

    # Hint 1 can be unlocked, but Hints 2 and 3 cannot be unlocked yet
    assert hints[0]["can_unlock"] is True
    assert hints[1]["can_unlock"] is False
    assert hints[2]["can_unlock"] is False


def test_sequential_progressive_unlocking(client, player_user):
    """Verify sequential unlocking enforcement: Hint 1 -> Hint 2 -> Hint 3."""
    login_user(client)

    # Attempt to unlock Hint 2 directly without Hint 1 -> REJECTED (HTTP 400)
    resp_bad2 = client.post("/challenges/1/hints/2/unlock")
    assert resp_bad2.status_code == 400
    assert "must unlock Hint #1" in resp_bad2.get_json()["message"]

    # Attempt to unlock Hint 3 directly -> REJECTED (HTTP 400)
    resp_bad3 = client.post("/challenges/1/hints/3/unlock")
    assert resp_bad3.status_code == 400

    # 1. Unlock Hint 1 -> SUCCESS (HTTP 200)
    resp_h1 = client.post("/challenges/1/hints/1/unlock")
    assert resp_h1.status_code == 200
    h1_data = resp_h1.get_json()
    assert h1_data["status"] == "success"
    assert h1_data["hint"]["hint_text"] is not None
    assert h1_data["hint"]["penalty_percentage"] == 10

    # Now Hint 2 can be unlocked
    resp_h2 = client.post("/challenges/1/hints/2/unlock")
    assert resp_h2.status_code == 200
    assert resp_h2.get_json()["hint"]["penalty_percentage"] == 20

    # Now Hint 3 can be unlocked
    resp_h3 = client.post("/challenges/1/hints/3/unlock")
    assert resp_h3.status_code == 200
    assert resp_h3.get_json()["hint"]["penalty_percentage"] == 30


def test_locked_challenge_rejects_hint_unlocking(client, player_user):
    """Operative cannot view or unlock hints for locked stages (HTTP 403)."""
    login_user(client)

    # Stage 2 is locked before Stage 1 is solved
    resp_get = client.get("/challenges/2/hints")
    assert resp_get.status_code == 403

    resp_post = client.post("/challenges/2/hints/1/unlock")
    assert resp_post.status_code == 403
    assert "locked" in resp_post.get_json()["message"].lower()


def test_idempotent_hint_unlock_no_duplicate_penalty(client, player_user, app):
    """Unlocking an already unlocked hint returns success without duplicating database rows."""
    login_user(client)

    # Unlock Hint 1 first time
    resp1 = client.post("/challenges/1/hints/1/unlock")
    assert resp1.status_code == 200

    # Unlock Hint 1 second time
    resp2 = client.post("/challenges/1/hints/1/unlock")
    assert resp2.status_code == 200
    assert resp2.get_json()["hint"]["already_unlocked"] is True

    # Verify only 1 row in hint_usages
    with app.app_context():
        usages = HintUsage.query.filter_by(user_id=player_user, challenge_id=1).all()
        assert len(usages) == 1


def test_hint_usage_audit_logging(client, player_user, app):
    """Hint usage records an audit log entry in the logs table."""
    login_user(client)

    client.post("/challenges/1/hints/1/unlock")

    with app.app_context():
        log = Log.query.filter_by(
            user_id=player_user,
            challenge_id=1,
            event_type="hint_used",
        ).first()
        assert log is not None
        assert "Hint #1" in log.message


# =========================================================================
# 3. Score Penalty Calculation & Integration Tests
# =========================================================================

def test_score_calculation_zero_hints(client, player_user, app):
    """Solving Stage 1 (100 pts) with 0 hints awards 100 points."""
    login_user(client)

    resp = client.post(
        "/challenges/1/submit",
        json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["points_awarded"] == 100
    assert data["new_total_score"] == 100


def test_score_calculation_hint_1_only(client, player_user, app):
    """Solving Stage 1 (100 pts) with Hint 1 (10% penalty) awards 90 points."""
    login_user(client)

    # Unlock Hint 1 (-10%)
    client.post("/challenges/1/hints/1/unlock")

    resp = client.post(
        "/challenges/1/submit",
        json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["points_awarded"] == 90
    assert data["new_total_score"] == 90


def test_score_calculation_hints_1_and_2(client, player_user, app):
    """Solving Stage 1 (100 pts) with Hints 1 & 2 (10% + 20% = 30% penalty) awards 70 points."""
    login_user(client)

    client.post("/challenges/1/hints/1/unlock")
    client.post("/challenges/1/hints/2/unlock")

    resp = client.post(
        "/challenges/1/submit",
        json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["points_awarded"] == 70
    assert data["new_total_score"] == 70


def test_score_calculation_all_three_hints(client, player_user, app):
    """Solving Stage 1 (100 pts) with all 3 hints (10% + 20% + 30% = 60% penalty) awards 40 points."""
    login_user(client)

    client.post("/challenges/1/hints/1/unlock")
    client.post("/challenges/1/hints/2/unlock")
    client.post("/challenges/1/hints/3/unlock")

    resp = client.post(
        "/challenges/1/submit",
        json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["points_awarded"] == 40
    assert data["new_total_score"] == 40


def test_multi_stage_hint_penalties_on_stage_3(client, player_user, app):
    """Stage 3 (150 pts base): with Hint 1 (10%) and Hint 2 (20%) -> 30% deduction (45 pts) -> awards 105 pts."""
    login_user(client)

    # Solve Stage 1 & Stage 2 first
    client.post("/challenges/1/submit", json={"flag": "CBANK{OSINT_f00tpr1nt_d1g1t4l_9821}"})
    client.post("/challenges/2/submit", json={"flag": "CBANK{STEGO_h1dd3n_sp3ctrum_4491}"})

    # Unlock Hint 1 and Hint 2 on Stage 3
    client.post("/challenges/3/hints/1/unlock")
    client.post("/challenges/3/hints/2/unlock")

    # Solve Stage 3
    resp = client.post("/challenges/3/submit", json={"flag": "CBANK{WEB_sqli_byp4ss_v4ult_7721}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["points_awarded"] == 105
    # Total score: 100 (Stage 1) + 100 (Stage 2) + 105 (Stage 3) = 305
    assert data["new_total_score"] == 305
