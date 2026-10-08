"""
CyberBank: Operation BlackVault
Dashboard & Access Control Test Suite

Tests:
    1. Protected /dashboard requires authentication
    2. Authenticated player dashboard displays telemetry (username, score, progress)
    3. All six challenge stages are displayed with correct metadata
    4. Progression resolution (Stage 1 unlocked -> solve Stage 1 -> unlocks Stage 2 -> locks Stages 3-6)
    5. Server-side access control: Normal player forbidden (HTTP 403) from admin endpoints
    6. Server-side access control: Admin allowed (HTTP 200) on admin endpoints
    7. JSON API endpoint output format and challenge statuses
"""

import os
import sys
import pytest

# Ensure platform module is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app
from extensions import db
from models import User, Score, Challenge, Submission, Log
from seed import seed_challenges


@pytest.fixture
def app():
    """Create and configure test application with in-memory SQLite database."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        # Seed the six canonical challenges
        seed_challenges()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client for HTTP requests."""
    return app.test_client()


@pytest.fixture
def player_user(app):
    """Fixture providing a standard operative player user."""
    with app.app_context():
        user = User(
            username="operative_alpha",
            email="alpha@cyberbank.local",
            role="player",
        )
        user.set_password("OperativePass123!")
        score = Score(user=user, total_score=0)
        db.session.add(user)
        db.session.add(score)
        db.session.commit()
        return user.id


@pytest.fixture
def admin_user(app):
    """Fixture providing an administrator user."""
    with app.app_context():
        user = User(
            username="vault_admin",
            email="admin@cyberbank.local",
            role="admin",
        )
        user.set_password("AdminRootPass123!")
        score = Score(user=user, total_score=0)
        db.session.add(user)
        db.session.add(score)
        db.session.commit()
        return user.id


# ============================================================
# 1. Protected Route & Telemetry Tests
# ============================================================

def test_dashboard_requires_login(client):
    """Test accessing /dashboard unauthenticated redirects to /login."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_dashboard_authenticated_player(client, player_user):
    """Test authenticated player can access /dashboard and sees telemetry."""
    # Login
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    response = client.get("/dashboard")
    assert response.status_code == 200
    assert b"operative_alpha" in response.data
    assert b"MISSION PROGRESS" in response.data
    assert b"0%" in response.data


def test_dashboard_shows_all_six_stages(client, player_user):
    """Test dashboard renders all six challenge stages with titles and domains."""
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    response = client.get("/dashboard")
    assert response.status_code == 200
    
    # 1. Digital Footprint
    assert b"Digital Footprint" in response.data
    # 2. Hidden in Plain Sight
    assert b"Hidden in Plain Sight" in response.data
    # 3. Broken Banking Portal
    assert b"Broken Banking Portal" in response.data
    # 4. The Banker's Secret Code (Jinja escapes apostrophe as &#39; in HTML)
    assert b"The Banker&#39;s Secret Code" in response.data or b"The Banker's Secret Code" in response.data
    # 5. Digital Crime Scene
    assert b"Digital Crime Scene" in response.data
    # 6. BlackVault Server
    assert b"BlackVault Server" in response.data


# ============================================================
# 2. Challenge Progression & Status Tests
# ============================================================

def test_initial_challenge_statuses(client, player_user):
    """Test initial state: Stage 1 is available, Stages 2-6 are locked."""
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    response = client.get("/dashboard", headers={"Accept": "application/json"})
    assert response.status_code == 200
    data = response.get_json()

    challenges = data["challenges"]
    assert len(challenges) == 6

    # Stage 1: Available
    assert challenges[0]["stage_number"] == 1
    assert challenges[0]["status"] == "available"

    # Stages 2-6: Locked
    for chal in challenges[1:]:
        assert chal["status"] == "locked"


def test_progression_after_solving_stage_1(client, player_user, app):
    """Test solving Stage 1 marks it completed and unlocks Stage 2 to available."""
    with app.app_context():
        chal1 = Challenge.query.filter_by(stage_number=1).first()
        # Record successful submission for Stage 1
        sub = Submission(
            user_id=player_user,
            challenge_id=chal1.id,
            success=True,
            score_awarded=chal1.points,
        )
        score = Score.query.filter_by(user_id=player_user).first()
        score.total_score += chal1.points
        db.session.add(sub)
        db.session.commit()

    # Login
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    response = client.get("/dashboard", headers={"Accept": "application/json"})
    assert response.status_code == 200
    data = response.get_json()

    user_data = data["user"]
    assert user_data["total_score"] == 100
    assert user_data["completed_challenges"] == 1
    assert user_data["progress_percentage"] == 17

    challenges = data["challenges"]
    # Stage 1 is now completed
    assert challenges[0]["status"] == "completed"
    # Stage 2 is now unlocked and available
    assert challenges[1]["status"] == "available"
    # Stages 3-6 remain locked
    for chal in challenges[2:]:
        assert chal["status"] == "locked"


# ============================================================
# 3. Server-Side Access Control Tests
# ============================================================

def test_player_forbidden_from_admin_area_json(client, player_user):
    """Test player role is rejected with HTTP 403 on admin API route."""
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 403
    data = response.get_json()
    assert data["status"] == "error"
    assert "Administrator clearance required" in data["message"]


def test_player_forbidden_from_admin_area_html(client, player_user):
    """Test player role is redirected with warning when accessing admin HTML."""
    client.post(
        "/login",
        data={"identifier": "operative_alpha", "password": "OperativePass123!"},
        follow_redirects=True,
    )

    response = client.get("/admin", follow_redirects=True)
    assert response.status_code == 200
    # Must redirect to dashboard with danger flash
    assert b"Administrator clearance required" in response.data
    assert b"Operation BlackVault" in response.data


def test_admin_allowed_access_to_admin_area(client, admin_user):
    """Test admin role is granted HTTP 200 access on admin route."""
    client.post(
        "/login",
        json={"identifier": "vault_admin", "password": "AdminRootPass123!"},
    )

    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "admin_telemetry" in data
    assert data["admin_telemetry"]["total_challenges"] == 6


# ============================================================
# 4. Progressive Server-Side Unlocking & Direct URL Bypass Tests
# ============================================================

def test_direct_url_access_to_initial_stage_1(client, player_user):
    """Test Stage 1 is initially available via direct URL access."""
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    # Access by ID
    resp_id = client.get("/challenges/1", headers={"Accept": "application/json"})
    assert resp_id.status_code == 200
    data_id = resp_id.get_json()
    assert data_id["status"] == "success"
    assert data_id["challenge"]["stage_number"] == 1
    assert data_id["challenge"]["status"] == "available"

    # Access by Stage Number
    resp_stage = client.get("/challenges/stage/1", headers={"Accept": "application/json"})
    assert resp_stage.status_code == 200


def test_direct_url_access_to_locked_stages_rejected(client, player_user, app):
    """Test direct URL access to Stages 2 through 6 is strictly rejected (HTTP 403)."""
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    # Stages 2 to 6 must all return HTTP 403 Forbidden
    for stage_num in range(2, 7):
        # By ID
        resp_id = client.get(f"/challenges/{stage_num}", headers={"Accept": "application/json"})
        assert resp_id.status_code == 403, f"Expected 403 for Stage {stage_num} by ID, got {resp_id.status_code}"
        data_id = resp_id.get_json()
        assert data_id["status"] == "locked"
        assert f"Stage #{stage_num} is locked" in data_id["message"]

        # By Stage Number
        resp_stage = client.get(f"/challenges/stage/{stage_num}", headers={"Accept": "application/json"})
        assert resp_stage.status_code == 403, f"Expected 403 for Stage {stage_num} by stage path"

    # Verify that audit log records were created for the blocked access attempts
    with app.app_context():
        logs = Log.query.filter_by(event_type="access_denied_locked_stage").all()
        assert len(logs) >= 5


def test_progressive_unlocking_chain_across_all_six_stages(client, player_user, app):
    """
    Test the full progressive chain:
        Initial: Stage 1 (200), Stages 2-6 (403)
        Solve 1: Stage 2 (200), Stages 3-6 (403)
        Solve 2: Stage 3 (200), Stages 4-6 (403)
        Solve 3: Stage 4 (200), Stages 5-6 (403)
        Solve 4: Stage 5 (200), Stage 6 (403)
        Solve 5: Stage 6 (200)
    """
    client.post(
        "/login",
        json={"identifier": "operative_alpha", "password": "OperativePass123!"},
    )

    with app.app_context():
        challenges = Challenge.query.order_by(Challenge.stage_number.asc()).all()
        stage_map = {c.stage_number: c for c in challenges}

    for current_stage in range(1, 6):
        # Verify current stage is accessible
        resp_curr = client.get(f"/challenges/{current_stage}", headers={"Accept": "application/json"})
        assert resp_curr.status_code == 200, f"Stage {current_stage} should be accessible"

        # Verify next stages are still locked
        for locked_stage in range(current_stage + 1, 7):
            resp_locked = client.get(f"/challenges/{locked_stage}", headers={"Accept": "application/json"})
            assert resp_locked.status_code == 403, f"Stage {locked_stage} should be locked before solving Stage {current_stage}"

        # Solve current stage
        with app.app_context():
            c = stage_map[current_stage]
            sub = Submission(
                user_id=player_user,
                challenge_id=c.id,
                success=True,
                score_awarded=c.points,
            )
            db.session.add(sub)
            db.session.commit()

    # After solving Stage 5, Stage 6 must now be unlocked (HTTP 200)
    resp_stage_6 = client.get("/challenges/6", headers={"Accept": "application/json"})
    assert resp_stage_6.status_code == 200
    assert resp_stage_6.get_json()["challenge"]["status"] == "available"


def test_direct_url_html_redirect_and_audit_logging(client, player_user, app):
    """Test accessing locked challenge via HTML browser request sets flash and logs event."""
    client.post(
        "/login",
        data={"identifier": "operative_alpha", "password": "OperativePass123!"},
        follow_redirects=True,
    )

    # Attempt direct browser navigation to locked Stage 4
    resp = client.get("/challenges/4", follow_redirects=True)
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Access Denied: Stage #4 is locked" in html
    assert "Infiltration Stages" in html

    # Verify audit log in DB
    with app.app_context():
        log = Log.query.filter_by(
            user_id=player_user,
            challenge_id=4,
            event_type="access_denied_locked_stage",
        ).first()
        assert log is not None

