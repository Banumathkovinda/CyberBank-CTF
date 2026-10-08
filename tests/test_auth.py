"""
CyberBank: Operation BlackVault
Authentication Test Suite

Tests:
    1. Successful registration (web form & JSON API)
    2. Duplicate username rejection
    3. Duplicate email rejection
    4. Input validation (short passwords, invalid email, password mismatch)
    5. Password hashing verification (never plaintext)
    6. Successful login (with username and with email)
    7. Wrong password rejection (anti-enumeration generic message)
    8. Non-existent user login rejection
    9. Session logout & protected route redirection
    10. Role assignment & UserMixin capabilities
"""

import os
import sys
import pytest

# Ensure platform module is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "platform")))

from app import create_app
from extensions import db
from models import User, Score, Log


@pytest.fixture
def app():
    """Create and configure an application instance for testing."""
    test_app = create_app("testing")
    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client for HTTP requests."""
    return app.test_client()


@pytest.fixture
def registered_user(app):
    """Fixture providing a pre-registered test user."""
    with app.app_context():
        user = User(
            username="test_operative",
            email="operative@cyberbank.local",
            role="player",
        )
        user.set_password("CorrectHorseBatteryStaple!123")
        score = Score(user=user, total_score=0)
        db.session.add(user)
        db.session.add(score)
        db.session.commit()
        return user.id


# ============================================================
# 1. Registration Tests
# ============================================================

def test_successful_registration_form(client, app):
    """Test successful user registration via HTML form."""
    response = client.post(
        "/register",
        data={
            "username": "neo_anderson",
            "email": "neo@matrix.local",
            "password": "SuperSecretPass123!",
            "confirm_password": "SuperSecretPass123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Registration successful" in response.data or b"Please log in" in response.data

    with app.app_context():
        user = User.query.filter_by(username="neo_anderson").first()
        assert user is not None
        assert user.email == "neo@matrix.local"
        assert user.role == "player"
        assert user.check_password("SuperSecretPass123!") is True
        assert user.password_hash != "SuperSecretPass123!"

        # Verify initial score record
        score = Score.query.filter_by(user_id=user.id).first()
        assert score is not None
        assert score.total_score == 0

        # Verify registration audit log
        log = Log.query.filter_by(user_id=user.id, event_type="register").first()
        assert log is not None


def test_successful_registration_json(client, app):
    """Test successful user registration via JSON API."""
    response = client.post(
        "/register",
        json={
            "username": "trinity_hack",
            "email": "trinity@matrix.local",
            "password": "SecurePassword456!",
            "confirm_password": "SecurePassword456!",
        },
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "trinity_hack"
    assert data["user"]["email"] == "trinity@matrix.local"
    assert data["user"]["role"] == "player"


def test_duplicate_username(client, registered_user):
    """Test registration failure when username is already taken."""
    response = client.post(
        "/register",
        json={
            "username": "test_operative",
            "email": "different_email@cyberbank.local",
            "password": "AnotherPassword123!",
            "confirm_password": "AnotherPassword123!",
        },
    )
    assert response.status_code == 409
    data = response.get_json()
    assert data["status"] == "error"
    assert "Username is already registered" in data["message"]


def test_duplicate_email(client, registered_user):
    """Test registration failure when email is already registered."""
    response = client.post(
        "/register",
        json={
            "username": "unique_username_99",
            "email": "operative@cyberbank.local",
            "password": "AnotherPassword123!",
            "confirm_password": "AnotherPassword123!",
        },
    )
    assert response.status_code == 409
    data = response.get_json()
    assert data["status"] == "error"
    assert "Email address is already registered" in data["message"]


def test_registration_validation_short_password(client):
    """Test registration failure when password is less than 8 characters."""
    response = client.post(
        "/register",
        json={
            "username": "valid_user",
            "email": "valid@cyberbank.local",
            "password": "short",
            "confirm_password": "short",
        },
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "at least 8 characters" in data["message"]


def test_registration_validation_mismatched_password(client):
    """Test registration failure when passwords do not match."""
    response = client.post(
        "/register",
        json={
            "username": "valid_user",
            "email": "valid@cyberbank.local",
            "password": "Password123!",
            "confirm_password": "DifferentPassword123!",
        },
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "Passwords do not match" in data["message"]


def test_registration_validation_invalid_email(client):
    """Test registration failure on invalid email format."""
    response = client.post(
        "/register",
        json={
            "username": "valid_user",
            "email": "not-an-email",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "valid email address" in data["message"]


def test_registration_validation_invalid_username(client):
    """Test registration failure on invalid username format (spaces/special chars)."""
    response = client.post(
        "/register",
        json={
            "username": "bad user@name!",
            "email": "valid@cyberbank.local",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "letters, numbers, and underscores" in data["message"]


# ============================================================
# 2. Login Tests
# ============================================================

def test_successful_login_with_username(client, registered_user):
    """Test successful login using username identifier."""
    response = client.post(
        "/login",
        json={
            "identifier": "test_operative",
            "password": "CorrectHorseBatteryStaple!123",
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "test_operative"
    assert data["user"]["role"] == "player"


def test_successful_login_with_email(client, registered_user):
    """Test successful login using email identifier."""
    response = client.post(
        "/login",
        json={
            "identifier": "operative@cyberbank.local",
            "password": "CorrectHorseBatteryStaple!123",
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["user"]["username"] == "test_operative"


def test_wrong_password(client, registered_user, app):
    """Test login failure with incorrect password returns generic secure error."""
    response = client.post(
        "/login",
        json={
            "identifier": "test_operative",
            "password": "WrongPassword999!",
        },
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Invalid username or password."

    # Verify failed login was logged
    with app.app_context():
        log = Log.query.filter_by(event_type="login_failed").first()
        assert log is not None


def test_nonexistent_user_login(client):
    """Test login with non-existent user returns the identical generic error."""
    response = client.post(
        "/login",
        json={
            "identifier": "phantom_user_does_not_exist",
            "password": "SomePassword123!",
        },
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data["status"] == "error"
    assert data["message"] == "Invalid username or password."


# ============================================================
# 3. Logout & Session Protection Tests
# ============================================================

def test_successful_logout(client, registered_user):
    """Test user logout terminates the active session."""
    login_resp = client.post(
        "/login",
        json={
            "identifier": "test_operative",
            "password": "CorrectHorseBatteryStaple!123",
        },
    )
    assert login_resp.status_code == 200

    logout_resp = client.post("/logout", headers={"Accept": "application/json"})
    assert logout_resp.status_code == 200
    data = logout_resp.get_json()
    assert data["status"] == "success"
    assert "logged out" in data["message"].lower()


def test_unauthenticated_logout_redirects(client):
    """Test calling /logout without being authenticated triggers redirect to login."""
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


# ============================================================
# 4. Security & Role Tests
# ============================================================

def test_password_hashing_security(app):
    """Verify Werkzeug generates unique salted hashes for identical passwords."""
    with app.app_context():
        u1 = User(username="user_one", email="u1@test.local")
        u2 = User(username="user_two", email="u2@test.local")
        pwd = "SamePasswordAcrossUsers!123"

        u1.set_password(pwd)
        u2.set_password(pwd)

        assert u1.password_hash != u2.password_hash
        assert pwd not in u1.password_hash
        assert pwd not in u2.password_hash

        assert u1.check_password(pwd) is True
        assert u2.check_password(pwd) is True
        assert u1.check_password("wrong") is False


def test_admin_role_capabilities(app):
    """Verify role flags work accurately for player and admin."""
    with app.app_context():
        player = User(username="player1", email="p1@test.local", role="player")
        admin = User(username="admin1", email="a1@test.local", role="admin")

        assert player.is_admin is False
        assert admin.is_admin is True


# ============================================================
# 5. Realtime Registration Availability Tests
# ============================================================

def test_check_availability_username_success(client):
    """Verify availability check returns true for unique valid callsign."""
    resp = client.get("/check-availability?field=username&value=unique_operative_007")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["valid"] is True
    assert data["available"] is True


def test_check_availability_username_taken(client, registered_user):
    """Verify availability check returns false for existing callsign."""
    resp = client.get("/check-availability?field=username&value=test_operative")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["valid"] is True
    assert data["available"] is False
    assert "already registered" in data["message"]


def test_check_availability_username_invalid_format(client):
    """Verify availability check rejects invalid format callsign."""
    resp = client.get("/check-availability?field=username&value=no")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["valid"] is False
    assert data["available"] is False


def test_check_availability_email_success(client):
    """Verify availability check returns true for valid new email."""
    resp = client.get("/check-availability?field=email&value=fresh@cyberbank.local")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["valid"] is True
    assert data["available"] is True


def test_check_availability_email_taken(client, registered_user):
    """Verify availability check returns false for existing registered email."""
    resp = client.get("/check-availability?field=email&value=operative@cyberbank.local")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert data["valid"] is True
    assert data["available"] is False
    assert "already registered" in data["message"]


def test_check_availability_invalid_field(client):
    """Verify availability check returns 400 for unknown field."""
    resp = client.get("/check-availability?field=unknown&value=test")
    assert resp.status_code == 400

