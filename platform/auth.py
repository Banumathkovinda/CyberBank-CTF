"""
CyberBank: Operation BlackVault
Authentication Blueprint

Handles user registration, login, logout, and session lifecycle.
Implements:
    - Werkzeug secure password hashing
    - Defensive input validation (regex, length bounds)
    - Anti-user-enumeration error responses
    - Duplicate username / email handling
    - Role-aware authentication (player / admin)
    - Open-redirect mitigation on login
    - Dual response support (HTML templates + JSON API)
    - Security event audit logging
"""

import re
from urllib.parse import urlsplit
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app,
)
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
from models import User, Score, Log

auth_bp = Blueprint("auth", __name__)

# RFC 5322 compliant simplified email regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# Alphanumeric + underscore, 3-30 chars
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


def is_safe_url(target: str) -> bool:
    """Ensure redirect target URL is relative and on the same host (prevent open redirects)."""
    if not target:
        return False
    ref_url = urlsplit(request.host_url)
    test_url = urlsplit(target)
    return test_url.scheme in ("", "http", "https") and ref_url.netloc == (
        test_url.netloc or ref_url.netloc
    )


def prefers_json() -> bool:
    """Detect if client is requesting a JSON response (API client or curl)."""
    return (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def validate_registration_input(username, email, password, confirm_password):
    """
    Validate user registration inputs.
    Returns: (is_valid: bool, error_message: str | None)
    """
    if not username or not username.strip():
        return False, "Username is required."
    username = username.strip()
    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3-30 characters long and contain only letters, numbers, and underscores."

    if not email or not email.strip():
        return False, "Email address is required."
    email = email.strip().lower()
    if len(email) > 200 or not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."

    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."

    if password != confirm_password:
        return False, "Passwords do not match."

    return True, None


# ============================================================
# Routes
# ============================================================

@auth_bp.route("/check-availability", methods=["GET", "POST"])
def check_availability():
    """Realtime check for username or email availability and formatting."""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
    else:
        data = request.args

    field = (data.get("field") or "").strip().lower()
    value = (data.get("value") or "").strip()

    if field == "username":
        if not value:
            return jsonify({
                "status": "error",
                "valid": False,
                "available": False,
                "message": "Callsign is required.",
            })
        if not USERNAME_REGEX.match(value):
            return jsonify({
                "status": "error",
                "valid": False,
                "available": False,
                "message": "Must be 3-30 characters (letters, numbers, underscores only).",
            })
        exists = User.query.filter_by(username=value).first() is not None
        if exists:
            return jsonify({
                "status": "success",
                "valid": True,
                "available": False,
                "message": "Callsign is already registered by another operative.",
            })
        return jsonify({
            "status": "success",
            "valid": True,
            "available": True,
            "message": "Callsign is available for BlackVault clearance.",
        })

    elif field == "email":
        value_lower = value.lower()
        if not value_lower:
            return jsonify({
                "status": "error",
                "valid": False,
                "available": False,
                "message": "Email address is required.",
            })
        if len(value_lower) > 200 or not EMAIL_REGEX.match(value_lower):
            return jsonify({
                "status": "error",
                "valid": False,
                "available": False,
                "message": "Please enter a valid email address.",
            })
        exists = User.query.filter_by(email=value_lower).first() is not None
        if exists:
            return jsonify({
                "status": "success",
                "valid": True,
                "available": False,
                "message": "Email is already registered. Please log in or use another.",
            })
        return jsonify({
            "status": "success",
            "valid": True,
            "available": True,
            "message": "Email address is available.",
        })

    return jsonify({"status": "error", "message": "Invalid field specified."}), 400


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Handle user registration."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        # Extract inputs from JSON or Form Data
        if request.is_json:
            data = request.get_json() or {}
            username = data.get("username", "")
            email = data.get("email", "")
            password = data.get("password", "")
            confirm_password = data.get("confirm_password", "")
            role = data.get("role", "player")
        else:
            username = request.form.get("username", "")
            email = request.form.get("email", "")
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            role = "player"

        username = username.strip()
        email = email.strip().lower()

        # 1. Input Validation
        is_valid, error_msg = validate_registration_input(
            username, email, password, confirm_password
        )
        if not is_valid:
            if prefers_json():
                return jsonify({"status": "error", "message": error_msg}), 400
            flash(error_msg, "danger")
            return render_template(
                "register.html",
                username=username,
                email=email,
            ), 400

        # 2. Duplicate Username Check
        if User.query.filter_by(username=username).first():
            msg = "Username is already registered. Please choose a different username."
            if prefers_json():
                return jsonify({"status": "error", "message": msg}), 409
            flash(msg, "danger")
            return render_template("register.html", username=username, email=email), 409

        # 3. Duplicate Email Check
        if User.query.filter_by(email=email).first():
            msg = "Email address is already registered. Please use another email or log in."
            if prefers_json():
                return jsonify({"status": "error", "message": msg}), 409
            flash(msg, "danger")
            return render_template("register.html", username=username, email=email), 409

        # 4. Create User Record with Werkzeug Password Hash
        assigned_role = "admin" if role == "admin" and request.is_json and current_app.config.get("TESTING") else "player"
        new_user = User(
            username=username,
            email=email,
            role=assigned_role,
        )
        new_user.set_password(password)

        # 5. Initialize Score & Audit Log
        initial_score = Score(user=new_user, total_score=0)
        reg_log = Log(
            user=new_user,
            event_type="register",
            message=f"User '{username}' registered with role '{assigned_role}'.",
        )

        try:
            db.session.add(new_user)
            db.session.add(initial_score)
            db.session.add(reg_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            msg = "An unexpected error occurred during registration. Please try again."
            if prefers_json():
                return jsonify({"status": "error", "message": msg}), 500
            flash(msg, "danger")
            return render_template("register.html", username=username, email=email), 500

        # 6. Response
        if prefers_json():
            return jsonify({
                "status": "success",
                "message": "Registration successful. You can now log in.",
                "user": {
                    "id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "role": new_user.role,
                },
            }), 201

        flash("Registration successful! Access granted. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle user authentication."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        # Extract inputs from JSON or Form Data
        if request.is_json:
            data = request.get_json() or {}
            identifier = data.get("username") or data.get("email") or data.get("identifier", "")
            password = data.get("password", "")
            remember = bool(data.get("remember", False))
        else:
            identifier = request.form.get("identifier") or request.form.get("username", "")
            password = request.form.get("password", "")
            remember = bool(request.form.get("remember", False))

        identifier = identifier.strip()

        if not identifier or not password:
            msg = "Please provide both username/email and password."
            if prefers_json():
                return jsonify({"status": "error", "message": msg}), 400
            flash(msg, "danger")
            return render_template("login.html", identifier=identifier), 400

        # Look up user by username or email
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        # Secure check: Verify password using constant-time hash comparison
        if user is None or not user.check_password(password):
            # Log failed attempt without exposing which field was wrong
            failed_log = Log(
                user_id=user.id if user else None,
                event_type="login_failed",
                message=f"Failed login attempt for identifier '{identifier}'.",
            )
            db.session.add(failed_log)
            db.session.commit()

            # Generic error message to prevent user enumeration attacks
            secure_error = "Invalid username or password."
            if prefers_json():
                return jsonify({"status": "error", "message": secure_error}), 401
            flash(secure_error, "danger")
            return render_template("login.html", identifier=identifier), 401

        # Successful Login
        login_user(user, remember=remember)

        success_log = Log(
            user=user,
            event_type="login",
            message=f"User '{user.username}' logged in successfully.",
        )
        db.session.add(success_log)
        db.session.commit()

        if prefers_json():
            return jsonify({
                "status": "success",
                "message": "Authentication successful.",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                },
            }), 200

        flash(f"Welcome back, Operative {user.username}.", "success")
        next_page = request.args.get("next")
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        return redirect(url_for("index"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """Handle user logout."""
    user_id = current_user.id
    username = current_user.username

    logout_log = Log(
        user_id=user_id,
        event_type="logout",
        message=f"User '{username}' logged out.",
    )
    db.session.add(logout_log)
    db.session.commit()

    logout_user()

    if prefers_json():
        return jsonify({
            "status": "success",
            "message": "Successfully logged out.",
        }), 200

    flash("You have been safely disconnected from the BlackVault session.", "info")
    return redirect(url_for("auth.login"))
