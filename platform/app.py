"""
CyberBank: Operation BlackVault
Flask Application Factory

Routes:
    GET /        - Platform landing page (HTML / JSON)
    GET /health  - Health check with database connectivity verification
    GET /register, POST /register  - User registration
    GET /login, POST /login        - User authentication
    GET /logout, POST /logout      - User logout
    GET /dashboard                 - Player mission control
    GET /admin                     - Admin console
"""

import os
import datetime

from flask import Flask, jsonify, render_template, request
from config import Config, config_by_name
from extensions import db, migrate, login_manager


def create_app(config_name=None):
    """Application factory pattern."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, Config))

    # ---- Initialize Extensions ----
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # ---- Import Models (required for Flask-Migrate and user loader) ----
    import models  # noqa: F401

    # ---- Register Blueprints ----
    from auth import auth_bp
    from dashboard import dashboard_bp
    from submission import submission_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(submission_bp)

    # ---- Register Core Routes ----
    register_routes(app)

    # ---- Auto-initialize tables and seed challenges (with retry loop for container orchestration) ----
    if config_name != "testing":
        import time
        with app.app_context():
            max_retries = 15
            for attempt in range(1, max_retries + 1):
                try:
                    db.create_all()
                    from seed import seed_challenges, seed_default_users
                    seed_challenges()
                    seed_default_users()
                    app.logger.info("Database initialized and challenges verified successfully.")
                    break
                except Exception as e:
                    if attempt < max_retries:
                        app.logger.warning(
                            f"Database not ready yet (attempt {attempt}/{max_retries}), retrying in 2s: {e}"
                        )
                        time.sleep(2)
                    else:
                        app.logger.error(f"Database auto-init failed after {max_retries} attempts: {e}")

    return app


def register_routes(app):
    """Register core application routes."""

    @app.route("/", methods=["GET"])
    def index():
        """Platform landing page - returns HTML for browsers, JSON for API clients."""
        if (
            request.is_json
            or request.headers.get("Accept", "").startswith("application/json")
            or "curl" in request.headers.get("User-Agent", "").lower()
        ):
            return jsonify({
                "platform": "CyberBank: Operation BlackVault",
                "version": "0.1.0",
                "phase": 6,
                "description": "Capture The Flag - Cybersecurity Training Platform",
                "endpoints": {
                    "/": "This page - platform info",
                    "/health": "Health check with database status",
                    "/register": "User registration (GET / POST)",
                    "/login": "User authentication (GET / POST)",
                    "/logout": "Session termination (GET / POST)",
                    "/dashboard": "Protected player dashboard (GET)",
                    "/scoreboard": "Live player leaderboard and standings (GET)",
                    "/admin": "Restricted admin panel (GET)",
                },
                "status": "operational",
            }), 200

        from scoring_service import get_leaderboard_standings
        from models import Submission
        from flask_login import current_user

        standings, total_challenges = get_leaderboard_standings()
        user_completed_all = False
        user_rank = None
        user_time_taken = None

        if current_user.is_authenticated:
            solved_count = Submission.query.filter_by(
                user_id=current_user.id, success=True
            ).count()
            user_completed_all = (solved_count >= total_challenges)
            for s in standings:
                if s["username"] == current_user.username:
                    user_rank = s["rank"]
                    user_time_taken = s["time_taken"]
                    break

        return render_template(
            "index.html",
            standings=standings,
            total_challenges=total_challenges,
            user_completed_all=user_completed_all,
            user_rank=user_rank,
            user_time_taken=user_time_taken,
        )

    @app.route("/health", methods=["GET"])
    def health():
        """
        Health check endpoint for container orchestration.
        Verifies Flask status and database reachability.
        """
        health_status = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "flask": "running",
            "database": "unknown",
            "status": "healthy",
        }

        try:
            # Universal query compatible with SQLite, PostgreSQL, and MySQL
            db.session.execute(db.text("SELECT 1"))
            health_status["database"] = "connected"
            return jsonify(health_status), 200
        except Exception as e:
            health_status["database"] = "disconnected"
            health_status["error"] = str(e)
            health_status["status"] = "degraded"
            # Return 200 so initial startup health check does not fail while services link
            return jsonify(health_status), 200


# ---- Application Entry Point ----
app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("FLASK_PORT", 5000)),
        debug=os.environ.get("FLASK_ENV", "development") == "development",
    )
