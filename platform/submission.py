"""
CyberBank: Operation BlackVault
Flag Submission Blueprint & Controller

Routes:
    POST /submit                     - Generic submission endpoint
    POST /challenges/<id>/submit     - Challenge-specific submission endpoint
"""

import datetime
from flask import (
    Blueprint,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
)
from flask_login import login_required, current_user
from extensions import db
from models import Challenge, Submission, Score, Log
from flag_service import (
    normalize_flag,
    validate_flag_format,
    verify_flag,
    is_canary_flag,
)
from scoring_service import (
    has_user_solved,
    get_solved_challenge_ids,
    award_challenge_score,
    get_user_score,
    deduct_wrong_submission_penalty,
)

submission_bp = Blueprint("submission", __name__)


def prefers_json() -> bool:
    """Detect if client expects a JSON response."""
    return (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


from hint_service import (
    calculate_effective_points,
    get_challenge_hints_for_user,
    unlock_hint,
)

# In-memory sliding window submission rate limiter: {user_id: [timestamps]}
import time
from collections import defaultdict
_submission_history = defaultdict(list)
RATE_LIMIT_WINDOW = 30  # seconds
MAX_SUBMISSIONS_PER_WINDOW = 5


def reset_rate_limits():
    """Reset rate limiting history."""
    _submission_history.clear()


def check_rate_limit(user_id: int) -> bool:
    """Returns True if within rate limit, False if exceeded."""
    from flask import current_app
    # In automated tests, only enforce if explicitly enabled
    if current_app.config.get("TESTING") and not current_app.config.get("ENFORCE_RATE_LIMITS"):
        return True

    now = time.time()
    # Clean expired timestamps
    _submission_history[user_id] = [
        t for t in _submission_history[user_id] if now - t < RATE_LIMIT_WINDOW
    ]
    if len(_submission_history[user_id]) >= MAX_SUBMISSIONS_PER_WINDOW:
        return False
    _submission_history[user_id].append(now)
    return True


@submission_bp.route("/challenges/<int:challenge_id>/hints", methods=["GET"])
@login_required
def get_hints(challenge_id: int):
    """Retrieve the 3 hints for a challenge with unlock status."""
    challenge = db.session.get(Challenge, challenge_id)
    if not challenge or not challenge.is_active:
        return jsonify({"status": "error", "message": "Challenge not found."}), 404

    # Check stage lock
    if challenge.dependency_id is not None:
        solved = Submission.query.filter_by(
            user_id=current_user.id, challenge_id=challenge.dependency_id, success=True
        ).first()
        if not solved:
            return jsonify({
                "status": "locked",
                "message": f"Stage #{challenge.stage_number} is locked.",
            }), 403

    hints_data = get_challenge_hints_for_user(current_user.id, challenge.id)
    return jsonify({
        "status": "success",
        "stage_number": challenge.stage_number,
        "hints": hints_data,
    }), 200


@submission_bp.route("/challenges/<int:challenge_id>/hints/<int:hint_number>/unlock", methods=["POST"])
@login_required
def unlock_hint_route(challenge_id: int, hint_number: int):
    """Unlock a sequential hint for a challenge."""
    success, msg, hint_data = unlock_hint(current_user.id, challenge_id, hint_number)
    status_code = 200 if success else 400
    if not success and "locked" in msg.lower():
        status_code = 403

    return jsonify({
        "status": "success" if success else "error",
        "message": msg,
        "hint": hint_data,
    }), status_code


@submission_bp.route("/submit", methods=["POST"])
@submission_bp.route("/challenges/<int:challenge_id>/submit", methods=["POST"])
@login_required
def submit_flag(challenge_id: int = None):
    """
    Handle flag submission attempt.
    Supports JSON API requests and standard HTML form posts.
    Enforces Rate Limiting, AI Canary Trap detection, and dependency checks.
    """
    user_id = current_user.id

    # 0. Anti-Brute-Force Rate Limiting
    if not check_rate_limit(user_id):
        log_rate = Log(
            user_id=user_id,
            challenge_id=challenge_id,
            event_type="rate_limit_exceeded",
            message=f"Operative '{current_user.username}' exceeded submission rate limit (5 submits / 30s).",
        )
        db.session.add(log_rate)
        db.session.commit()

        msg = "Rate limit exceeded. Too many rapid submission attempts. Please wait 30 seconds."
        if prefers_json():
            return jsonify({"status": "rate_limited", "message": msg}), 429
        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    raw_flag = ""

    if request.is_json:
        data = request.get_json() or {}
        if challenge_id is None:
            challenge_id = data.get("challenge_id") or data.get("id")
        raw_flag = data.get("flag") or data.get("flag_input", "")
    else:
        if challenge_id is None:
            challenge_id = request.form.get("challenge_id") or request.form.get("id")
        raw_flag = request.form.get("flag") or request.form.get("flag_input", "")

    # 1. Parameter Validation
    try:
        challenge_id = int(challenge_id)
    except (TypeError, ValueError):
        msg = "Invalid or missing challenge identifier."
        if prefers_json():
            return jsonify({"status": "error", "message": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    challenge = db.session.get(Challenge, challenge_id)
    if not challenge or not challenge.is_active:
        msg = "Challenge not found or currently inactive."
        if prefers_json():
            return jsonify({"status": "error", "message": msg}), 404
        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # 1.5 2-Hour Mission Time Limit Enforcement
    MISSION_LIMIT_SECONDS = 7200
    if current_user.role != "admin" and current_user.created_at:
        now = datetime.datetime.utcnow()
        elapsed_seconds = (now - current_user.created_at).total_seconds()
        if elapsed_seconds > MISSION_LIMIT_SECONDS:
            log_expired = Log(
                user_id=user_id,
                challenge_id=challenge.id,
                event_type="mission_time_expired",
                message=f"Operative '{current_user.username}' attempted submission after 2-hour mission limit elapsed ({int(elapsed_seconds)}s > 7200s).",
            )
            db.session.add(log_expired)
            db.session.commit()

            msg = "Mission window expired. Your 2-hour infiltration allowance has lapsed. Challenge submissions are now closed."
            if prefers_json():
                return jsonify({
                    "status": "expired",
                    "message": msg,
                    "time_expired": True,
                }), 403
            flash(msg, "danger")
            return redirect(url_for("dashboard.dashboard_view"))

    # 2. Flag Sanitization & Normalization
    candidate_flag = normalize_flag(raw_flag)
    if not candidate_flag:
        msg = "Flag submission cannot be empty."
        if prefers_json():
            return jsonify({"status": "error", "message": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # 3. Anti-AI Canary Trap Detection
    if is_canary_flag(candidate_flag):
        new_total_score = deduct_wrong_submission_penalty(user_id, penalty=10)
        sub_canary = Submission(
            user_id=user_id,
            challenge_id=challenge.id,
            success=False,
            score_awarded=0,
        )
        log_canary = Log(
            user_id=user_id,
            challenge_id=challenge.id,
            event_type="anti_cheat_canary_triggered",
            message=f"SECURITY ALERT: Operative '{current_user.username}' tripped Anti-AI Prompt Canary Trap on Stage #{challenge.stage_number}. -10 PTS penalty applied.",
        )
        db.session.add(sub_canary)
        db.session.add(log_canary)
        db.session.commit()

        msg = "Security Violation: Anti-AI Prompt Canary Trap detected. -10 PTS penalty applied."
        if prefers_json():
            return jsonify({
                "status": "canary_triggered",
                "message": msg,
                "violation": True,
                "penalty_points": 10,
                "new_total_score": new_total_score,
            }), 400
        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # 4. Duplicate Solve Check
    if has_user_solved(user_id, challenge.id):
        log_dup = Log(
            user_id=user_id,
            challenge_id=challenge.id,
            event_type="flag_duplicate",
            message=f"Operative '{current_user.username}' attempted repeated solve for Stage #{challenge.stage_number}.",
        )
        db.session.add(log_dup)
        db.session.commit()

        msg = "You have already completed this stage. Points were already awarded."
        if prefers_json():
            return jsonify({
                "status": "duplicate",
                "message": msg,
                "stage_number": challenge.stage_number,
                "already_solved": True,
            }), 409
        flash(msg, "warning")
        return redirect(url_for("dashboard.dashboard_view"))

    # 5. Challenge Dependency & Prerequisite Check
    if challenge.dependency_id is not None:
        solved_ids = get_solved_challenge_ids(user_id)
        if challenge.dependency_id not in solved_ids:
            dep_stage = challenge.dependency.stage_number if challenge.dependency else "?"
            msg = f"Access denied: Stage #{challenge.stage_number} is locked. You must solve Stage #{dep_stage} first."
            if prefers_json():
                return jsonify({"status": "locked", "message": msg}), 403
            flash(msg, "danger")
            return redirect(url_for("dashboard.dashboard_view"))

    # 6. Format Validation
    if not validate_flag_format(candidate_flag):
        new_total_score = deduct_wrong_submission_penalty(user_id, penalty=10)
        msg = "Invalid flag format. Flags must follow the CBANK{...} structure. (-10 PTS penalty applied)"
        # Record failed attempt due to malformed flag
        sub_fail = Submission(
            user_id=user_id,
            challenge_id=challenge.id,
            success=False,
            score_awarded=0,
        )
        log_malformed = Log(
            user_id=user_id,
            challenge_id=challenge.id,
            event_type="flag_malformed",
            message=f"Operative '{current_user.username}' submitted malformed flag for Stage #{challenge.stage_number}. -10 PTS penalty applied.",
        )
        db.session.add(sub_fail)
        db.session.add(log_malformed)
        db.session.commit()

        if prefers_json():
            return jsonify({
                "status": "error",
                "message": msg,
                "penalty_points": 10,
                "new_total_score": new_total_score,
            }), 400
        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # 6. Cryptographic Flag Verification
    is_correct = verify_flag(candidate_flag, challenge.flag_hash)

    if is_correct:
        # Successful solve - Calculate score adjusted for hint penalties
        points_to_award = calculate_effective_points(challenge, user_id)
        sub = Submission(
            user_id=user_id,
            challenge_id=challenge.id,
            success=True,
            score_awarded=points_to_award,
        )
        new_total_score = award_challenge_score(user_id, points_to_award)

        log_success = Log(
            user_id=user_id,
            challenge_id=challenge.id,
            event_type="flag_correct",
            message=f"Operative '{current_user.username}' solved Stage #{challenge.stage_number} ('{challenge.title}') for +{points_to_award} pts.",
        )
        db.session.add(sub)
        db.session.add(log_success)
        db.session.commit()

        msg = f"Clearance Granted! Flag accepted for Stage 0{challenge.stage_number}. +{points_to_award} PTS awarded."
        if prefers_json():
            return jsonify({
                "status": "success",
                "message": msg,
                "stage_number": challenge.stage_number,
                "challenge_title": challenge.title,
                "points_awarded": points_to_award,
                "new_total_score": new_total_score,
                "mission_completed": True if challenge.stage_number == 6 else False,
            }), 200

        flash(msg, "success")
        if challenge.stage_number == 6:
            return redirect(url_for("dashboard.completion_view"))
        return redirect(url_for("dashboard.dashboard_view"))

    else:
        # Failed solve
        new_total_score = deduct_wrong_submission_penalty(user_id, penalty=10)

        sub_fail = Submission(
            user_id=user_id,
            challenge_id=challenge.id,
            success=False,
            score_awarded=0,
        )
        log_fail = Log(
            user_id=user_id,
            challenge_id=challenge.id,
            event_type="flag_incorrect",
            message=f"Incorrect flag attempt by '{current_user.username}' on Stage #{challenge.stage_number}. -10 PTS penalty applied.",
        )
        db.session.add(sub_fail)
        db.session.add(log_fail)
        db.session.commit()

        msg = "Incorrect flag submitted. -10 PTS penalty applied. Verify your findings and try again."
        if prefers_json():
            return jsonify({
                "status": "incorrect",
                "message": msg,
                "stage_number": challenge.stage_number,
                "penalty_points": 10,
                "new_total_score": new_total_score,
            }), 400

        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))
