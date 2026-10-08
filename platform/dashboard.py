"""
CyberBank: Operation BlackVault
Dashboard & Access Control Blueprint

Provides:
    - Protected Player Dashboard (/dashboard)
    - Challenge progression status resolution (locked / available / completed)
    - Player statistics (score, progress percentage, solves)
    - Role-based access control decorators (@admin_required)
    - Protected Admin Area (/admin) for access control validation
"""

from functools import wraps
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
)
from flask_login import login_required, current_user
import datetime
from models import Challenge, Submission, User, Score, Log, HintUsage
from extensions import db

dashboard_bp = Blueprint("dashboard", __name__)


# ============================================================
# Access Control Decorators
# ============================================================

def admin_required(f):
    """
    Enforce administrator privileges on protected routes.
    Standard players (role='player') are forbidden (HTTP 403).
    """
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            if (
                request.is_json
                or request.headers.get("Accept", "").startswith("application/json")
            ):
                return jsonify({
                    "status": "error",
                    "message": "Access denied: Administrator clearance required.",
                }), 403

            flash("Access denied: Administrator clearance required.", "danger")
            return redirect(url_for("dashboard.dashboard_view"))
        return f(*args, **kwargs)

    return decorated_function


# ============================================================
# Status Computation Helper
# ============================================================

def resolve_challenge_statuses(user_id: int):
    """
    Compute progression status for all active challenges for a given user.
    Returns: (list_of_challenge_dicts, completed_count, total_count, progress_percentage)
    """
    challenges = (
        Challenge.query.filter_by(is_active=True)
        .order_by(Challenge.stage_number.asc())
        .all()
    )

    # Get set of successfully solved challenge IDs by this user
    solved_submissions = Submission.query.filter_by(
        user_id=user_id, success=True
    ).all()
    solved_ids = {sub.challenge_id for sub in solved_submissions}

    challenge_items = []
    completed_count = 0

    for chal in challenges:
        if chal.id in solved_ids:
            status = "completed"
            completed_count += 1
        elif chal.dependency_id is None or chal.dependency_id in solved_ids:
            status = "available"
        else:
            status = "locked"

        challenge_items.append({
            "id": chal.id,
            "stage_number": chal.stage_number,
            "title": chal.title,
            "domain": chal.domain,
            "difficulty": chal.difficulty,
            "description": chal.description,
            "objective": chal.objective,
            "points": chal.points,
            "dependency_id": chal.dependency_id,
            "status": status,
        })

    total_count = len(challenges)
    progress_percentage = (
        round((completed_count / total_count) * 100) if total_count > 0 else 0
    )

    return challenge_items, completed_count, total_count, progress_percentage


# ============================================================
# Routes
# ============================================================

@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard_view():
    """
    Player CTF Mission Control.
    Displays operative telemetry, score, progress %, and all six stages.
    """
    (
        challenges_list,
        completed_count,
        total_count,
        progress_percentage,
    ) = resolve_challenge_statuses(current_user.id)

    total_score = current_user.score.total_score if current_user.score else 0

    # API / JSON response
    if (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
        or request.args.get("format") == "json"
    ):
        return jsonify({
            "status": "success",
            "user": {
                "id": current_user.id,
                "username": current_user.username,
                "email": current_user.email,
                "role": current_user.role,
                "total_score": total_score,
                "completed_challenges": completed_count,
                "total_challenges": total_count,
                "progress_percentage": progress_percentage,
            },
            "challenges": challenges_list,
        }), 200

    from scoring_service import get_leaderboard_standings, format_countdown
    standings, _ = get_leaderboard_standings()

    # 2-Hour Mission Allowance (7200 seconds)
    MISSION_LIMIT_SECONDS = 7200
    now = datetime.datetime.utcnow()
    if current_user.created_at:
        elapsed_seconds = max(0, int((now - current_user.created_at).total_seconds()))
    else:
        elapsed_seconds = 0
    time_remaining_seconds = max(0, MISSION_LIMIT_SECONDS - elapsed_seconds)
    time_remaining_formatted = format_countdown(time_remaining_seconds)

    user_time_taken = None
    for s in standings:
        if s["username"] == current_user.username:
            user_time_taken = s["time_taken"]
            break

    # Web template response
    return render_template(
        "dashboard.html",
        user=current_user,
        username=current_user.username,
        role=current_user.role,
        total_score=total_score,
        completed_count=completed_count,
        solved_count=completed_count,
        total_count=total_count,
        progress_percentage=progress_percentage,
        challenges=challenges_list,
        standings=standings,
        user_time_taken=user_time_taken,
        time_remaining_seconds=time_remaining_seconds,
        time_remaining_formatted=time_remaining_formatted,
    )


@dashboard_bp.route("/mission/reset-timer", methods=["GET", "POST"])
@login_required
def reset_mission_timer():
    """
    Tournament mission clocks are immutable in live competition conditions.
    Players cannot reset their own mission clock.
    """
    if current_user.role != "admin":
        flash("Tournament mission clocks cannot be reset once started.", "warning")
        return redirect(url_for("dashboard.dashboard_view"))

    current_user.created_at = datetime.datetime.utcnow()
    db.session.commit()
    flash("Admin reset: 2-Hour Mission Clock initialized.", "success")
    return redirect(url_for("dashboard.dashboard_view"))


@dashboard_bp.route("/challenges/<int:challenge_id>", methods=["GET"])
@dashboard_bp.route("/challenges/stage/<int:stage_number>", methods=["GET"])
@login_required
def challenge_detail_view(challenge_id: int = None, stage_number: int = None):
    """
    Direct access to a challenge details endpoint.
    Strictly verifies server-side prerequisite unlocks from the database.
    Direct URL access to locked stages returns HTTP 403 Forbidden.
    """
    if challenge_id is not None:
        challenge = db.session.get(Challenge, challenge_id)
    elif stage_number is not None:
        challenge = Challenge.query.filter_by(stage_number=stage_number).first()
    else:
        challenge = None

    if not challenge or not challenge.is_active:
        if (
            request.is_json
            or request.headers.get("Accept", "").startswith("application/json")
        ):
            return jsonify({"status": "error", "message": "Challenge not found."}), 404
        flash("Challenge not found.", "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # Server-side unlock status verification from database
    solved_submissions = Submission.query.filter_by(
        user_id=current_user.id, success=True
    ).all()
    solved_ids = {sub.challenge_id for sub in solved_submissions}

    if challenge.dependency_id is not None and challenge.dependency_id not in solved_ids:
        # Challenge is locked! Reject direct URL access
        dep_stage = challenge.dependency.stage_number if challenge.dependency else "?"
        msg = f"Access Denied: Stage #{challenge.stage_number} is locked. You must solve Stage #{dep_stage} first."

        # Audit log the unauthorized direct access attempt
        log_entry = Log(
            user_id=current_user.id,
            challenge_id=challenge.id,
            event_type="access_denied_locked_stage",
            message=f"Operative '{current_user.username}' attempted direct URL access to locked Stage #{challenge.stage_number}.",
        )
        db.session.add(log_entry)
        db.session.commit()

        if (
            request.is_json
            or request.headers.get("Accept", "").startswith("application/json")
        ):
            return jsonify({
                "status": "locked",
                "error": "Forbidden",
                "message": msg,
                "stage_number": challenge.stage_number,
                "required_stage": dep_stage,
            }), 403

        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # Challenge is unlocked (available or completed)
    from hint_service import get_challenge_hints_for_user
    hints_data = get_challenge_hints_for_user(current_user.id, challenge.id)
    status = "completed" if challenge.id in solved_ids else "available"

    chal_data = {
        "id": challenge.id,
        "stage_number": challenge.stage_number,
        "title": challenge.title,
        "domain": challenge.domain,
        "difficulty": challenge.difficulty,
        "description": challenge.description,
        "objective": challenge.objective,
        "points": challenge.points,
        "status": status,
        "hints": hints_data,
    }

    if (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
    ):
        return jsonify({
            "status": "success",
            "challenge": chal_data,
        }), 200

    return render_template("challenge_view.html", challenge=chal_data, hints=hints_data)


@dashboard_bp.route("/admin", methods=["GET"])
@admin_required
def admin_view():
    """
    Administrator Control Panel.
    Protected by server-side @admin_required access control.
    """
    total_users = User.query.count()
    total_challenges = Challenge.query.count()
    total_submissions = Submission.query.count()
    anti_cheat_count = Log.query.filter(
        (Log.event_type.like("%canary%")) | (Log.event_type.like("%rate_limit%"))
    ).count()

    users_list = User.query.order_by(User.id.asc()).all()
    recent_submissions = (
        Submission.query.order_by(Submission.submitted_at.desc()).limit(10).all()
    )
    recent_logs = Log.query.order_by(Log.created_at.desc()).limit(20).all()

    from scoring_service import get_leaderboard_standings
    standings, _ = get_leaderboard_standings()

    if (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
    ):
        return jsonify({
            "status": "success",
            "admin_telemetry": {
                "total_users": total_users,
                "total_challenges": total_challenges,
                "total_submissions": total_submissions,
                "anti_cheat_count": anti_cheat_count,
            },
            "standings": standings,
        }), 200

    return render_template(
        "admin.html",
        total_users=total_users,
        total_challenges=total_challenges,
        total_submissions=total_submissions,
        anti_cheat_count=anti_cheat_count,
        users_list=users_list,
        recent_submissions=recent_submissions,
        recent_logs=recent_logs,
        standings=standings,
    )


@dashboard_bp.route("/completion", methods=["GET"])
@login_required
def completion_view():
    """
    Operation BlackVault Final Completion Screen.
    Accessible once the operative has successfully solved Stage 06.
    """
    solved_submissions = Submission.query.filter_by(
        user_id=current_user.id, success=True
    ).all()
    solved_chal_ids = {sub.challenge_id for sub in solved_submissions}

    c6 = Challenge.query.filter_by(stage_number=6).first()
    if not c6 or c6.id not in solved_chal_ids:
        flash("Clearance Denied: You must complete all infiltration stages before accessing Operation Completion.", "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    score_rec = Score.query.filter_by(user_id=current_user.id).first()
    total_score = score_rec.total_score if score_rec else 0
    hints_used = HintUsage.query.filter_by(user_id=current_user.id).count()

    c6_sub = Submission.query.filter_by(
        user_id=current_user.id, challenge_id=c6.id, success=True
    ).order_by(Submission.submitted_at.desc()).first()

    completion_time = (
        c6_sub.submitted_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if c6_sub and c6_sub.submitted_at
        else datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    all_challenges = Challenge.query.order_by(Challenge.stage_number.asc()).all()
    stages_summary = [
        {
            "stage_number": c.stage_number,
            "title": c.title,
            "domain": c.domain,
            "points": c.points,
        }
        for c in all_challenges
    ]

    if (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
    ):
        return jsonify({
            "status": "success",
            "operation": "Operation BlackVault Completed",
            "total_score": total_score,
            "completed_challenges": "6/6",
            "hints_used": hints_used,
            "completion_time": completion_time,
            "stages": stages_summary,
        }), 200

    from scoring_service import get_leaderboard_standings
    standings, _ = get_leaderboard_standings()

    user_time_taken = None
    for s in standings:
        if s["username"] == current_user.username:
            user_time_taken = s["time_taken"]
            break

    return render_template(
        "completion.html",
        total_score=total_score,
        hints_used=hints_used,
        completion_time=completion_time,
        stages_summary=stages_summary,
        standings=standings,
        user_time_taken=user_time_taken,
    )


@dashboard_bp.route("/scoreboard", methods=["GET"])
def scoreboard_view():
    """
    Live CyberBank Scoreboard / Leaderboard.
    Restricted: Only operatives who have breached all stages (or administrators)
    can view the classified scoreboard.
    """
    from scoring_service import get_leaderboard_standings
    standings, total_challenges = get_leaderboard_standings()

    # Access check: Admin is always allowed; players must have completed all stages
    if current_user.is_authenticated and current_user.role == "admin":
        is_allowed = True
    elif current_user.is_authenticated and current_user.role == "player":
        solved_count = Submission.query.filter_by(
            user_id=current_user.id, success=True
        ).count()
        is_allowed = (solved_count >= total_challenges)
    else:
        is_allowed = False

    if not is_allowed:
        msg = f"Access Denied: The Scoreboard is classified until you complete all {total_challenges} stages of Operation BlackVault."
        if (
            request.is_json
            or request.headers.get("Accept", "").startswith("application/json")
            or request.args.get("format") == "json"
        ):
            return jsonify({"status": "error", "message": msg}), 403

        if not current_user.is_authenticated:
            flash("Please sign in with an operative account that has completed all stages to view the scoreboard.", "warning")
            return redirect(url_for("auth.login"))

        flash(msg, "danger")
        return redirect(url_for("dashboard.dashboard_view"))

    # JSON response
    if (
        request.is_json
        or request.headers.get("Accept", "").startswith("application/json")
        or request.args.get("format") == "json"
    ):
        return jsonify({
            "status": "success",
            "total_challenges": total_challenges,
            "standings": [
                {
                    "rank": s["rank"],
                    "username": s["username"],
                    "total_score": s["total_score"],
                    "solved_count": s["solved_count"],
                    "completed": s["completed"],
                    "time_taken": s["time_taken"],
                    "duration_seconds": s["duration_seconds"],
                    "last_solve_time": (
                        s["last_solve_time"].strftime("%Y-%m-%d %H:%M:%S")
                        if s["last_solve_time"]
                        else None
                    ),
                }
                for s in standings
            ],
        }), 200

    return render_template(
        "scoreboard.html",
        standings=standings,
        total_challenges=total_challenges,
    )

