"""
CyberBank: Operation BlackVault
Scoring & Challenge Progression Service

Provides:
    - User score calculation and updates
    - Challenge resolution and dependency tracking
    - Duplicate solve prevention
"""

import datetime
from extensions import db
from models import Score, Submission, Challenge, User


def get_user_score(user_id: int) -> int:
    """Retrieve the current total score for a user."""
    score_record = Score.query.filter_by(user_id=user_id).first()
    return score_record.total_score if score_record else 0


def has_user_solved(user_id: int, challenge_id: int) -> bool:
    """Check whether a user has already successfully solved a given challenge."""
    sub = Submission.query.filter_by(
        user_id=user_id,
        challenge_id=challenge_id,
        success=True,
    ).first()
    return sub is not None


def get_solved_challenge_ids(user_id: int) -> set[int]:
    """Get the set of challenge IDs successfully solved by the user."""
    submissions = Submission.query.filter_by(
        user_id=user_id,
        success=True,
    ).all()
    return {sub.challenge_id for sub in submissions}


def can_attempt_challenge(user_id: int, challenge: Challenge) -> tuple[bool, str | None]:
    """
    Verify if a user is permitted to attempt the challenge.
    Returns: (can_attempt: bool, reason: str | None)
    """
    if not challenge.is_active:
        return False, "This challenge is currently deactivated."

    if has_user_solved(user_id, challenge.id):
        return False, "Challenge already solved."

    if challenge.dependency_id is not None:
        solved_ids = get_solved_challenge_ids(user_id)
        if challenge.dependency_id not in solved_ids:
            return False, f"Prerequisite Stage not completed. Solve Stage #{challenge.dependency.stage_number} first."

    return True, None


def award_challenge_score(user_id: int, points: int) -> int:
    """
    Atomically update user's total score in the database.
    Returns the new updated total score.
    """
    score_record = Score.query.filter_by(user_id=user_id).first()
    if not score_record:
        score_record = Score(user_id=user_id, total_score=0)
        db.session.add(score_record)

    score_record.total_score += points
    score_record.updated_at = datetime.datetime.utcnow()
    db.session.flush()
    return score_record.total_score


def format_duration(seconds: int) -> str:
    """Format duration in seconds into clean HHh MMm SSs or MMm SSs string."""
    if seconds is None or seconds < 0:
        return "--"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if hours > 0:
        return f"{hours:02d}h {minutes:02d}m {secs:02d}s"
    return f"{minutes:02d}m {secs:02d}s"


def format_countdown(seconds: int) -> str:
    """Format remaining seconds into HH:MM:SS backward countdown string."""
    if seconds is None or seconds <= 0:
        return "00:00:00"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def get_leaderboard_standings():
    """
    Compute live scoreboard standings for all player operatives.
    Counts duration from operative start (created_at) to completion (final solve).
    Ranks by:
      1. total_score DESC (higher score ranks first)
      2. duration_seconds ASC (faster breach duration ranks higher for completed players)
      3. last_solve_time ASC
    Returns: (list_of_standings_dicts, total_challenges_int)
    """
    total_challenges = Challenge.query.filter_by(is_active=True).count() or 6
    c6 = Challenge.query.filter_by(stage_number=6).first()

    players = (
        User.query.filter(User.role == "player")
        .outerjoin(Score, User.id == Score.user_id)
        .all()
    )

    now = datetime.datetime.utcnow()
    standings = []
    for user in players:
        total_score = user.score.total_score if user.score else 0
        solved_count = Submission.query.filter_by(
            user_id=user.id, success=True
        ).count()
        completed = (solved_count >= total_challenges)

        sub6 = (
            Submission.query.filter_by(
                user_id=user.id, challenge_id=c6.id if c6 else None, success=True
            ).order_by(Submission.submitted_at.desc()).first()
            if c6 else None
        )

        last_solve = (
            Submission.query.filter_by(user_id=user.id, success=True)
            .order_by(Submission.submitted_at.desc())
            .first()
        )
        last_solve_time = last_solve.submitted_at if last_solve else user.created_at

        # Calculate time taken from registration / start to final solve or last solve
        if completed and sub6 and sub6.submitted_at and user.created_at:
            diff = sub6.submitted_at - user.created_at
            duration_seconds = max(1, int(diff.total_seconds()))
        elif last_solve and last_solve.submitted_at and user.created_at:
            diff = last_solve.submitted_at - user.created_at
            duration_seconds = max(1, int(diff.total_seconds()))
        elif user.created_at:
            diff = now - user.created_at
            duration_seconds = max(0, int(diff.total_seconds()))
        else:
            duration_seconds = 0

        time_taken_formatted = format_duration(duration_seconds) if (completed or solved_count > 0) else "--"

        standings.append({
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "total_score": total_score,
            "solved_count": solved_count,
            "completed": completed,
            "duration_seconds": duration_seconds,
            "time_taken": time_taken_formatted,
            "last_solve_time": last_solve_time,
            "created_at": user.created_at,
        })

    # Sort criteria:
    # 1. Highest total_score first (-total_score)
    # 2. For completed players, least duration (fastest time) first
    # 3. Earliest last_solve_time
    standings.sort(
        key=lambda x: (
            -x["total_score"],
            x["duration_seconds"] if x["completed"] else 999999999,
            x["last_solve_time"] or datetime.datetime.max,
        )
    )

    for rank_idx, item in enumerate(standings, start=1):
        item["rank"] = rank_idx

    return standings, total_challenges

