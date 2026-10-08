"""
CyberBank: Operation BlackVault
Three-Level Progressive Hint Service

Provides:
    - Progressive hint retrieval and state resolution
    - Sequential hint unlocking (Hint 1 -> Hint 2 -> Hint 3)
    - Single-use enforcement and audit logging
    - Penalty calculation for scoring
"""

import datetime
from extensions import db
from models import Challenge, Hint, HintUsage, Submission, Log


def get_challenge_hints_for_user(user_id: int, challenge_id: int) -> list[dict]:
    """
    Retrieve all 3 hints for a challenge formatted for the specified user.
    Reveals hint_text ONLY for hints the user has unlocked.
    """
    hints = Hint.query.filter_by(challenge_id=challenge_id).order_by(Hint.hint_number.asc()).all()
    usages = HintUsage.query.filter_by(user_id=user_id, challenge_id=challenge_id).all()
    unlocked_hint_ids = {u.hint_id for u in usages}

    result = []
    prev_unlocked = True  # Hint 1 can be unlocked immediately if challenge is accessible

    for h in hints:
        is_unlocked = h.id in unlocked_hint_ids
        can_unlock = prev_unlocked and not is_unlocked

        result.append({
            "id": h.id,
            "hint_number": h.hint_number,
            "penalty_percentage": h.penalty_percentage,
            "is_unlocked": is_unlocked,
            "can_unlock": can_unlock,
            "hint_text": h.hint_text if is_unlocked else None,
        })

        prev_unlocked = is_unlocked

    return result


def unlock_hint(user_id: int, challenge_id: int, hint_number: int) -> tuple[bool, str, dict | None]:
    """
    Unlock a specific hint number for a challenge.
    Enforces:
        - Challenge exists and is active
        - Challenge is unlocked for this user
        - Sequential progression (Hint 1 before 2, 2 before 3)
        - Idempotency (already unlocked hints return success without re-logging)
    """
    challenge = db.session.get(Challenge, challenge_id)
    if not challenge or not challenge.is_active:
        return False, "Challenge not found or inactive.", None

    # Verify prerequisite stage is solved
    if challenge.dependency_id is not None:
        solved = Submission.query.filter_by(
            user_id=user_id, challenge_id=challenge.dependency_id, success=True
        ).first()
        if not solved:
            dep_num = challenge.dependency.stage_number if challenge.dependency else "?"
            return False, f"Cannot access hints. Stage #{challenge.stage_number} is locked. Solve Stage #{dep_num} first.", None

    target_hint = Hint.query.filter_by(
        challenge_id=challenge_id, hint_number=hint_number
    ).first()
    if not target_hint:
        return False, f"Hint #{hint_number} does not exist for this challenge.", None

    # Check if already unlocked
    existing_usage = HintUsage.query.filter_by(
        user_id=user_id, hint_id=target_hint.id
    ).first()
    if existing_usage:
        return True, f"Hint #{hint_number} was already unlocked.", {
            "id": target_hint.id,
            "hint_number": target_hint.hint_number,
            "penalty_percentage": target_hint.penalty_percentage,
            "hint_text": target_hint.hint_text,
            "already_unlocked": True,
        }

    # Enforce sequential order: previous hint must be unlocked
    if hint_number > 1:
        prev_hint = Hint.query.filter_by(
            challenge_id=challenge_id, hint_number=hint_number - 1
        ).first()
        if prev_hint:
            prev_usage = HintUsage.query.filter_by(
                user_id=user_id, hint_id=prev_hint.id
            ).first()
            if not prev_usage:
                return False, f"You must unlock Hint #{hint_number - 1} before unlocking Hint #{hint_number}.", None

    # Record hint usage
    usage = HintUsage(
        user_id=user_id,
        challenge_id=challenge_id,
        hint_id=target_hint.id,
    )
    log_entry = Log(
        user_id=user_id,
        challenge_id=challenge_id,
        event_type="hint_used",
        message=f"Operative used Hint #{target_hint.hint_number} (-{target_hint.penalty_percentage}%) on Stage #{challenge.stage_number}.",
    )
    db.session.add(usage)
    db.session.add(log_entry)
    db.session.commit()

    return True, f"Hint #{hint_number} unlocked (-{target_hint.penalty_percentage}% penalty).", {
        "id": target_hint.id,
        "hint_number": target_hint.hint_number,
        "penalty_percentage": target_hint.penalty_percentage,
        "hint_text": target_hint.hint_text,
        "already_unlocked": False,
    }


def calculate_effective_points(challenge: Challenge, user_id: int) -> int:
    """
    Calculate the actual points to award for a challenge based on used hints.
    Penalties:
        Hint 1 = 10%
        Hint 2 = 20%
        Hint 3 = 30%
    Score cannot become negative.
    """
    usages = HintUsage.query.filter_by(
        user_id=user_id, challenge_id=challenge.id
    ).all()

    total_penalty_pct = 0
    for u in usages:
        if u.hint:
            total_penalty_pct += u.hint.penalty_percentage

    # Ensure max deduction does not exceed 100%
    total_penalty_pct = min(100, total_penalty_pct)
    deduction = int(challenge.points * (total_penalty_pct / 100.0))
    effective_score = max(0, challenge.points - deduction)

    return effective_score
