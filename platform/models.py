"""
CyberBank: Operation BlackVault
SQLAlchemy Database Models

Models:
    User         - Platform users (students, admins)
    Challenge    - CTF challenge definitions
    Submission   - Flag submission attempts
    Hint         - Challenge hints with point penalties
    HintUsage    - Tracks which hints each user has unlocked
    Score        - Aggregated user scores (leaderboard cache)
    Log          - Audit trail for security events
"""

import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from extensions import db, login_manager


# ============================================================
# 1. User
# ============================================================
class User(db.Model, UserMixin):
    """Platform user - player or admin."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(
        db.String(80), unique=True, nullable=False, index=True,
        comment="Unique display name"
    )
    email = db.Column(
        db.String(200), unique=True, nullable=False, index=True,
        comment="Unique email address"
    )
    password_hash = db.Column(
        db.String(256), nullable=False,
        comment="Werkzeug hashed password - never store plaintext"
    )
    role = db.Column(
        db.String(20), nullable=False, default="player",
        index=True,
        comment="Role: player | admin"
    )
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=datetime.datetime.utcnow,
        comment="Account creation timestamp"
    )

    # ---- Password Hashing Methods ----
    def set_password(self, password: str) -> None:
        """Hash plaintext password using Werkzeug's default secure algorithm."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify candidate plaintext password against stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        """Check if user has admin privileges."""
        return self.role == "admin"

    def has_completed_all_stages(self) -> bool:
        """Check if user has successfully solved all stages."""
        return self.submissions.filter_by(success=True).count() >= 6

    # ---- Relationships ----
    submissions = db.relationship(
        "Submission", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )
    hint_usages = db.relationship(
        "HintUsage", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )
    score = db.relationship(
        "Score", backref="user", uselist=False,
        cascade="all, delete-orphan"
    )
    logs = db.relationship(
        "Log", backref="user", lazy="dynamic",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# ============================================================
# 2. Challenge
# ============================================================
class Challenge(db.Model):
    """CTF challenge definition."""

    __tablename__ = "challenges"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stage_number = db.Column(
        db.Integer, nullable=False, index=True,
        comment="Stage number (1-6)"
    )
    title = db.Column(
        db.String(200), nullable=False,
        comment="Challenge display title"
    )
    domain = db.Column(
        db.String(50), nullable=False, index=True,
        comment="Domain: osint | stego | web | crypto | forensics | linux"
    )
    difficulty = db.Column(
        db.String(20), nullable=False,
        comment="Difficulty: easy | medium | hard"
    )
    description = db.Column(
        db.Text, nullable=False,
        comment="Full challenge description shown to students"
    )
    objective = db.Column(
        db.Text, nullable=True,
        comment="Brief objective summary"
    )
    points = db.Column(
        db.Integer, nullable=False, default=100,
        comment="Base points awarded for solving"
    )
    flag_hash = db.Column(
        db.String(256), nullable=False,
        comment="SHA-256 hash of the correct flag - never store plaintext flags"
    )
    is_active = db.Column(
        db.Boolean, nullable=False, default=True, index=True,
        comment="Whether the challenge is visible and solvable"
    )
    dependency_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="Challenge that must be solved before this one unlocks"
    )
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=datetime.datetime.utcnow,
        comment="Challenge creation timestamp"
    )

    # ---- Self-referential relationship (dependency chain) ----
    dependency = db.relationship(
        "Challenge", remote_side=[id],
        backref=db.backref("dependents", lazy="dynamic")
    )

    # ---- Relationships ----
    submissions = db.relationship(
        "Submission", backref="challenge", lazy="dynamic",
        cascade="all, delete-orphan"
    )
    hints = db.relationship(
        "Hint", backref="challenge", lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="Hint.hint_number"
    )
    hint_usages = db.relationship(
        "HintUsage", backref="challenge", lazy="dynamic",
        cascade="all, delete-orphan"
    )
    logs = db.relationship(
        "Log", backref="challenge", lazy="dynamic",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Challenge S{self.stage_number}: {self.title}>"


# ============================================================
# 3. Submission
# ============================================================
class Submission(db.Model):
    """Flag submission attempt."""

    __tablename__ = "submissions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="User who submitted"
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="Challenge attempted"
    )
    success = db.Column(
        db.Boolean, nullable=False, default=False,
        comment="Whether the submitted flag was correct"
    )
    score_awarded = db.Column(
        db.Integer, nullable=False, default=0,
        comment="Points awarded (0 if incorrect, adjusted for hints)"
    )
    submitted_at = db.Column(
        db.DateTime, nullable=False,
        default=datetime.datetime.utcnow,
        index=True,
        comment="Submission timestamp"
    )

    # ---- Composite index for quick lookups ----
    __table_args__ = (
        db.Index("ix_submissions_user_challenge", "user_id", "challenge_id"),
    )

    def __repr__(self):
        result = "PASSED" if self.success else "FAILED"
        return f"<Submission U{self.user_id}->C{self.challenge_id} {result}>"


# ============================================================
# 4. Hint
# ============================================================
class Hint(db.Model):
    """Challenge hint with point penalty."""

    __tablename__ = "hints"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="Challenge this hint belongs to"
    )
    hint_number = db.Column(
        db.Integer, nullable=False,
        comment="Hint order (1 = first hint, 2 = second, etc.)"
    )
    hint_text = db.Column(
        db.Text, nullable=False,
        comment="The hint content shown to the student"
    )
    penalty_percentage = db.Column(
        db.Integer, nullable=False, default=10,
        comment="Percentage of points deducted for using this hint (0-100)"
    )

    # ---- Relationships ----
    usages = db.relationship(
        "HintUsage", backref="hint", lazy="dynamic",
        cascade="all, delete-orphan"
    )

    # ---- Unique constraint: one hint_number per challenge ----
    __table_args__ = (
        db.UniqueConstraint("challenge_id", "hint_number", name="uq_hint_per_challenge"),
    )

    def __repr__(self):
        return f"<Hint C{self.challenge_id} #{self.hint_number} (-{self.penalty_percentage}%)>"


# ============================================================
# 5. HintUsage
# ============================================================
class HintUsage(db.Model):
    """Tracks which hints a user has unlocked."""

    __tablename__ = "hint_usages"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="User who unlocked the hint"
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="Challenge the hint belongs to"
    )
    hint_id = db.Column(
        db.Integer, db.ForeignKey("hints.id", ondelete="CASCADE"),
        nullable=False, index=True,
        comment="The specific hint unlocked"
    )
    used_at = db.Column(
        db.DateTime, nullable=False,
        default=datetime.datetime.utcnow,
        comment="When the hint was unlocked"
    )

    # ---- Unique constraint: each user can unlock a hint only once ----
    __table_args__ = (
        db.UniqueConstraint("user_id", "hint_id", name="uq_user_hint"),
        db.Index("ix_hint_usages_user_challenge", "user_id", "challenge_id"),
    )

    def __repr__(self):
        return f"<HintUsage U{self.user_id}->H{self.hint_id}>"


# ============================================================
# 6. Score
# ============================================================
class Score(db.Model):
    """Aggregated user score for the leaderboard."""

    __tablename__ = "scores"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
        comment="One score row per user"
    )
    total_score = db.Column(
        db.Integer, nullable=False, default=0,
        index=True,
        comment="Cumulative score across all challenges"
    )
    updated_at = db.Column(
        db.DateTime, nullable=False,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        comment="Last score update timestamp"
    )

    def __repr__(self):
        return f"<Score U{self.user_id}: {self.total_score}pts>"


# ============================================================
# 7. Log
# ============================================================
class Log(db.Model):
    """Audit log for security-relevant events."""

    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="User who triggered the event (NULL for system events)"
    )
    event_type = db.Column(
        db.String(50), nullable=False, index=True,
        comment="Event type: login | logout | submit_flag | unlock_hint | admin_action | error"
    )
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="SET NULL"),
        nullable=True, index=True,
        comment="Related challenge (if applicable)"
    )
    message = db.Column(
        db.Text, nullable=True,
        comment="Human-readable event description"
    )
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=datetime.datetime.utcnow,
        index=True,
        comment="Event timestamp"
    )

    def __repr__(self):
        return f"<Log [{self.event_type}] U{self.user_id} @ {self.created_at}>"


# ============================================================
# Flask-Login User Loader Callback
# ============================================================
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login session management."""
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None
