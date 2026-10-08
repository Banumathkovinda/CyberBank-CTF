"""
CyberBank: Operation BlackVault
Flask Application Configuration

All configuration is read from environment variables.
Credentials are NEVER hard-coded.
"""

import os
from urllib.parse import quote_plus

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
    load_dotenv()
except ImportError:
    pass


class Config:
    """Base configuration - reads from environment variables."""

    # ---- Flask Core ----
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-me-in-production")
    DEBUG = False
    TESTING = False

    # ---- Database / SQLAlchemy ----
    # 1. Check for standard DATABASE_URL / MYSQL_URL
    _raw_db_url = os.environ.get("DATABASE_URL") or os.environ.get("MYSQL_URL")

    if _raw_db_url:
        if _raw_db_url.startswith("postgres://"):
            _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)
        elif _raw_db_url.startswith("mysql://"):
            _raw_db_url = _raw_db_url.replace("mysql://", "mysql+pymysql://", 1)
        SQLALCHEMY_DATABASE_URI = _raw_db_url
    elif os.environ.get("MYSQL_HOST"):
        # 2. Explicit MySQL connection parameters (local development or Docker MySQL)
        MYSQL_USER = os.environ.get("MYSQL_USER", "cyberbank_user")
        MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
        MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
        MYSQL_PORT = os.environ.get("MYSQL_PORT", "3306")
        MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "cyberbank")
        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{MYSQL_USER}:{quote_plus(MYSQL_PASSWORD)}"
            f"@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}"
            f"?charset=utf8mb4"
        )
    else:
        # 3. Default fallback SQLite file
        _sqlite_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberbank.db")
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{_sqlite_path}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    if SQLALCHEMY_DATABASE_URI.startswith("sqlite"):
        SQLALCHEMY_ENGINE_OPTIONS = {}
    else:
        SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_pre_ping": True,
            "pool_recycle": 3600,
            "pool_size": 5,
            "max_overflow": 10,
        }

    # ---- Session & Cookie Security ----
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 7200
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 604800


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration - uses in-memory SQLite for fast, isolated tests."""
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}


# Map config names to classes
config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
