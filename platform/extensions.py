"""
CyberBank: Operation BlackVault
Flask Extensions

Centralized extension initialization to avoid circular imports.
Extensions are created here and initialized with the app in app.py.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# Database ORM
db = SQLAlchemy()

# Database migrations
migrate = Migrate()

# Authentication & Session Management
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please authenticate to access the BlackVault platform."
login_manager.login_message_category = "warning"

