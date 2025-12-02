"""
flask_headless_auth.models.token
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Token models for JWT blacklist, MFA, and password reset.
"""

from datetime import datetime
from sqlalchemy.ext.declarative import declared_attr
from flask_headless_auth import extensions

# Import db from extensions - it will be set by core.py before models are imported
db = extensions.db or extensions.get_db()


class BlacklistedToken(db.Model):
    """Blacklisted JWT tokens."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_blacklisted_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class MFAToken(db.Model):
    """Multi-factor authentication tokens."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_mfa_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


class PasswordResetToken(db.Model):
    """Password reset tokens."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    token = db.Column(db.String(128), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)


class UserActivityLog(db.Model):
    """User activity logging."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_user_activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    activity = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(255))

