"""
flask_headless_auth.models.user
~~~~~~~~~~~~~~~~~~~~~~~~~~

User model for authentication.
"""

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect
from sqlalchemy.ext.declarative import declared_attr
from flask_headless_auth import extensions

# Import db from extensions - it will be set by core.py before models are imported
db = extensions.db or extensions.get_db()


class User(db.Model):
    """User model with authentication and profile fields."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            # If called outside app context during import, use default
            prefix = 'authsvc'
        return f'{prefix}_users'
    
    # Core auth fields
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(1024))
    provider = db.Column(db.String(50), nullable=False, default='local')  # local, google, microsoft
    
    # RBAC
    role_id = db.Column(db.Integer, nullable=True)
    
    # Auth flags
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    
    # Profile fields
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    profile_picture = db.Column(db.String(255))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    
    def set_password(self, password):
        """Hash and set password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash."""
        return check_password_hash(self.password_hash, password)
    
    @property
    def full_name(self):
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}".strip() if self.first_name and self.last_name else self.email
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {c.key: getattr(self, c.key)
                for c in inspect(self).mapper.column_attrs}

