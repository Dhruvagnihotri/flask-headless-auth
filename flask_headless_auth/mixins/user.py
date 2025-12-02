"""
flask_headless_auth.mixins.user
~~~~~~~~~~~~~~~~~~~~~~~~~~

User model mixin.
"""

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect


class UserMixin:
    """Mixin for User model providing auth fields and methods."""
    
    # Core auth fields
    id = None  # Must be defined by the implementing class
    email = None  # Must be defined by the implementing class
    password_hash = None  # Must be defined by the implementing class
    
    # Fields that will be added by the mixin
    @classmethod
    def __declare_last__(cls):
        """Called after model is fully constructed."""
        pass
    
    def set_password(self, password):
        """Hash and set user password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {c.key: getattr(self, c.key)
                for c in inspect(self).mapper.column_attrs}
    
    def __repr__(self):
        return f'<User {self.email}>'

