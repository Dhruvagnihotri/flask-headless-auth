"""
flask_headless_auth.default_models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Default model implementations using mixins.
These are used when users don't provide custom models.
"""

from datetime import datetime
from flask_headless_auth.mixins import (
    UserMixin, RoleMixin, PermissionMixin,
    TokenMixin, MFATokenMixin, PasswordResetTokenMixin,
    OAuthTokenMixin
)

# Cache for default models - only create once per db instance
_default_models_cache = {}


def create_default_models(db):
    """
    Create default model classes using the provided db instance.
    
    Args:
        db: SQLAlchemy database instance
        
    Returns:
        tuple: (User, Role, Permission, BlacklistedToken, MFAToken, 
                PasswordResetToken, UserActivityLog, OAuthToken, role_permissions)
    """
    
    # Return cached models if already created for this db instance
    db_id = id(db)
    if db_id in _default_models_cache:
        return _default_models_cache[db_id]
    
    # Association table for role-permission relationship
    role_permissions = db.Table(
        'authsvc_role_permissions',
        db.Column('role_id', db.Integer, db.ForeignKey('authsvc_roles.id'), primary_key=True),
        db.Column('permission_id', db.Integer, db.ForeignKey('authsvc_permissions.id'), primary_key=True),
        extend_existing=True  # Allow redefining if already exists
    )
    
    class User(db.Model, UserMixin):
        """Default User model with authentication and profile fields."""
        __tablename__ = 'authsvc_users'
        
        # Core auth fields
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True, nullable=False, index=True)
        password_hash = db.Column(db.String(1024))
        provider = db.Column(db.String(50), nullable=False, default='local')
        
        # RBAC
        role_id = db.Column(db.Integer, nullable=True)
        
        # Auth flags
        is_verified = db.Column(db.Boolean, nullable=False, default=False)
        is_active = db.Column(db.Boolean, nullable=False, default=True)
        mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
        
        # Profile fields (optional)
        first_name = db.Column(db.String(100))
        last_name = db.Column(db.String(100))
        phone_number = db.Column(db.String(20))
        date_of_birth = db.Column(db.Date)
        profile_picture = db.Column(db.String(500))
        bio = db.Column(db.Text)
        
        # Address fields
        address = db.Column(db.String(255))
        city = db.Column(db.String(100))
        state = db.Column(db.String(100))
        country = db.Column(db.String(100))
        zip_code = db.Column(db.String(20))
        
        # Occupation
        occupation = db.Column(db.String(100))
        
        # Timestamps
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    class Role(db.Model, RoleMixin):
        """Default Role model for RBAC."""
        __tablename__ = 'authsvc_roles'
        
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(80), unique=True, nullable=False)
        description = db.Column(db.String(255))
        
        # Many-to-many relationship with permissions
        permissions = db.relationship(
            'Permission',
            secondary='authsvc_role_permissions',
            back_populates='roles',
            lazy='dynamic'
        )
    
    class Permission(db.Model, PermissionMixin):
        """Default Permission model for RBAC."""
        __tablename__ = 'authsvc_permissions'
        
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), unique=True, nullable=False)
        description = db.Column(db.String(255))
        resource = db.Column(db.String(100), nullable=False)
        action = db.Column(db.String(50), nullable=False)
        
        # Many-to-many relationship with roles
        roles = db.relationship(
            'Role',
            secondary='authsvc_role_permissions',
            back_populates='permissions',
            lazy='dynamic'
        )
    
    class BlacklistedToken(db.Model, TokenMixin):
        """Default model for blacklisted JWT tokens."""
        __tablename__ = 'authsvc_blacklisted_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        jti = db.Column(db.String(120), nullable=False, unique=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    class MFAToken(db.Model, MFATokenMixin):
        """Default model for MFA tokens."""
        __tablename__ = 'authsvc_mfa_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        token = db.Column(db.String(10), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
    
    class PasswordResetToken(db.Model, PasswordResetTokenMixin):
        """Default model for password reset tokens."""
        __tablename__ = 'authsvc_password_reset_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        token = db.Column(db.String(100), nullable=False, unique=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
        used = db.Column(db.Boolean, default=False, nullable=False)
    
    class UserActivityLog(db.Model):
        """Default model for user activity logging."""
        __tablename__ = 'authsvc_user_activity_logs'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        activity = db.Column(db.String(255), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.String(255))
    
    class OAuthToken(db.Model, OAuthTokenMixin):
        """Default model for OAuth tokens."""
        __tablename__ = 'authsvc_oauth_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        provider = db.Column(db.String(50), nullable=False)
        access_token = db.Column(db.Text, nullable=False)
        refresh_token = db.Column(db.Text)
        token_type = db.Column(db.String(50))
        expires_at = db.Column(db.DateTime)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Cache and return
    result = (User, Role, Permission, BlacklistedToken, MFAToken, 
              PasswordResetToken, UserActivityLog, OAuthToken, role_permissions)
    _default_models_cache[db_id] = result
    
    return result
