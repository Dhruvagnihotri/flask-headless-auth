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

# Cache for default models - only create once per (db instance, prefix) pair
_default_models_cache = {}


def create_default_models(db, table_prefix='authsvc_'):
    """
    Create default model classes using the provided db instance.
    
    Args:
        db: SQLAlchemy database instance
        table_prefix: Prefix for all table names (default: 'authsvc_').
                      Set via AUTHSVC_TABLE_PREFIX config to customise per app
                      (e.g. 'mrscribe_', 'brakit_').
        
    Returns:
        tuple: (User, Role, Permission, BlacklistedToken, MFAToken, 
                PasswordResetToken, UserActivityLog, OAuthToken, AuditLogEntry,
                UserSession, ActivityLog, role_permissions)
    """
    
    # Return cached models if already created for this (db, prefix) pair
    cache_key = (id(db), table_prefix)
    if cache_key in _default_models_cache:
        return _default_models_cache[cache_key]
    
    # Association table for role-permission relationship
    role_permissions = db.Table(
        f'{table_prefix}role_permissions',
        db.Column('role_id', db.Integer, db.ForeignKey(f'{table_prefix}roles.id', ondelete='CASCADE'), primary_key=True),
        db.Column('permission_id', db.Integer, db.ForeignKey(f'{table_prefix}permissions.id', ondelete='CASCADE'), primary_key=True),
        db.Column('granted_at', db.DateTime, default=datetime.utcnow),
        extend_existing=True  # Allow redefining if already exists
    )
    
    # Skip default model creation if a custom model already registered that table.
    # This happens when the app provides a custom user_model AND the table prefix
    # matches (e.g. MrScribeUser -> mrscribe_users, prefix = mrscribe_).
    _user_table = f'{table_prefix}users'
    if _user_table in db.metadata.tables:
        User = None  # Custom model already exists; caller will use it
    else:
        class User(db.Model, UserMixin):
            """Default User model with authentication and profile fields."""
            __tablename__ = _user_table
            
            # Core auth fields
            id = db.Column(db.Integer, primary_key=True)
            email = db.Column(db.String(255), unique=True, nullable=False, index=True)
            password_hash = db.Column(db.String(1024))
            provider = db.Column(db.String(50), nullable=False, default='local')
            
            # RBAC
            role_id = db.Column(db.Integer, db.ForeignKey(f'{table_prefix}roles.id'), nullable=True)
            
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
            
            # Relationship to Role
            role = db.relationship('Role', backref=db.backref('users', lazy='dynamic'))
    
    class Role(db.Model, RoleMixin):
        """Default Role model for RBAC."""
        __tablename__ = f'{table_prefix}roles'
        
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(80), unique=True, nullable=False, index=True)
        display_name = db.Column(db.String(100))
        description = db.Column(db.String(255))
        is_system = db.Column(db.Boolean, nullable=False, default=False)
        
        # Timestamps
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Many-to-many relationship with permissions
        permissions = db.relationship(
            'Permission',
            secondary=role_permissions,
            back_populates='roles',
            lazy='select'
        )
    
    class Permission(db.Model, PermissionMixin):
        """Default Permission model for RBAC."""
        __tablename__ = f'{table_prefix}permissions'
        
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), unique=True, nullable=False, index=True)
        display_name = db.Column(db.String(120))
        description = db.Column(db.String(255))
        category = db.Column(db.String(50), index=True)
        resource = db.Column(db.String(100), nullable=False)
        action = db.Column(db.String(50), nullable=False)
        is_system = db.Column(db.Boolean, nullable=False, default=False)
        
        # Timestamps
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        
        # Many-to-many relationship with roles
        roles = db.relationship(
            'Role',
            secondary=role_permissions,
            back_populates='permissions',
            lazy='select'
        )
    
    class BlacklistedToken(db.Model, TokenMixin):
        """Default model for blacklisted JWT tokens."""
        __tablename__ = f'{table_prefix}blacklisted_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        jti = db.Column(db.String(120), nullable=False, unique=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    class MFAToken(db.Model, MFATokenMixin):
        """Default model for MFA tokens."""
        __tablename__ = f'{table_prefix}mfa_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        token = db.Column(db.String(10), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
    
    class PasswordResetToken(db.Model, PasswordResetTokenMixin):
        """Default model for password reset tokens."""
        __tablename__ = f'{table_prefix}password_reset_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        token = db.Column(db.String(100), nullable=False, unique=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
        used = db.Column(db.Boolean, default=False, nullable=False)
    
    class UserActivityLog(db.Model):
        """Default model for user activity logging."""
        __tablename__ = f'{table_prefix}user_activity_logs'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        activity = db.Column(db.String(255), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.String(255))
    
    class OAuthToken(db.Model, OAuthTokenMixin):
        """Default model for OAuth tokens."""
        __tablename__ = f'{table_prefix}oauth_tokens'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        provider = db.Column(db.String(50), nullable=False)
        access_token = db.Column(db.Text, nullable=False)
        refresh_token = db.Column(db.Text)
        token_type = db.Column(db.String(50))
        expires_at = db.Column(db.DateTime)
        created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # ============================================================================
    # AUDIT & SESSION MODELS  (Supabase parity – auto-created, zero config)
    #
    # Tables:
    #   {prefix}audit_log_entries  →  like Supabase auth.audit_log_entries
    #   {prefix}user_sessions      →  like Supabase auth.sessions
    #   {prefix}activity_logs      →  app-level events (generic activity tracking)
    # ============================================================================

    class AuditLogEntry(db.Model):
        """
        Every auth event is recorded here automatically.
        The backend developer never writes to this table -- the library does it.
        """
        __tablename__ = f'{table_prefix}audit_log_entries'

        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow,
                              nullable=False, index=True)
        action = db.Column(db.String(100), nullable=False, index=True)
        actor_user_id = db.Column(db.Integer, nullable=True, index=True)
        target_user_id = db.Column(db.Integer, nullable=True)
        ip_address = db.Column(db.String(45))   # IPv6 safe
        user_agent = db.Column(db.Text)
        session_id = db.Column(db.String(36), index=True)
        # Multi-tenancy: nullable for single-tenant apps
        # Store your org/tenant/company ID here (e.g., clinic_id, company_id, org_id)
        tenant_id = db.Column(db.String(255), nullable=True, index=True)
        success = db.Column(db.Boolean, default=True, nullable=False)
        error_message = db.Column(db.Text)
        event_metadata = db.Column(db.JSON)

        def to_dict(self):
            return {
                'id': self.id,
                'timestamp': self.timestamp.isoformat() if self.timestamp else None,
                'action': self.action,
                'actor_user_id': self.actor_user_id,
                'target_user_id': self.target_user_id,
                'ip_address': self.ip_address,
                'user_agent': self.user_agent,
                'session_id': self.session_id,
                'tenant_id': self.tenant_id,
                'success': self.success,
                'error_message': self.error_message,
                'metadata': self.event_metadata,
            }

    class UserSession(db.Model):
        """
        One row per login.  Created automatically in TokenManager,
        revoked automatically on logout, touched on token refresh.
        """
        __tablename__ = f'{table_prefix}user_sessions'

        id = db.Column(db.Integer, primary_key=True)
        session_id = db.Column(db.String(36), unique=True, nullable=False,
                               index=True)
        user_id = db.Column(db.Integer, nullable=False, index=True)
        jti = db.Column(db.String(120), unique=True, nullable=False,
                        index=True)

        # Device fingerprinting
        device_name = db.Column(db.String(255))        # "Chrome on macOS"
        device_fingerprint = db.Column(db.String(255)) # SHA-256 hash
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.Text)
        country = db.Column(db.String(100))
        city = db.Column(db.String(100))

        # Lifecycle
        created_at = db.Column(db.DateTime, default=datetime.utcnow,
                               nullable=False)
        last_activity = db.Column(db.DateTime, default=datetime.utcnow,
                                  nullable=False, index=True)
        expires_at = db.Column(db.DateTime, nullable=True)

        # State
        is_active = db.Column(db.Boolean, default=True, nullable=False,
                              index=True)
        revoked = db.Column(db.Boolean, default=False, nullable=False)
        revoked_at = db.Column(db.DateTime, nullable=True)
        revoke_reason = db.Column(db.String(255))

        # Multi-tenancy (nullable for single-tenant apps)
        tenant_id = db.Column(db.String(255), nullable=True, index=True)

        def to_dict(self, include_sensitive=False):
            data = {
                'id': self.id,
                'session_id': self.session_id,
                'device_name': self.device_name,
                'ip_address': self.ip_address,
                'country': self.country,
                'city': self.city,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'last_activity': self.last_activity.isoformat() if self.last_activity else None,
                'is_active': self.is_active,
                'is_current': False,  # set by caller
            }
            if include_sensitive:
                data.update({
                    'jti': self.jti,
                    'user_id': self.user_id,
                    'device_fingerprint': self.device_fingerprint,
                    'revoked': self.revoked,
                    'revoke_reason': self.revoke_reason,
                })
            return data

    class ActivityLog(db.Model):
        """
        Generic application-level activity log.
        Written by the @audit_action decorator or audit_manager.log_activity().

        Tracks who accessed/modified which resource.  Domain-specific flags
        (e.g. compliance tags) belong in event_metadata or in a custom
        model passed via activity_log_model=.
        """
        __tablename__ = f'{table_prefix}activity_logs'

        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow,
                              nullable=False, index=True)
        action = db.Column(db.String(100), nullable=False, index=True)
        user_id = db.Column(db.Integer, nullable=False, index=True)
        session_id = db.Column(db.String(36), index=True)
        resource_type = db.Column(db.String(100), index=True)
        resource_id = db.Column(db.Integer)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.Text)
        # Multi-tenancy (nullable for single-tenant apps)
        tenant_id = db.Column(db.String(255), nullable=True, index=True)
        event_metadata = db.Column(db.JSON)

        def to_dict(self):
            return {
                'id': self.id,
                'timestamp': self.timestamp.isoformat() if self.timestamp else None,
                'action': self.action,
                'user_id': self.user_id,
                'resource_type': self.resource_type,
                'resource_id': self.resource_id,
                'ip_address': self.ip_address,
                'tenant_id': self.tenant_id,
                'metadata': self.event_metadata,
            }

    # Cache and return
    result = (User, Role, Permission, BlacklistedToken, MFAToken,
              PasswordResetToken, UserActivityLog, OAuthToken,
              AuditLogEntry, UserSession, ActivityLog, role_permissions)
    _default_models_cache[cache_key] = result

    return result
