"""
flask_headless_auth.data_access.repository
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SQLAlchemy implementation of data access layer.
"""

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.inspection import inspect
from datetime import datetime
from typing import Optional, Dict, Any

from flask_headless_auth.interfaces import UserDataAccess
from flask_headless_auth import extensions

# No longer need lazy imports - models are passed as constructor arguments


class SQLAlchemyUserRepository(UserDataAccess):
    """SQLAlchemy implementation of user data access."""
    
    def __init__(self, user_model, blacklisted_token_model=None, 
                 mfa_token_model=None, password_reset_token_model=None,
                 user_activity_log_model=None):
        """
        Initialize repository with model classes.
        
        Args:
            user_model: User model class
            blacklisted_token_model: BlacklistedToken model class
            mfa_token_model: MFAToken model class
            password_reset_token_model: PasswordResetToken model class
            user_activity_log_model: UserActivityLog model class
        """
        self.User = user_model
        self.BlacklistedToken = blacklisted_token_model
        self.MFAToken = mfa_token_model
        self.PasswordResetToken = password_reset_token_model
        self.UserActivityLog = user_activity_log_model
    
    @property
    def db(self):
        """Get database instance."""
        return extensions.db or extensions.get_db()
    
    def _to_dict(self, obj, include_password_hash=False):
        """
        Convert SQLAlchemy model to dictionary.
        
        Args:
            obj: SQLAlchemy model instance
            include_password_hash: If True, includes password_hash for internal auth use
        """
        if obj is None:
            return None
        
        # For internal authentication, use raw column attrs to include password_hash
        if include_password_hash:
            result = {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}
            return result
        
        # For external use, use to_dict() which excludes sensitive fields
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        return {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}
    
    def find_user_by_email(self, email: str, include_password_hash=False) -> Optional[Dict[str, Any]]:
        """
        Find user by email.
        
        Args:
            email: User's email address
            include_password_hash: If True, includes password_hash for authentication
        """
        user = self.User.query.filter_by(email=email).first()
        return self._to_dict(user, include_password_hash=include_password_hash) if user else None
    
    def create_user(self, user_data: Dict[str, Any], commit: bool = True) -> Dict[str, Any]:
        """
        Create new user.
        
        Args:
            user_data: User data dictionary
            commit: Whether to commit the transaction (default True).
                    Set to False to batch multiple operations.
        """
        # Map and filter data
        mapped_data = self.map_user_data(user_data)
        filtered_data = self.filter_valid_fields(mapped_data, self.User)
        
        # Set defaults
        if 'role_id' not in filtered_data:
            filtered_data['role_id'] = 2  # Default role
        
        # Create user
        user = self.User(**filtered_data)
        self.db.session.add(user)
        
        if commit:
            self.db.session.commit()
        
        return self._to_dict(user)
    
    def update_user(self, user_id: int, user_data: Dict[str, Any], commit: bool = True) -> None:
        """
        Update existing user.
        
        Args:
            user_id: User ID to update
            user_data: User data dictionary
            commit: Whether to commit the transaction (default True).
                    Set to False to batch multiple operations.
        """
        user = self.User.query.get(user_id)
        if user:
            mapped_data = self.map_user_data(user_data)
            filtered_data = self.filter_valid_fields(mapped_data, self.User)
            
            for key, value in filtered_data.items():
                setattr(user, key, value)
            
            if commit:
                self.db.session.commit()
    
    def verify_password(self, stored_password: str, provided_password: str) -> bool:
        """Verify password against hash."""
        return check_password_hash(stored_password, provided_password)
    
    def set_password(self, password: str) -> str:
        """Hash password."""
        return generate_password_hash(password)
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        user = self.User.query.get(user_id)
        return self._to_dict(user) if user else None
    
    def get_all_users(self):
        """Get all users."""
        users = self.User.query.all()
        return [self._to_dict(user) for user in users]
    
    def delete_user(self, user_id: int, commit: bool = True) -> None:
        """
        Delete user.
        
        Args:
            user_id: User ID to delete
            commit: Whether to commit the transaction (default True).
        """
        user = self.User.query.get(user_id)
        if user:
            self.db.session.delete(user)
            if commit:
                self.db.session.commit()
    
    def create_mfa_token(self, user_id: int, token: str, expires_at: datetime, commit: bool = True) -> None:
        """
        Create MFA token.
        
        Args:
            commit: Whether to commit the transaction (default True).
        """
        mfa_token = self.MFAToken(user_id=user_id, token=token, expires_at=expires_at)
        self.db.session.add(mfa_token)
        if commit:
            self.db.session.commit()
    
    def verify_mfa_token(self, user_id: int, token: str, commit: bool = True) -> bool:
        """
        Verify MFA token.
        
        Args:
            commit: Whether to commit the transaction (default True).
        """
        mfa_token = self.MFAToken.query.filter_by(
            user_id=user_id, token=token
        ).filter(
            self.MFAToken.expires_at > datetime.utcnow()
        ).first()
        
        if mfa_token:
            self.db.session.delete(mfa_token)
            if commit:
                self.db.session.commit()
            return True
        return False
    
    def create_password_reset_token(self, user_id: int, token: str, expires_at: datetime, commit: bool = True) -> None:
        """
        Create password reset token.
        
        Args:
            commit: Whether to commit the transaction (default True).
        """
        reset_token = self.PasswordResetToken(
            user_id=user_id, 
            token=token, 
            expires_at=expires_at
        )
        self.db.session.add(reset_token)
        if commit:
            self.db.session.commit()
    
    def verify_password_reset_token(self, token: str) -> Optional[int]:
        """Verify password reset token and return user_id."""
        reset_token = self.PasswordResetToken.query.filter_by(
            token=token
        ).filter(
            self.PasswordResetToken.expires_at > datetime.utcnow()
        ).first()
        
        if reset_token:
            return reset_token.user_id
        return None
    
    def log_user_activity(self, user_id: int, activity: str, commit: bool = True) -> None:
        """
        Log user activity.
        
        Args:
            commit: Whether to commit the transaction (default True).
        """
        try:
            log = self.UserActivityLog(user_id=user_id, activity=activity)
            self.db.session.add(log)
            if commit:
                self.db.session.commit()
        except Exception as e:
            # Fail gracefully if activity logging table schema is outdated
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Activity logging failed (schema mismatch?): {e}")
            if commit:
                self.db.session.rollback()
    
    def blacklist_token(self, jti: str, commit: bool = True) -> None:
        """
        Blacklist JWT token.
        
        Args:
            commit: Whether to commit the transaction (default True).
        """
        blacklisted_token = self.BlacklistedToken(jti=jti)
        self.db.session.add(blacklisted_token)
        if commit:
            self.db.session.commit()
    
    def is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        try:
            return self.BlacklistedToken.query.filter_by(jti=jti).first() is not None
        except Exception as e:
            # Fail open if blacklist table schema is outdated (better UX than 500 error)
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Token blacklist check failed (schema mismatch?): {e}")
            return False  # Assume not blacklisted if we can't check
    
    def filter_valid_fields(self, data: Dict[str, Any], model) -> Dict[str, Any]:
        """Filter data to include only valid model fields."""
        model_fields = {column.key for column in inspect(model).mapper.column_attrs}
        return {key: value for key, value in data.items() if key in model_fields}
    
    def map_user_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map user data field names."""
        mapping = {
            'emailAddress': 'email',
            'userPassword': 'password_hash',
            'phone': 'phone_number',
        }
        return {mapping.get(key, key): value for key, value in data.items()}

