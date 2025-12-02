"""
flask_headless_auth.interfaces
~~~~~~~~~~~~~~~~~~~~~~~~~

Abstract interfaces for data access layer.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime


class UserDataAccess(ABC):
    """Abstract interface for user data access."""
    
    @abstractmethod
    def find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user by email address."""
        pass
    
    @abstractmethod
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user."""
        pass
    
    @abstractmethod
    def update_user(self, user_id: int, user_data: Dict[str, Any]) -> None:
        """Update existing user."""
        pass
    
    @abstractmethod
    def verify_password(self, stored_password: str, provided_password: str) -> bool:
        """Verify password against stored hash."""
        pass
    
    @abstractmethod
    def set_password(self, password: str) -> str:
        """Hash password and return hash."""
        pass
    
    @abstractmethod
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        pass
    
    @abstractmethod
    def blacklist_token(self, jti: str) -> None:
        """Blacklist a JWT token."""
        pass
    
    @abstractmethod
    def is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        pass
    
    @abstractmethod
    def create_mfa_token(self, user_id: int, token: str, expires_at: datetime) -> None:
        """Create MFA token."""
        pass
    
    @abstractmethod
    def verify_mfa_token(self, user_id: int, token: str) -> bool:
        """Verify MFA token."""
        pass
    
    @abstractmethod
    def create_password_reset_token(self, user_id: int, token: str, expires_at: datetime) -> None:
        """Create password reset token."""
        pass
    
    @abstractmethod
    def verify_password_reset_token(self, token: str) -> Optional[int]:
        """Verify password reset token and return user_id."""
        pass
    
    @abstractmethod
    def log_user_activity(self, user_id: int, activity: str) -> None:
        """Log user activity."""
        pass

