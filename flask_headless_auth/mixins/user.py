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
    
    def to_auth_dict(self):
        """
        Serialize auth-related fields (SAFE - excludes password_hash).
        
        Apps using multiple packages should override to_dict() to combine
        multiple mixins. This method provides auth fields only.
        
        Returns:
            dict: Auth-related user fields
        """
        return {
            'id': getattr(self, 'id', None),
            'email': getattr(self, 'email', None),
            'first_name': getattr(self, 'first_name', None),
            'last_name': getattr(self, 'last_name', None),
            'phone_number': getattr(self, 'phone_number', None),
            'is_verified': getattr(self, 'is_verified', False),
            'is_active': getattr(self, 'is_active', True),
            'mfa_enabled': getattr(self, 'mfa_enabled', False),
            'role_id': getattr(self, 'role_id', None),
            'provider': getattr(self, 'provider', 'local'),
            'date_of_birth': getattr(self, 'date_of_birth').isoformat() if getattr(self, 'date_of_birth', None) else None,
            'profile_picture': getattr(self, 'profile_picture', None),
            'bio': getattr(self, 'bio', None),
            'occupation': getattr(self, 'occupation', None),
            'address': getattr(self, 'address', None),
            'city': getattr(self, 'city', None),
            'state': getattr(self, 'state', None),
            'country': getattr(self, 'country', None),
            'zip_code': getattr(self, 'zip_code', None),
            'created_at': getattr(self, 'created_at').isoformat() if getattr(self, 'created_at', None) else None,
            'updated_at': getattr(self, 'updated_at').isoformat() if getattr(self, 'updated_at', None) else None,
        }
    
    def to_dict(self):
        """
        Default serialization method.
        
        Apps can override this to combine multiple package mixins:
        
        Example:
            def to_dict(self):
                result = {}
                result.update(self.to_auth_dict())  # from UserMixin
                result.update(self.to_subscription_dict())  # from SubscriptionMixin
                result.update({'custom_field': self.custom_field})
                return result
        
        Returns:
            dict: User data (defaults to auth fields only)
        """
        return self.to_auth_dict()
    
    def __repr__(self):
        return f'<User {self.email}>'

