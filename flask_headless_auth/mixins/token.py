"""
flask_headless_auth.mixins.token
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Token model mixins for JWT blacklist, MFA, and password reset.
"""


class TokenMixin:
    """Mixin for blacklisted token model."""
    
    id = None
    jti = None
    
    def __repr__(self):
        return f'<BlacklistedToken {self.jti}>'


class MFATokenMixin:
    """Mixin for MFA token model."""
    
    id = None
    user_id = None
    token = None
    
    def __repr__(self):
        return f'<MFAToken user_id={self.user_id}>'


class PasswordResetTokenMixin:
    """Mixin for password reset token model."""
    
    id = None
    user_id = None
    token = None
    
    def __repr__(self):
        return f'<PasswordResetToken user_id={self.user_id}>'

