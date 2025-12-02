"""
flask_headless_auth.email_service.token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Token generation and validation for email verification.
"""

from itsdangerous import URLSafeTimedSerializer, BadTimeSignature, SignatureExpired
from flask import current_app
from typing import Union

DEFAULT_EXPIRATION = 172800  # 48 hours in seconds


def generate_confirmation_token(email: str) -> str:
    """Generate a secure token for email confirmation."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')


def confirm_token(token: str, expiration: int = DEFAULT_EXPIRATION) -> Union[str, bool]:
    """Validate and decode an email confirmation token."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
        return email
    except SignatureExpired:
        current_app.logger.warning("Token expired")
        return False
    except BadTimeSignature:
        current_app.logger.warning("Invalid token signature")
        return False
    except Exception as e:
        current_app.logger.error(f"Unexpected error during token confirmation: {str(e)}")
        return False

