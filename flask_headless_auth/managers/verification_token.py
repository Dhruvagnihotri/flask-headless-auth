"""
flask_headless_auth.managers.verification_token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Token generation and validation for email verification.

These are auth tokens (not email infrastructure) — they live
alongside the other managers that handle password-reset tokens,
MFA tokens, etc.
"""

from itsdangerous import URLSafeTimedSerializer, BadTimeSignature, SignatureExpired
from flask import current_app
from typing import Union
import logging

logger = logging.getLogger(__name__)

DEFAULT_EXPIRATION = 172800  # 48 hours in seconds


def generate_confirmation_token(email: str) -> str:
    """Generate a secure, time-limited token for email confirmation."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')


def confirm_token(token: str, expiration: int = DEFAULT_EXPIRATION) -> Union[str, bool]:
    """
    Validate and decode an email confirmation token.

    Returns:
        The email address if valid, False if expired or invalid.
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
        return email
    except SignatureExpired:
        logger.warning("Verification token expired")
        return False
    except BadTimeSignature:
        logger.warning("Invalid verification token signature")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during token confirmation: {e}")
        return False
