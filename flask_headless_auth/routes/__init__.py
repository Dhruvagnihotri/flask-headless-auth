"""
flask_headless_auth.routes
~~~~~~~~~~~~~~~~~~~~

API routes for authentication.
"""

from .auth import create_auth_blueprint

__all__ = ['create_auth_blueprint']

