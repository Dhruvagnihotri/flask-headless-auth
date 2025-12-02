"""
flask_headless_auth.data_access
~~~~~~~~~~~~~~~~~~~~~~~~~~

Data access layer for database operations.
"""

from .repository import SQLAlchemyUserRepository

__all__ = ['SQLAlchemyUserRepository']

