"""
flask_headless_auth.extensions
~~~~~~~~~~~~~~~~~~~~~~~~~

Flask extensions initialization.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Singletons
_db = None
_jwt = None
_cache = None
_limiter = None
db = None  # Will be set before models are imported


def get_db():
    """Get or create SQLAlchemy instance."""
    global _db, db
    if _db is None:
        _db = SQLAlchemy()
        db = _db
    return _db


def set_db(db_instance):
    """Set the SQLAlchemy instance (used when reusing app's existing db)."""
    global _db, db
    _db = db_instance
    db = db_instance


def get_jwt():
    """Get or create JWT manager instance."""
    global _jwt
    if _jwt is None:
        _jwt = JWTManager()
    return _jwt


def get_cache():
    """Get or create cache instance."""
    global _cache
    if _cache is None:
        _cache = Cache()
    return _cache


def get_limiter():
    """Get or create limiter instance."""
    global _limiter
    if _limiter is None:
        _limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["50000 per day", "5000 per hour"]
            # Note: RATELIMIT_DEFAULT from config can override this when init_app is called
        )
    return _limiter


# Export JWT and Limiter instances for use in decorators
jwt = get_jwt()
limiter = get_limiter()
cache = get_cache()
