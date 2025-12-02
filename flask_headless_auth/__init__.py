"""
Flask-Headless-Auth
~~~~~~~~~~~~~~~~~~~

Modern, headless authentication for Flask APIs.

Basic usage:

    from flask import Flask
    from flask_headless_auth import AuthSvc

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['JWT_SECRET_KEY'] = 'your-jwt-secret'
    
    auth = AuthSvc(app)
    
    if __name__ == '__main__':
        app.run()

:copyright: (c) 2024 by Dhruv Agnihotri.
:license: MIT, see LICENSE for more details.
"""

from .core import AuthSvc
from .__version__ import __version__

# Export mixins for users to create custom models
from .mixins import (
    UserMixin, RoleMixin, PermissionMixin,
    TokenMixin, MFATokenMixin, PasswordResetTokenMixin,
    OAuthTokenMixin
)

# Export db for convenience
from .extensions import db

__all__ = [
    'AuthSvc',
    'db',
    'UserMixin',
    'RoleMixin',
    'PermissionMixin',
    'TokenMixin',
    'MFATokenMixin',
    'PasswordResetTokenMixin',
    'OAuthTokenMixin',
    '__version__',
]
