"""
flask_headless_auth.utils
~~~~~~~~~~~~~~~~~~~

Utility functions and decorators.
"""

from .redirect import validate_redirect_url
from .request import is_browser_request

__all__ = ['validate_redirect_url', 'is_browser_request']

