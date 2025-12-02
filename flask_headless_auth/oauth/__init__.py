"""
flask_headless_auth.oauth
~~~~~~~~~~~~~~~~~~~

OAuth provider integration.
"""

from .providers import oauth_clients, configure_oauth

__all__ = ['oauth_clients', 'configure_oauth']

