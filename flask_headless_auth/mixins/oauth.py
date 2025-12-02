"""
flask_headless_auth.mixins.oauth
~~~~~~~~~~~~~~~~~~~~~~~~~~~

OAuth token model mixin.
"""


class OAuthTokenMixin:
    """Mixin for OAuth token model."""
    
    id = None
    user_id = None
    provider = None
    
    def __repr__(self):
        return f'<OAuthToken user_id={self.user_id} provider={self.provider}>'

