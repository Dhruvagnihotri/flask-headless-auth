"""
flask_headless_auth.oauth.providers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OAuth provider configuration.
"""

from authlib.integrations.flask_client import OAuth

oauth_clients = OAuth()


def configure_oauth(app):
    """Configure OAuth providers."""
    oauth_clients.init_app(app)
    
    # Google OAuth
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        redirect_uri = app.config.get('GOOGLE_REDIRECT_URI', None)
        
        oauth_clients.register(
            name='google',
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            client_kwargs={'scope': 'openid profile email'},
            redirect_uri=redirect_uri
        )
    
    # Microsoft OAuth
    if app.config.get('MICROSOFT_CLIENT_ID') and app.config.get('MICROSOFT_CLIENT_SECRET'):
        redirect_uri = app.config.get('MICROSOFT_REDIRECT_URI', None)
        
        oauth_clients.register(
            name='microsoft',
            client_id=app.config['MICROSOFT_CLIENT_ID'],
            client_secret=app.config['MICROSOFT_CLIENT_SECRET'],
            authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
            client_kwargs={'scope': 'openid profile email'},
            redirect_uri=redirect_uri
        )

